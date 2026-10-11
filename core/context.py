"""
GHOST RECON v2.0 — core/context.py
SQLite-backed Context (Ctx) state manager.

The Ctx class is the ONLY interface step modules use to read/write scan state.
No module should ever write raw SQL — all persistence flows through Ctx helpers.

Usage:
    ctx = Ctx.new(db, target="https://example.com", domain="example.com", ...)
    ctx.add_subdomain("mail.example.com", ip_addresses=["1.2.3.4"])
    ctx.add_finding(severity="HIGH", category="XSS", ...)
    snapshot = ctx.snapshot()   # For checkpointing
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.db import GhostDB


# ═══════════════════════════════════════════════════════════════════════════════
# CVSS / OWASP / MITRE MAPPING TABLES
# ═══════════════════════════════════════════════════════════════════════════════

CVSS_MAP: Dict[str, Tuple[float, str]] = {
    "CRITICAL": (9.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "HIGH":     (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "MEDIUM":   (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "LOW":      (2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "INFO":     (0.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}

# Category → (OWASP Top 10 2021, MITRE ATT&CK Tactic, MITRE Technique)
CATEGORY_MAP: Dict[str, Tuple[str, str, str]] = {
    "CDN_BYPASS":       ("A05:2021", "TA0001", "T1190"),
    "CORS_MISCONFIG":   ("A05:2021", "TA0009", "T1557"),
    "XSS_REFLECTED":    ("A03:2021", "TA0001", "T1189"),
    "SQLI":             ("A03:2021", "TA0001", "T1190"),
    "SSTI":             ("A03:2021", "TA0002", "T1203"),
    "SSRF":             ("A10:2021", "TA0043", "T1595"),
    "LFI":              ("A01:2021", "TA0009", "T1005"),
    "CRLF_INJECTION":   ("A03:2021", "TA0001", "T1190"),
    "CACHE_POISON":     ("A05:2021", "TA0040", "T1557"),
    "CONTENT_DISCOVERY":("A01:2021", "TA0043", "T1595"),
    "SUB_EXPOSED":      ("A01:2021", "TA0043", "T1595"),
    "API_EXPOSED":      ("A01:2021", "TA0043", "T1595"),
    "SECRET_LEAK":      ("A02:2021", "TA0006", "T1552"),
    "OPEN_REDIRECT":    ("A01:2021", "TA0001", "T1566"),
    "HOST_POISON":      ("A05:2021", "TA0040", "T1557"),
    "SUBDOMAIN_TAKEOVER":("A05:2021","TA0001", "T1584"),
    "OPEN_PORTS":       ("A05:2021", "TA0043", "T1046"),
    "SHODAN_VULNS":     ("A06:2021", "TA0043", "T1595"),
    "TECH_CVE":         ("A06:2021", "TA0001", "T1190"),
    "CLOUD_SERVICE_LEAK":("A05:2021","TA0009", "T1530"),
    "METHOD_OVERRIDE":  ("A01:2021", "TA0005", "T1548"),
    "HTML_INJECTION":   ("A03:2021", "TA0001", "T1189"),
    "VERB_ALLOWED":     ("A05:2021", "TA0043", "T1595"),
    "CACHE_DECEPTION":  ("A01:2021", "TA0009", "T1557"),
    "SUB_HEADER_LEAK":  ("A05:2021", "TA0043", "T1592"),
    "JWT_VULN":         ("A02:2021", "TA0006", "T1552"),
    "IDOR":             ("A01:2021", "TA0009", "T1005"),
}

# Marketing params to strip during URL normalization
MARKETING_PARAMS: frozenset = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "gad_source", "gad", "gbraid", "wbraid",
    "adgroup", "clickid", "matchtype", "placement", "network", "device",
    "extension", "targetid", "campaign", "campaignid", "adgroupid",
    "creative", "keyword", "mc_cid", "mc_eid", "msclkid", "twclid",
    "li_fat_id", "_ga", "_gl", "sxsrf", "ref", "ref_", "referer",
})


# ═══════════════════════════════════════════════════════════════════════════════
# URL NORMALIZATION (mirrors ghost_core.py P2 logic)
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_url(url: str) -> str:
    """Normalize a URL: lowercase scheme/host, strip marketing params, sort qs."""
    try:
        p = urlparse(url)
        params = parse_qs(p.query, keep_blank_values=True)
        filtered = {k: v for k, v in params.items() if k.lower() not in MARKETING_PARAMS}
        sq = urlencode(sorted(filtered.items()), doseq=True) if filtered else ""
        return urlunparse((
            p.scheme.lower(), p.netloc.lower(),
            p.path.rstrip("/") or "/", p.params, sq, ""
        ))
    except Exception:
        return url


def endpoint_key(url: str) -> str:
    """Generate a dedup key: host|path|sorted_param_names."""
    try:
        p = urlparse(url)
        pnames = sorted(
            k for k in parse_qs(p.query).keys()
            if k.lower() not in MARKETING_PARAMS
        )
        return f"{p.netloc.lower()}|{p.path.rstrip('/') or '/'}|{'&'.join(pnames)}"
    except Exception:
        return url


def classify_url(url: str) -> str:
    """Classify a URL by its likely function."""
    path = urlparse(url).path.lower()
    if any(k in path for k in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/")):
        return "api"
    if any(k in path for k in ("/admin", "/dashboard", "/panel", "/manage")):
        return "admin"
    if any(k in path for k in ("/login", "/auth", "/signin", "/register", "/oauth")):
        return "auth"
    if any(k in path for k in (".env", ".git", "config", "backup", ".sql", "debug", "actuator")):
        return "sensitive"
    if any(path.endswith(e) for e in (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico")):
        return "static"
    return "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# CONTEXT CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class Ctx:
    """SQLite-backed scan context. All state flows through this class.

    Step modules interact ONLY with Ctx methods — never with raw SQL.
    Provides in-memory caches for hot-path reads (subdomains, urls, params)
    that are lazily loaded and write-through to SQLite.
    """

    def __init__(self, db: GhostDB, scan_id: str):
        self._db = db
        self.scan_id = scan_id

        # Load scan-level fields from DB
        row = db.get_scan(scan_id)
        if not row:
            raise ValueError(f"Scan {scan_id} not found in database")

        self.target: str = row["target"]
        self.url: str = row["target"]
        self.domain: str = row["domain"]
        self.root_domain: str = row["root_domain"]
        self.scope: str = row["scope"]
        self.stealth: str = row["stealth"]

        # Mutable scan-level state (kept in sync with DB)
        self.waf_detected: List[str] = json.loads(row["waf_detected"] or "[]")
        self.cdn_detected: str = row["cdn_detected"] or ""
        self.origin_ip: str = row["origin_ip"] or ""
        self.tech_stack: str = row["tech_stack"] or ""
        self.server_header: str = row["server_header"] or ""
        self.powered_by: str = row["powered_by"] or ""
        self.http_code: int = row["http_code"] or 0
        self.security_headers: Dict[str, str] = json.loads(row["security_headers"] or "{}")
        self.wildcard_ip: str = row["wildcard_ip"] or ""

        # Derived convenience fields
        parsed = urlparse(self.target)
        self.scheme: str = parsed.scheme or "https"
        parts = self.domain.split(".")
        self.dname: str = parts[-2] if len(parts) >= 2 else self.domain
        self.probe_base: str = f"{self.scheme}://{self.origin_ip}" if self.origin_ip else f"{self.scheme}://{self.domain}"
        self.host_header: str = self.domain if self.origin_ip else ""

        # In-memory caches — lazily populated, write-through
        self._subdomains_cache: Optional[List[str]] = None
        self._urls_cache: Optional[Set[str]] = None
        self._params_cache: Optional[Set[str]] = None
        self._js_cache: Optional[Set[str]] = None

        # Runtime-only attributes (not persisted to DB)
        self.payload_registry: Dict[str, Any] = {}
        self.engine: Any = None  # Set by orchestrator for direct engine access

        # v2.0: scope enforcement at the data layer. Every asset a step stores
        # passes through _keep(); out-of-scope hosts are recorded, never stored,
        # so no later step can probe them.
        self.scope_guard: Any = None
        self.out_of_scope_hosts: Set[str] = set()
        self.completed_steps: Set[int] = set()

    # ─── Scope filtering (v2.0) ───────────────────────────────────────────────

    def _keep(self, target: str) -> bool:
        guard = self.scope_guard
        if guard is None or not target:
            return True
        if guard.is_in_scope(target):
            return True
        host = urlparse(target if "://" in target else "//" + target).hostname or target
        if len(self.out_of_scope_hosts) < 50000:
            self.out_of_scope_hosts.add(host.lower())
        return False

    def _keep_js(self, url: str) -> bool:
        # Third-party JS (CDNs) is only dropped under --strict-scope.
        guard = self.scope_guard
        if guard is None or not getattr(guard, "enforce", False):
            return True
        return self._keep(url)

    @property
    def db(self) -> GhostDB:
        """Direct DB access for advanced queries (use sparingly)."""
        return self._db

    # ─── Factory Methods ──────────────────────────────────────────────────────

    @classmethod
    def new(
        cls,
        db: GhostDB,
        target: str,
        domain: str,
        root_domain: str,
        scope: str = "single",
        stealth: str = "medium",
        config_json: str = "{}",
    ) -> "Ctx":
        """Create a new scan context (fresh scan)."""
        scan_id = db.create_scan(
            target=target,
            domain=domain,
            root_domain=root_domain,
            scope=scope,
            stealth=stealth,
            config_json=config_json,
        )
        return cls(db, scan_id)

    @classmethod
    def resume(cls, db: GhostDB, scan_id: str) -> "Ctx":
        """Resume an existing scan from checkpoint."""
        return cls(db, scan_id)

    # ─── Scan-Level State Persistence ─────────────────────────────────────────

    def persist_scan_state(self) -> None:
        """Flush mutable scan-level fields to SQLite."""
        self._db.update_scan(
            self.scan_id,
            waf_detected=json.dumps(self.waf_detected),
            cdn_detected=self.cdn_detected,
            origin_ip=self.origin_ip,
            tech_stack=self.tech_stack,
            server_header=self.server_header,
            powered_by=self.powered_by,
            http_code=self.http_code,
            security_headers=json.dumps(self.security_headers),
            wildcard_ip=self.wildcard_ip,
        )
        # Update derived fields
        self.probe_base = (
            f"{self.scheme}://{self.origin_ip}"
            if self.origin_ip
            else f"{self.scheme}://{self.domain}"
        )
        self.host_header = self.domain if self.origin_ip else ""

    # ─── Subdomains ───────────────────────────────────────────────────────────

    def add_subdomain(
        self,
        fqdn: str,
        ip_addresses: Optional[List[str]] = None,
        cname: str = "",
        status: str = "unknown",
        http_code: int = 0,
        title: str = "",
        tech_stack: str = "",
        waf: str = "",
        cdn: str = "",
    ) -> int:
        """Add or update a subdomain. Returns row ID (0 if out of scope)."""
        if not self._keep(fqdn.strip().rstrip(".")):
            return 0
        self._subdomains_cache = None  # Invalidate cache
        return self._db.upsert(
            "subdomains",
            {
                "scan_id": self.scan_id,
                "fqdn": fqdn.lower().strip().rstrip("."),
                "ip_addresses": json.dumps(ip_addresses or []),
                "cname": cname,
                "status": status,
                "http_code": http_code,
                "title": title,
                "tech_stack": tech_stack,
                "waf": waf,
                "cdn": cdn,
                "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            conflict_columns=["scan_id", "fqdn"],
            update_columns=[
                "ip_addresses", "cname", "status", "http_code",
                "title", "tech_stack", "waf", "cdn", "last_seen",
            ],
        )

    def add_subdomains_bulk(self, fqdns: List[str], source: str = "unknown") -> int:
        """Add many subdomains at once. Returns count added."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._subdomains_cache = None
        params = [
            (self.scan_id, f.lower().strip().rstrip("."), "[]", "", "unknown", 0, "", "", "", "", now, now)
            for f in fqdns
            if f.strip() and self._keep(f.strip().rstrip("."))
        ]
        if not params:
            return 0
        self._db.execute_many(
            """INSERT OR IGNORE INTO subdomains
               (scan_id, fqdn, ip_addresses, cname, status, http_code,
                title, tech_stack, waf, cdn, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            params,
        )
        return len(params)

    @property
    def subdomains(self) -> List[str]:
        """Get all subdomain FQDNs for this scan (cached)."""
        if self._subdomains_cache is None:
            rows = self._db.fetch_all(
                "SELECT fqdn FROM subdomains WHERE scan_id = ? ORDER BY fqdn",
                (self.scan_id,),
            )
            self._subdomains_cache = [r["fqdn"] for r in rows]
        return self._subdomains_cache

    def get_alive_subdomains(self) -> List[str]:
        """Get subdomains with status='alive'."""
        rows = self._db.fetch_all(
            "SELECT fqdn FROM subdomains WHERE scan_id = ? AND status = 'alive'",
            (self.scan_id,),
        )
        return [r["fqdn"] for r in rows]

    # ─── Live Hosts ───────────────────────────────────────────────────────────

    def add_live_host(
        self, url: str, http_code: int = 0, title: str = "",
        content_length: int = 0, tech: str = "",
    ) -> int:
        """Add or update a live host (0 if out of scope)."""
        if not self._keep(url):
            return 0
        return self._db.upsert(
            "live_hosts",
            {
                "scan_id": self.scan_id,
                "url": url,
                "http_code": http_code,
                "title": title,
                "content_length": content_length,
                "tech": tech,
                "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            conflict_columns=["scan_id", "url"],
            update_columns=["http_code", "title", "content_length", "tech", "last_seen"],
        )

    @property
    def live_hosts(self) -> List[Dict[str, Any]]:
        """Get all live hosts as dicts."""
        rows = self._db.fetch_all(
            "SELECT * FROM live_hosts WHERE scan_id = ? ORDER BY url",
            (self.scan_id,),
        )
        return [dict(r) for r in rows]

    def live_host_urls(self) -> List[str]:
        """Get just the URLs of live hosts."""
        rows = self._db.fetch_all(
            "SELECT url FROM live_hosts WHERE scan_id = ? ORDER BY url",
            (self.scan_id,),
        )
        return [r["url"] for r in rows]

    # ─── URLs ─────────────────────────────────────────────────────────────────

    def add_url(self, url: str, source: str = "unknown") -> int:
        """Add a URL with automatic normalization, dedup, and classification."""
        if not self._keep(url):
            return 0
        self._urls_cache = None
        norm = normalize_url(url)
        epk = endpoint_key(url)
        cls = classify_url(url)
        return self._db.upsert(
            "urls",
            {
                "scan_id": self.scan_id,
                "url": url,
                "source": source,
                "normalized": norm,
                "endpoint_key": epk,
                "classification": cls,
                "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            conflict_columns=["scan_id", "normalized"],
            update_columns=["source", "last_seen"],
        )

    def add_urls_bulk(self, urls: List[str], source: str = "unknown") -> int:
        """Add many URLs via single-transaction executemany. OOM-safe: call in chunks."""
        self._urls_cache = None
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        seen_norms: Set[str] = set()
        rows = []
        for u in urls:
            if not u or not u.strip():
                continue
            u = u.strip()
            if not self._keep(u):
                continue
            norm = normalize_url(u)
            if norm in seen_norms:
                continue
            seen_norms.add(norm)
            rows.append((u, source, norm, endpoint_key(u), classify_url(u), now, now))
        return self._db.bulk_insert_urls(self.scan_id, rows)

    def bulk_insert_js_files(self, js_urls: List[str], priority_fn=None) -> int:
        """Bulk insert JS files via single-transaction executemany."""
        self._js_cache = None
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        seen: Set[str] = set()
        rows = []
        for u in js_urls:
            if not u or u in seen or not self._keep_js(u):
                continue
            seen.add(u)
            score = priority_fn(u) if priority_fn else 50
            rows.append((u, "", 0, score, now, now))
        return self._db.bulk_insert_js(self.scan_id, rows)

    def bulk_insert_params(self, names: List[str], source: str = "unknown") -> int:
        """Bulk insert params via single-transaction executemany."""
        self._params_cache = None
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        seen: Set[str] = set()
        rows = []
        for n in names:
            n = n.strip()
            if not n or n in seen:
                continue
            seen.add(n)
            rows.append((n, source, now))
        return self._db.bulk_insert_params(self.scan_id, rows)

    @property
    def urls(self) -> Set[str]:
        """Get all URLs for this scan (cached set)."""
        if self._urls_cache is None:
            rows = self._db.fetch_all(
                "SELECT url FROM urls WHERE scan_id = ?", (self.scan_id,)
            )
            self._urls_cache = {r["url"] for r in rows}
        return self._urls_cache

    def get_urls_by_class(self, classification: str) -> List[str]:
        """Get URLs filtered by classification (api, admin, auth, sensitive, etc.)."""
        rows = self._db.fetch_all(
            "SELECT url FROM urls WHERE scan_id = ? AND classification = ?",
            (self.scan_id, classification),
        )
        return [r["url"] for r in rows]

    def url_count(self) -> int:
        """Count total URLs without loading them all."""
        return self._db.fetch_scalar(
            "SELECT COUNT(*) FROM urls WHERE scan_id = ?", (self.scan_id,)
        ) or 0

    # ─── JavaScript Files ─────────────────────────────────────────────────────

    def add_js_file(
        self, url: str, hash_: str = "", size: int = 0, priority_score: int = 50,
    ) -> int:
        """Add or update a JavaScript file."""
        if not self._keep_js(url):
            return 0
        self._js_cache = None
        return self._db.upsert(
            "js_files",
            {
                "scan_id": self.scan_id,
                "url": url,
                "hash": hash_,
                "size": size,
                "priority_score": priority_score,
                "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            conflict_columns=["scan_id", "url"],
            update_columns=["hash", "size", "priority_score", "last_seen"],
        )

    @property
    def js_files(self) -> Set[str]:
        """Get all JS file URLs (cached)."""
        if self._js_cache is None:
            rows = self._db.fetch_all(
                "SELECT url FROM js_files WHERE scan_id = ? ORDER BY priority_score DESC",
                (self.scan_id,),
            )
            self._js_cache = {r["url"] for r in rows}
        return self._js_cache

    def get_unanalyzed_js(self, limit: int = 50) -> List[str]:
        """Get JS files not yet analyzed, ordered by priority."""
        rows = self._db.fetch_all(
            """SELECT url FROM js_files
               WHERE scan_id = ? AND analyzed = 0
               ORDER BY priority_score DESC LIMIT ?""",
            (self.scan_id, limit),
        )
        return [r["url"] for r in rows]

    def mark_js_analyzed(self, url: str, secrets: int = 0, routes: int = 0) -> None:
        """Mark a JS file as analyzed with result counts."""
        self._db.execute(
            """UPDATE js_files
               SET analyzed = 1, secrets_found = ?, routes_found = ?
               WHERE scan_id = ? AND url = ?""",
            (secrets, routes, self.scan_id, url),
        )

    # ─── Parameters ───────────────────────────────────────────────────────────

    def add_param(self, name: str, source: str = "unknown") -> int:
        """Add a discovered parameter name."""
        self._params_cache = None
        return self._db.upsert(
            "params",
            {
                "scan_id": self.scan_id,
                "name": name,
                "source": source,
            },
            conflict_columns=["scan_id", "name"],
            update_columns=["source"],
        )

    def add_params_bulk(self, names: List[str], source: str = "unknown") -> int:
        """Legacy wrapper → delegates to bulk_insert_params."""
        return self.bulk_insert_params(names, source)

    @property
    def params(self) -> Set[str]:
        """Get all parameter names (cached)."""
        if self._params_cache is None:
            rows = self._db.fetch_all(
                "SELECT name FROM params WHERE scan_id = ?", (self.scan_id,)
            )
            self._params_cache = {r["name"] for r in rows}
        return self._params_cache

    def get_untested_params(self, limit: int = 20) -> List[str]:
        """Get params not yet tested for vulns."""
        rows = self._db.fetch_all(
            "SELECT name FROM params WHERE scan_id = ? AND tested = 0 LIMIT ?",
            (self.scan_id, limit),
        )
        return [r["name"] for r in rows]

    def mark_param_tested(self, name: str) -> None:
        """Mark a parameter as tested."""
        self._db.execute(
            "UPDATE params SET tested = 1 WHERE scan_id = ? AND name = ?",
            (self.scan_id, name),
        )

    def tag_param_gf(self, name: str, patterns: List[str]) -> None:
        """Tag a parameter with GF pattern matches (xss, sqli, etc.)."""
        self._db.execute(
            "UPDATE params SET gf_patterns = ? WHERE scan_id = ? AND name = ?",
            (json.dumps(patterns), self.scan_id, name),
        )

    # ─── Paths (200/403) ─────────────────────────────────────────────────────

    def add_path(self, url: str, status_code: int, size: int = 0, source: str = "ffuf") -> int:
        """Record a discovered path with its HTTP status code."""
        if not self._keep(url):
            return 0
        return self._db.upsert(
            "paths",
            {
                "scan_id": self.scan_id,
                "url": url,
                "status_code": status_code,
                "size": size,
                "source": source,
            },
            conflict_columns=["scan_id", "url", "status_code"],
            update_columns=["size", "source"],
        )

    @property
    def paths_403(self) -> List[str]:
        """Get all 403 blocked paths."""
        rows = self._db.fetch_all(
            "SELECT url FROM paths WHERE scan_id = ? AND status_code = 403",
            (self.scan_id,),
        )
        return [r["url"] for r in rows]

    @property
    def paths_200(self) -> List[str]:
        """Get all 200 OK paths."""
        rows = self._db.fetch_all(
            "SELECT url FROM paths WHERE scan_id = ? AND status_code = 200",
            (self.scan_id,),
        )
        return [r["url"] for r in rows]

    def get_untested_403s(self) -> List[str]:
        """Get 403 paths not yet tested with bypass engine."""
        rows = self._db.fetch_all(
            "SELECT url FROM paths WHERE scan_id = ? AND status_code = 403 AND bypass_tested = 0",
            (self.scan_id,),
        )
        return [r["url"] for r in rows]

    def mark_403_tested(self, url: str) -> None:
        """Mark a 403 path as bypass-tested."""
        self._db.execute(
            "UPDATE paths SET bypass_tested = 1 WHERE scan_id = ? AND url = ? AND status_code = 403",
            (self.scan_id, url),
        )

    # ─── API Endpoints ────────────────────────────────────────────────────────

    def add_api_endpoint(self, path: str, source: str = "js_mine", method: str = "GET") -> int:
        """Add a discovered API endpoint."""
        return self._db.upsert(
            "api_endpoints",
            {
                "scan_id": self.scan_id,
                "path": path,
                "source": source,
                "method": method,
            },
            conflict_columns=["scan_id", "path", "method"],
            update_columns=["source"],
        )

    @property
    def api_endpoints(self) -> List[str]:
        """Get all API endpoint paths."""
        rows = self._db.fetch_all(
            "SELECT path FROM api_endpoints WHERE scan_id = ?", (self.scan_id,)
        )
        return [r["path"] for r in rows]

    # ─── Ports ────────────────────────────────────────────────────────────────

    def add_port(
        self, ip: str, port: int, protocol: str = "tcp",
        service: str = "", version: str = "", source: str = "nmap",
    ) -> int:
        """Record an open port."""
        return self._db.upsert(
            "ports",
            {
                "scan_id": self.scan_id,
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "service": service,
                "version": version,
                "source": source,
                "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            conflict_columns=["scan_id", "ip", "port", "protocol"],
            update_columns=["service", "version", "source", "last_seen"],
        )

    # ─── Secrets ──────────────────────────────────────────────────────────────

    def add_secret(
        self, pattern_name: str, value_preview: str,
        source_url: str = "", source_type: str = "unknown",
        severity: str = "MEDIUM", cwe: str = "", validated: bool = False,
    ) -> int:
        """Record a discovered secret."""
        # Mask the preview: show first 20 chars + ***
        masked = value_preview[:20] + "***" if len(value_preview) > 20 else value_preview
        return self._db.upsert(
            "secrets",
            {
                "scan_id": self.scan_id,
                "pattern_name": pattern_name,
                "value_preview": masked,
                "source_url": source_url,
                "source_type": source_type,
                "severity": severity,
                "cwe": cwe,
                "validated": 1 if validated else 0,
            },
            conflict_columns=["scan_id", "pattern_name", "value_preview", "source_url"],
            update_columns=["severity", "validated"],
        )

    # ─── Findings ─────────────────────────────────────────────────────────────

    def add_finding(
        self,
        severity: str,
        category: str,
        url: str,
        title: str,
        detail: str = "",
        impact: str = "",
        exploit: str = "",
        confidence: str = "LOW",
        cwe: str = "",
        phase: str = "",
    ) -> int:
        """Add a vulnerability finding with automatic CVSS/OWASP/MITRE enrichment.

        This is the PRIMARY interface for step modules to report findings.
        """
        # Auto-enrich from mapping tables
        cvss_score, cvss_vector = CVSS_MAP.get(severity.upper(), (0.0, ""))
        owasp, mitre_tactic, mitre_technique = CATEGORY_MAP.get(category, ("", "", ""))

        return self._db.upsert(
            "findings",
            {
                "scan_id": self.scan_id,
                "severity": severity.upper(),
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "category": category,
                "cwe": cwe,
                "owasp": owasp,
                "mitre_tactic": mitre_tactic,
                "mitre_technique": mitre_technique,
                "url": url,
                "title": title,
                "detail": detail,
                "impact": impact,
                "exploit": exploit,
                "confidence": confidence,
                "phase": phase,
                "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "is_new": 1,
            },
            conflict_columns=["scan_id", "category", "url", "title"],
            update_columns=[
                "severity", "cvss_score", "cvss_vector", "detail", "impact",
                "exploit", "confidence", "phase", "last_seen",
            ],
        )

    @property
    def findings(self) -> List[Dict[str, Any]]:
        """Get all findings, ordered by severity."""
        sev_order = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
        rows = self._db.fetch_all(
            f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {sev_order}, category",
            (self.scan_id,),
        )
        return [dict(r) for r in rows]

    def finding_count(self) -> int:
        """Count total findings."""
        return self._db.fetch_scalar(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (self.scan_id,)
        ) or 0

    def findings_by_severity(self) -> Dict[str, int]:
        """Get finding counts grouped by severity."""
        rows = self._db.fetch_all(
            """SELECT severity, COUNT(*) as cnt FROM findings
               WHERE scan_id = ? GROUP BY severity""",
            (self.scan_id,),
        )
        return {r["severity"]: r["cnt"] for r in rows}

    # ─── Checkpointing ────────────────────────────────────────────────────────

    def snapshot(self) -> Dict[str, Any]:
        """Create a JSON-serializable snapshot of scan-level state for checkpointing.

        This captures the mutable fields that are NOT in per-row tables.
        Per-row data (subdomains, urls, findings) is already in SQLite.
        """
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "domain": self.domain,
            "root_domain": self.root_domain,
            "scheme": self.scheme,
            "origin_ip": self.origin_ip,
            "probe_base": self.probe_base,
            "host_header": self.host_header,
            "waf_detected": self.waf_detected,
            "cdn_detected": self.cdn_detected,
            "tech_stack": self.tech_stack,
            "server_header": self.server_header,
            "powered_by": self.powered_by,
            "http_code": self.http_code,
            "security_headers": self.security_headers,
            "wildcard_ip": self.wildcard_ip,
            "completed_steps": sorted(self.completed_steps),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def restore_from_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """Restore scan-level state from a checkpoint snapshot."""
        for key in (
            "origin_ip", "waf_detected", "cdn_detected", "tech_stack",
            "server_header", "powered_by", "http_code", "security_headers",
            "wildcard_ip",
        ):
            if key in snapshot:
                setattr(self, key, snapshot[key])
        if isinstance(snapshot.get("completed_steps"), list):
            self.completed_steps = {int(x) for x in snapshot["completed_steps"]}
        # Recompute derived fields
        self.probe_base = (
            f"{self.scheme}://{self.origin_ip}"
            if self.origin_ip
            else f"{self.scheme}://{self.domain}"
        )
        self.host_header = self.domain if self.origin_ip else ""

    def save_checkpoint(self, step: int) -> None:
        """Persist current state as a checkpoint.

        ``step`` is kept for backward compatibility (scans.current_step); the
        authoritative resume state is ``completed_steps`` in the snapshot.
        """
        self.persist_scan_state()
        self._db.save_checkpoint(self.scan_id, step, self.snapshot())

    # ─── Statistics ───────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, int]:
        """Get comprehensive scan statistics."""
        return self._db.scan_stats(self.scan_id)

    # ─── Probe URL Helper ─────────────────────────────────────────────────────

    def probe_url(self, path: str = "") -> str:
        """Build a URL for probing (respects origin IP if set)."""
        base = f"{self.scheme}://{self.origin_ip}" if self.origin_ip else self.probe_base
        if path:
            return f"{base}/{path.lstrip('/')}"
        return base

    # ─── Diff Against Previous Scan ───────────────────────────────────────────

    def diff_previous(self) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """Compare this scan against the most recent completed scan of same domain.

        Returns None if no previous scan exists.
        """
        prev = self._db.get_latest_scan(self.domain)
        if not prev or prev["scan_id"] == self.scan_id:
            return None
        return self._db.diff_scans(self.scan_id, prev["scan_id"])

    # ─── Finalize ─────────────────────────────────────────────────────────────

    def finalize(self) -> None:
        """Mark the scan as completed."""
        self.persist_scan_state()
        self._db.complete_scan(self.scan_id)
