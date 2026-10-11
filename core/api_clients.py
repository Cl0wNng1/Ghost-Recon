"""
GHOST RECON v2.0 — core/api_clients.py
Async OSINT Client Engine — Fixes "Token Amnesia"

Architecture:
  - Single OSINTClients instance initialized once with all API keys
  - Injected into Ctx at scan start → available to every step module
  - All I/O via httpx.AsyncClient + asyncio.Semaphore concurrency control
  - Per-provider circuit breaker: 401 → disable client for remainder of scan
  - 429 → exponential backoff with jitter (never crash the loop)

Usage:
    from core.api_clients import OSINTClients
    osint = OSINTClients(
        shodan_key="...", github_token="...",
        securitytrails_key="...", virustotal_key="...",
        censys_id="...", censys_secret="...",
    )
    ctx.osint = osint  # Wired in ghost.py

    # In any step module:
    subs = await ctx.osint.get_securitytrails_subs("example.com")
    hits = await ctx.osint.search_github_dorks("example.com", ["password", "api_key"])
    intel = await ctx.osint.get_shodan_host_intel("1.2.3.4")
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote

log = logging.getLogger("ghost.osint")

try:
    import httpx
except ImportError:
    raise ImportError(
        "core.api_clients requires httpx. Install: pip install 'httpx[http2]' --break-system-packages"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB DORK PATTERNS (extracted from v10 GITHUB_DORKS)
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_GITHUB_DORKS: List[str] = [
    "password", "secret", "api_key", "apikey", "token",
    "database_url", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY",
    "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
    "smtp_password", "STRIPE_SECRET", "SLACK_TOKEN",
    "SENDGRID_API_KEY", "FIREBASE_CONFIG", "MONGO_URI",
    ".env", "credentials", "authorization",
]


class OSINTClients:
    """
    Centralized async OSINT API client manager.

    Provides resilient access to:
      - Shodan (host intelligence, port data, CVE lookup)
      - GitHub (code search / dorking)
      - SecurityTrails (historical DNS, subdomain enumeration)
      - VirusTotal (subdomain enumeration, domain report)
      - Censys (host search, certificate search)

    Each provider has an independent circuit breaker:
      - 401/403 Unauthorized → provider disabled for scan lifetime
      - 429 Too Many Requests → exponential backoff with jitter
      - Timeout/network error → retry once, then skip
    """

    def __init__(
        self,
        shodan_key: str = "",
        github_token: str = "",
        securitytrails_key: str = "",
        virustotal_key: str = "",
        censys_id: str = "",
        censys_secret: str = "",
        max_concurrency: int = 5,
    ):
        self._shodan_key = shodan_key
        self._github_token = github_token
        self._securitytrails_key = securitytrails_key
        self._virustotal_key = virustotal_key
        self._censys_id = censys_id
        self._censys_secret = censys_secret

        self._sem = asyncio.Semaphore(max_concurrency)

        # Circuit breakers: provider → disabled flag
        self._disabled: Dict[str, bool] = {
            "shodan": not bool(shodan_key),
            "github": not bool(github_token),
            "securitytrails": not bool(securitytrails_key),
            "virustotal": not bool(virustotal_key),
            "censys": not bool(censys_id and censys_secret),
        }

        # Backoff state per provider
        self._backoff_until: Dict[str, float] = {}

        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(15.0, connect=8.0),
                verify=False,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def is_available(self, provider: str) -> bool:
        return not self._disabled.get(provider, True)

    def available_providers(self) -> List[str]:
        return [p for p, disabled in self._disabled.items() if not disabled]

    def _check_disabled(self, provider: str) -> bool:
        if self._disabled.get(provider, True):
            return True
        now = time.monotonic()
        until = self._backoff_until.get(provider, 0)
        if now < until:
            return True
        return False

    def _handle_status(self, provider: str, status: int, headers: Dict[str, str]) -> None:
        if status in (401, 403):
            self._disabled[provider] = True
            log.warning(
                f"[OSINT:{provider}] HTTP {status} — API key invalid/expired. "
                f"Provider DISABLED for remainder of scan."
            )
        elif status == 429:
            retry_after = 10.0
            ra = headers.get("retry-after", "")
            if ra:
                try:
                    retry_after = float(ra)
                except ValueError:
                    pass
            backoff = retry_after + random.uniform(1.0, 5.0)
            self._backoff_until[provider] = time.monotonic() + backoff
            log.warning(
                f"[OSINT:{provider}] 429 Rate Limited — backing off {backoff:.1f}s"
            )

    async def _request(
        self,
        provider: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
        json_body: Optional[Dict] = None,
    ) -> Optional[Dict[str, Any]]:
        if self._check_disabled(provider):
            return None

        async with self._sem:
            try:
                client = await self._get_client()
                if method == "GET":
                    resp = await client.get(url, headers=headers or {})
                else:
                    resp = await client.post(
                        url, headers=headers or {}, json=json_body
                    )

                self._handle_status(provider, resp.status_code, dict(resp.headers))

                if resp.status_code in (401, 403, 429):
                    return None

                if resp.status_code != 200:
                    log.debug(f"[OSINT:{provider}] HTTP {resp.status_code} for {url}")
                    return None

                return resp.json()

            except httpx.HTTPStatusError as e:
                self._handle_status(provider, e.response.status_code, dict(e.response.headers))
                return None
            except httpx.TimeoutException:
                log.debug(f"[OSINT:{provider}] Timeout: {url}")
                return None
            except httpx.ConnectError as e:
                log.debug(f"[OSINT:{provider}] Connection error: {e}")
                return None
            except (json.JSONDecodeError, Exception) as e:
                log.debug(f"[OSINT:{provider}] Error: {e}")
                return None

    # ═══════════════════════════════════════════════════════════════════════
    # SHODAN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_shodan_host_intel(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Query Shodan /shodan/host/{ip} for ports, vulns, org, OS.
        Returns normalized dict or None.
        """
        data = await self._request(
            "shodan",
            f"https://api.shodan.io/shodan/host/{ip}?key={self._shodan_key}",
        )
        if not data or not isinstance(data, dict):
            return None

        return {
            "ip": ip,
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "os": data.get("os", ""),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "asn": data.get("asn", ""),
            "hostnames": data.get("hostnames", []),
            "country": data.get("country_name", ""),
            "last_update": data.get("last_update", ""),
        }

    async def shodan_search(self, query: str, page: int = 1) -> Optional[Dict]:
        """Search Shodan with arbitrary query (e.g., ssl.cert.subject.cn:domain)."""
        return await self._request(
            "shodan",
            f"https://api.shodan.io/shodan/host/search"
            f"?key={self._shodan_key}&query={quote(query)}&page={page}",
        )

    # ═══════════════════════════════════════════════════════════════════════
    # GITHUB
    # ═══════════════════════════════════════════════════════════════════════

    async def search_github_dorks(
        self,
        domain: str,
        dorks: Optional[List[str]] = None,
        max_results_per_dork: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Search GitHub Code API for secrets/credentials related to domain.
        Returns list of {dork, total_count, items: [{html_url, repo, path}]}.
        """
        if self._check_disabled("github"):
            return []

        dork_list = dorks or DEFAULT_GITHUB_DORKS
        all_hits: List[Dict[str, Any]] = []

        for dork in dork_list:
            if self._check_disabled("github"):
                break

            query = f"{domain} {dork}"
            data = await self._request(
                "github",
                f"https://api.github.com/search/code?q={quote(query)}"
                f"&per_page={max_results_per_dork}",
                headers={
                    "Authorization": f"token {self._github_token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Ghost-Recon/13.0",
                },
            )

            if data and isinstance(data, dict):
                total = data.get("total_count", 0)
                if total > 0:
                    items = []
                    for item in data.get("items", [])[:max_results_per_dork]:
                        if isinstance(item, dict):
                            repo = item.get("repository", {})
                            items.append({
                                "html_url": item.get("html_url", ""),
                                "repo": repo.get("full_name", "") if isinstance(repo, dict) else "",
                                "path": item.get("path", ""),
                                "score": item.get("score", 0),
                            })
                    all_hits.append({
                        "dork": dork,
                        "total_count": total,
                        "items": items,
                    })
                    log.info(f"[GitHub] Dork '{dork}' → {total} results")

            # GitHub rate limit: 10 searches/min for authenticated
            await asyncio.sleep(2.5)

        return all_hits

    # ═══════════════════════════════════════════════════════════════════════
    # SECURITYTRAILS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_securitytrails_subs(
        self, domain: str
    ) -> List[str]:
        """
        Fetch subdomains from SecurityTrails API.
        Returns list of FQDNs.
        """
        data = await self._request(
            "securitytrails",
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={
                "APIKEY": self._securitytrails_key,
                "Accept": "application/json",
            },
        )
        if not data or not isinstance(data, dict):
            return []

        subs = data.get("subdomains", [])
        if not isinstance(subs, list):
            return []

        return [f"{s}.{domain}" for s in subs if isinstance(s, str) and s.strip()]

    async def get_securitytrails_history(
        self, domain: str, record_type: str = "a"
    ) -> List[Dict]:
        """Fetch DNS history from SecurityTrails."""
        data = await self._request(
            "securitytrails",
            f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}",
            headers={
                "APIKEY": self._securitytrails_key,
                "Accept": "application/json",
            },
        )
        if not data or not isinstance(data, dict):
            return []

        records = data.get("records", [])
        return records if isinstance(records, list) else []

    # ═══════════════════════════════════════════════════════════════════════
    # VIRUSTOTAL
    # ═══════════════════════════════════════════════════════════════════════

    async def get_virustotal_subs(self, domain: str) -> List[str]:
        """Fetch subdomains from VirusTotal."""
        data = await self._request(
            "virustotal",
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
            headers={"x-apikey": self._virustotal_key},
        )
        if not data or not isinstance(data, dict):
            return []

        subs = []
        for item in data.get("data", []):
            if isinstance(item, dict):
                fqdn = item.get("id", "")
                if fqdn:
                    subs.append(fqdn)
        return subs

    # ═══════════════════════════════════════════════════════════════════════
    # CENSYS
    # ═══════════════════════════════════════════════════════════════════════

    async def censys_host_search(
        self, query: str, per_page: int = 25
    ) -> List[Dict]:
        """Search Censys hosts API."""
        auth = base64.b64encode(
            f"{self._censys_id}:{self._censys_secret}".encode()
        ).decode()

        data = await self._request(
            "censys",
            "https://search.censys.io/api/v2/hosts/search",
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json",
            },
            method="POST",
            json_body={"q": query, "per_page": per_page},
        )
        if not data or not isinstance(data, dict):
            return []

        result = data.get("result", {})
        return result.get("hits", []) if isinstance(result, dict) else []
