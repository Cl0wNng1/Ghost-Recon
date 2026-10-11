"""
GHOST RECON v2.0 — core/nessus_client.py
Async Nessus REST API client with exponential backoff, jitter, and
standardized finding normalization for Critical/High severity findings.

Authentication: API Key pair (X-ApiKeys header).
Transport:      httpx.AsyncClient (enforced by Ghost architecture contract).
Concurrency:    asyncio.Semaphore(4) — Nessus REST server is single-threaded
                internally; flooding it produces 500s.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("ghost.nessus")

# Nessus severity integer mapping (Tenable internal encoding)
_NESSUS_SEV: Dict[int, str] = {
    0: "INFO",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}

# Severities we import into Ghost findings
_IMPORT_SEVERITIES: frozenset[str] = frozenset({"CRITICAL", "HIGH"})

# Exponential backoff parameters
_BACKOFF_BASE: float = 1.0
_BACKOFF_MAX: float = 64.0
_BACKOFF_RETRIES: int = 7
_JITTER_MAX: float = 2.0


def _jitter() -> float:
    return random.uniform(0.0, _JITTER_MAX)


# ═══════════════════════════════════════════════════════════════════════════════
# STANDARDIZED FINDING SCHEMA
# (matches ctx.add_finding() parameter contract)
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_finding(vuln: Dict[str, Any], target: str) -> Dict[str, Any]:
    """
    Convert a Nessus plugin/host vulnerability dict into a Ghost-standard
    finding dict suitable for ctx.add_finding(**finding).
    """
    plugin: Dict[str, Any] = vuln.get("plugin", {})
    plugin_id: int = plugin.get("id", 0)
    name: str = plugin.get("name", f"Nessus Plugin {plugin_id}")
    description: str = plugin.get("description", "")
    solution: str = plugin.get("solution", "")
    synopsis: str = plugin.get("synopsis", "")
    cvss3_score: float = plugin.get("cvss3_base_score", 0.0) or 0.0
    cve_list: List[str] = plugin.get("cve", []) or []
    cve_str: str = ", ".join(cve_list[:5])  # cap display

    sev_int: int = vuln.get("severity", 0)
    sev_str: str = _NESSUS_SEV.get(sev_int, "INFO")

    # Map to Ghost category
    family: str = plugin.get("family", {}).get("name", "") if isinstance(plugin.get("family"), dict) else str(plugin.get("family", ""))
    category: str = _map_family_to_category(family, name)

    port_info: Dict[str, Any] = vuln.get("port", {})
    port: int = port_info.get("port", 0) if isinstance(port_info, dict) else 0
    protocol: str = port_info.get("protocol", "tcp") if isinstance(port_info, dict) else "tcp"

    host_str: str = vuln.get("asset", {}).get("hostname", target) if isinstance(vuln.get("asset"), dict) else target
    url: str = f"{host_str}:{port}" if port else host_str

    plugin_output: str = vuln.get("plugin_output", "")[:1000] if vuln.get("plugin_output") else ""

    detail_parts = [synopsis, description]
    if cve_str:
        detail_parts.append(f"CVEs: {cve_str}")
    if plugin_output:
        detail_parts.append(f"Plugin Output:\n{plugin_output}")
    detail: str = "\n\n".join(p for p in detail_parts if p)

    return {
        "severity": sev_str,
        "category": category,
        "url": url,
        "title": f"[Nessus] {name}",
        "detail": detail[:2000],
        "impact": f"CVSS3: {cvss3_score:.1f}" if cvss3_score else "",
        "exploit": solution[:500] if solution else "",
        "confidence": "HIGH",
        "cwe": "",
        "phase": "step13_vulnscan",
    }


def _map_family_to_category(family: str, name: str) -> str:
    """Map Nessus plugin family to Ghost category enum."""
    fl = family.lower()
    nl = name.lower()
    if "web" in fl or "xss" in nl or "injection" in nl:
        return "SQLI" if "sql" in nl else "XSS_REFLECTED"
    if "backdoor" in fl or "malware" in fl:
        return "TECH_CVE"
    if "denial" in fl:
        return "OPEN_PORTS"
    if "default" in nl and "credential" in nl:
        return "SECRET_LEAK"
    if "misconfiguration" in fl or "config" in nl:
        return "CORS_MISCONFIG"
    return "TECH_CVE"


# ═══════════════════════════════════════════════════════════════════════════════
# NESSUS CLIENT
# ═══════════════════════════════════════════════════════════════════════════════

class NessusClient:
    """
    Async Nessus REST API client.

    Args:
        base_url:   Nessus server URL (e.g., https://nessus.internal:8834)
        access_key: Nessus API access key
        secret_key: Nessus API secret key
        verify_ssl: SSL verification (default False — Nessus uses self-signed)
        timeout:    Per-request timeout in seconds
    """

    def __init__(
        self,
        base_url: str,
        access_key: str,
        secret_key: str,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self._base: str = base_url.rstrip("/")
        self._headers: Dict[str, str] = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._verify: bool = verify_ssl
        self._timeout: float = timeout
        self._sem: asyncio.Semaphore = asyncio.Semaphore(4)
        # Circuit breaker: set True after repeated 5xx / auth failure
        self._dead: bool = False

    # ─── Internal HTTP engine ─────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Execute an authenticated HTTP request with exponential backoff + jitter.

        Retries on:
          - HTTP 429 (rate-limit)
          - HTTP 500-503 (transient server error)

        Raises:
          - httpx.HTTPStatusError on non-retryable 4xx
          - RuntimeError if circuit breaker is open
        """
        if self._dead:
            raise RuntimeError("NessusClient circuit breaker open — server unreachable.")

        url = f"{self._base}/{path.lstrip('/')}"
        delay: float = _BACKOFF_BASE

        async with self._sem:
            async with httpx.AsyncClient(
                verify=self._verify,
                timeout=self._timeout,
                headers=self._headers,
            ) as client:
                for attempt in range(_BACKOFF_RETRIES):
                    try:
                        resp = await client.request(
                            method,
                            url,
                            json=payload,
                            params=params,
                        )
                    except (httpx.TimeoutException, httpx.ConnectError) as exc:
                        log.warning("[nessus] network error attempt %d: %s", attempt + 1, exc)
                        if attempt == _BACKOFF_RETRIES - 1:
                            self._dead = True
                            raise
                        await asyncio.sleep(min(delay, _BACKOFF_MAX) + _jitter())
                        delay *= 2.0
                        continue

                    # 429 / 5xx → back off and retry
                    if resp.status_code == 429 or resp.status_code >= 500:
                        wait: float = min(delay, _BACKOFF_MAX) + _jitter()
                        log.warning(
                            "[nessus] HTTP %d on attempt %d — backing off %.1fs",
                            resp.status_code, attempt + 1, wait,
                        )
                        if attempt == _BACKOFF_RETRIES - 1:
                            self._dead = True
                            resp.raise_for_status()
                        await asyncio.sleep(wait)
                        delay *= 2.0
                        continue

                    # Auth failure → circuit break
                    if resp.status_code in (401, 403):
                        self._dead = True
                        log.error("[nessus] auth failure HTTP %d — circuit breaker opened", resp.status_code)
                        resp.raise_for_status()

                    resp.raise_for_status()

                    try:
                        return resp.json()
                    except json.JSONDecodeError:
                        return {}

        # Should not reach here
        raise RuntimeError("NessusClient: exhausted retry budget")

    # ─── Public API ───────────────────────────────────────────────────────────

    async def launch_scan(self, policy_id: int, target: str) -> str:
        """
        Create and launch a Nessus scan.

        Args:
            policy_id: Nessus scan policy template ID
            target:    Target hostname or IP

        Returns:
            scan_uuid (str) — opaque identifier for poll_scan / fetch_results
        """
        # Step 1: create scan
        create_payload: Dict[str, Any] = {
            "uuid": await self._get_policy_template_uuid(policy_id),
            "settings": {
                "name": f"Ghost_v14_{target}_{int(time.time())}",
                "policy_id": policy_id,
                "text_targets": target,
                "launch": "ON_DEMAND",
                "enabled": True,
                "scanner_id": "local",
            },
        }
        create_resp: Dict[str, Any] = await self._request("POST", "/scans", payload=create_payload)
        scan: Dict[str, Any] = create_resp.get("scan", {})
        scan_id: int = scan.get("id", 0)

        if not scan_id:
            raise ValueError(f"Nessus scan creation failed: {create_resp}")

        # Step 2: launch
        launch_resp: Dict[str, Any] = await self._request("POST", f"/scans/{scan_id}/launch")
        scan_uuid: str = launch_resp.get("scan_uuid", "")

        if not scan_uuid:
            raise ValueError(f"Nessus scan launch failed — no UUID returned: {launch_resp}")

        log.info("[nessus] scan launched: id=%d uuid=%s target=%s", scan_id, scan_uuid, target)
        return scan_uuid

    async def _get_policy_template_uuid(self, policy_id: int) -> str:
        """Resolve the template UUID for a given policy ID."""
        templates: Dict[str, Any] = await self._request("GET", "/editor/scan/templates")
        for tmpl in templates.get("templates", []):
            if isinstance(tmpl, dict) and tmpl.get("id") == policy_id:
                return tmpl.get("uuid", "")
        # Fallback: basic network scan template UUID (Tenable default)
        return "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"

    async def poll_scan(self, scan_uuid: str) -> str:
        """
        Poll a running scan until completion.

        Args:
            scan_uuid: UUID returned by launch_scan

        Returns:
            Final status string: "completed" | "aborted" | "canceled" | "error"
        """
        terminal_states: frozenset[str] = frozenset({
            "completed", "aborted", "canceled", "imported", "empty",
        })
        poll_interval: float = 15.0

        # Resolve scan_uuid → numeric scan ID for status endpoint
        scan_list: Dict[str, Any] = await self._request("GET", "/scans")
        scan_id: Optional[int] = None
        for s in scan_list.get("scans", []) or []:
            if isinstance(s, dict) and s.get("uuid") == scan_uuid:
                scan_id = s.get("id")
                break

        if scan_id is None:
            log.warning("[nessus] poll_scan: UUID %s not found in scan list", scan_uuid)
            return "error"

        while True:
            detail: Dict[str, Any] = await self._request("GET", f"/scans/{scan_id}")
            info: Dict[str, Any] = detail.get("info", {})
            status: str = info.get("status", "unknown")

            log.debug("[nessus] scan %s status=%s", scan_uuid, status)

            if status in terminal_states:
                log.info("[nessus] scan %s → %s", scan_uuid, status)
                return status

            await asyncio.sleep(poll_interval)

    async def fetch_results(self, scan_uuid: str) -> List[Dict[str, Any]]:
        """
        Fetch and normalize Critical/High findings from a completed scan.

        Args:
            scan_uuid: UUID returned by launch_scan

        Returns:
            List of Ghost-standard finding dicts (compatible with ctx.add_finding).
        """
        # Resolve UUID → scan_id and target
        scan_list: Dict[str, Any] = await self._request("GET", "/scans")
        scan_id: Optional[int] = None
        target: str = ""
        for s in scan_list.get("scans", []) or []:
            if isinstance(s, dict) and s.get("uuid") == scan_uuid:
                scan_id = s.get("id")
                target = s.get("name", "")
                break

        if scan_id is None:
            log.error("[nessus] fetch_results: UUID %s not found", scan_uuid)
            return []

        # Fetch full scan detail (includes vulnerabilities per host)
        detail: Dict[str, Any] = await self._request("GET", f"/scans/{scan_id}")
        vulnerabilities: List[Dict[str, Any]] = detail.get("vulnerabilities", []) or []

        findings: List[Dict[str, Any]] = []
        seen: set[str] = set()

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            sev_int: int = vuln.get("severity", 0)
            sev_str: str = _NESSUS_SEV.get(sev_int, "INFO")

            if sev_str not in _IMPORT_SEVERITIES:
                continue

            plugin_id: int = vuln.get("plugin_id", 0)
            plugin_name: str = vuln.get("plugin_name", f"Plugin {plugin_id}")

            # Fetch per-plugin detail for richer output
            plugin_detail: Dict[str, Any] = {}
            try:
                plugin_detail = await self._request(
                    "GET", f"/scans/{scan_id}/plugins/{plugin_id}"
                )
            except Exception as exc:
                log.debug("[nessus] plugin detail fetch failed %d: %s", plugin_id, exc)

            # Build synthetic vuln dict for normalizer
            enriched: Dict[str, Any] = {
                "severity": sev_int,
                "plugin": {
                    "id": plugin_id,
                    "name": plugin_name,
                    "family": vuln.get("plugin_family", ""),
                    "description": plugin_detail.get("plugindescription", {})
                                               .get("pluginattributes", {})
                                               .get("description", "")
                                   if isinstance(plugin_detail.get("plugindescription"), dict)
                                   else "",
                    "solution": plugin_detail.get("plugindescription", {})
                                             .get("pluginattributes", {})
                                             .get("solution", "")
                                if isinstance(plugin_detail.get("plugindescription"), dict)
                                else "",
                    "synopsis": plugin_detail.get("plugindescription", {})
                                             .get("pluginattributes", {})
                                             .get("synopsis", "")
                                if isinstance(plugin_detail.get("plugindescription"), dict)
                                else "",
                    "cvss3_base_score": vuln.get("cvss3_base_score", 0.0),
                    "cve": vuln.get("vuln_index", []),
                },
                "asset": {"hostname": target},
                "port": {"port": vuln.get("port", 0), "protocol": "tcp"},
                "plugin_output": "",
            }

            normalized = _normalize_finding(enriched, target)

            dedup_key = f"{normalized['category']}|{normalized['url']}|{normalized['title']}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(normalized)

        log.info(
            "[nessus] scan %s → %d Critical/High findings extracted",
            scan_uuid, len(findings),
        )
        return findings

    async def health_check(self) -> bool:
        """Verify connectivity and auth. Returns True if server is reachable."""
        try:
            resp = await self._request("GET", "/server/status")
            return isinstance(resp, dict) and resp.get("code") == 200
        except Exception:
            return False
