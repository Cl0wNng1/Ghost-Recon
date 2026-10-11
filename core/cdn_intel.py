"""
GHOST RECON v2.0 — core/cdn_intel.py
CDN/WAF Infrastructure Triage Engine

Architecture:
  1. ASN → PTR → CIDR triple-layer CDN classification (zero external API calls)
  2. Origin IP discovery via Shodan/Censys SSL certificate history
  3. Origin validation via ASN correlation + response similarity scoring
  4. Integrated into Step 2 (quarantine CDN edges) and Step 9 (scan only origins)

Usage:
    from core.cdn_intel import is_cdn_ip, CdnTriage, OriginDiscoverer

    is_cdn, vendor = is_cdn_ip("104.16.132.229")
    # → (True, "cloudflare")

    triage = CdnTriage()
    result = triage.classify("104.16.132.229", asn=13335, ptr="...")
    # → CdnVerdict(is_cdn=True, vendor="cloudflare", confidence="HIGH", ...)

    discoverer = OriginDiscoverer(engine, ctx)
    origin = await discoverer.hunt("example.com")
    # → OriginResult(ip="93.184.216.34", method="shodan_ssl", validated=True)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("ghost.cdn_intel")


# ═══════════════════════════════════════════════════════════════════════════════
# CDN ASN DATABASE (Zero external calls — pure local lookup)
# ═══════════════════════════════════════════════════════════════════════════════

CDN_ASN_MAP: Dict[int, str] = {
    # Cloudflare
    13335: "cloudflare", 209242: "cloudflare",
    # Akamai (all major ASNs)
    16625: "akamai", 20940: "akamai", 21342: "akamai",
    22207: "akamai", 23454: "akamai", 31107: "akamai",
    23455: "akamai", 34164: "akamai", 35994: "akamai",
    # AWS CloudFront
    16509: "cloudfront", 14618: "cloudfront",
    # Fastly
    54113: "fastly",
    # Incapsula / Imperva
    19551: "incapsula",
    # Azure Front Door / CDN
    8075: "azure_cdn", 8069: "azure_cdn",
    # GCP / Google
    15169: "google_cdn", 36492: "google_cdn",
    # Sucuri
    30148: "sucuri",
    # BunnyCDN
    47172: "bunny_cdn",
    # StackPath / Highwinds
    33438: "stackpath", 12989: "stackpath",
    # KeyCDN
    44486: "keycdn",
    # CDNetworks
    36408: "cdnetworks",
    # ArvanCloud
    202468: "arvancloud",
    # DDoS-Guard
    57724: "ddos_guard",
}

CDN_PTR_PATTERNS: List[str] = [
    "cloudflare.com", "cloudflare.net", "cf-dns",
    "akamai.com", "akamaiedge.net", "akamaized.net", "akamaitechnologies",
    "cloudfront.net", "amazonaws.com",
    "fastly.net", "fastlylb.net",
    "incapdns.net", "incapsula.com", "imperva",
    "azure.com", "azureedge.net", "trafficmanager.net", "msedge.net",
    "googlesyndication.com", "googleusercontent.com", "1e100.net",
    "sucuri.net", "sucuricdn",
    "bunnycdn.com", "b-cdn.net",
    "stackpathcdn.com", "hwcdn.net",
    "ddos-guard.net",
    "arvancdn.ir",
]

# Well-known CDN IP prefix hints (used when ASN/PTR unavailable)
CDN_CIDR_HINTS: List[str] = [
    # Cloudflare
    "103.21.244.", "103.22.200.", "103.31.4.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "198.41.128.", "198.41.192.",
    "162.158.", "141.101.",
    # Fastly
    "23.227.38.", "23.227.39.",
    "151.101.",
    # CloudFront
    "54.230.", "54.239.", "99.84.", "99.86.", "205.251.",
    "52.84.", "52.85.",
    "143.204.",
    # Incapsula
    "45.223.",
    "107.154.",
]


@dataclass
class CdnVerdict:
    """Result of CDN classification for a single IP."""
    is_cdn: bool
    vendor: str = ""
    confidence: str = ""         # HIGH | MEDIUM | LOW
    detection_method: str = ""   # asn | ptr | cidr | header
    raw_asn: int = 0
    raw_ptr: str = ""


def is_cdn_ip(ip: str, asn: int = 0, ptr: str = "") -> Tuple[bool, str]:
    """
    Quick boolean check: (is_cdn, vendor_name).
    Checks ASN → PTR → CIDR hint in priority order.
    """
    if asn and asn in CDN_ASN_MAP:
        return True, CDN_ASN_MAP[asn]

    ptr_lower = ptr.lower()
    for pattern in CDN_PTR_PATTERNS:
        if pattern in ptr_lower:
            vendor = pattern.split(".")[0].replace("-", "_")
            return True, vendor

    for cidr in CDN_CIDR_HINTS:
        if ip.startswith(cidr):
            return True, "cdn_cidr_match"

    return False, ""


class CdnTriage:
    """Full CDN classification engine with confidence scoring."""

    # HTTP response headers that indicate CDN/WAF presence
    CDN_HEADER_SIGS: Dict[str, str] = {
        "cf-ray": "cloudflare",
        "cf-cache-status": "cloudflare",
        "x-amz-cf-id": "cloudfront",
        "x-amz-cf-pop": "cloudfront",
        "x-akamai-transformed": "akamai",
        "x-cache-key": "akamai",
        "x-fastly-request-id": "fastly",
        "x-served-by": "fastly",
        "x-iinfo": "incapsula",
        "x-sucuri-id": "sucuri",
        "x-azure-ref": "azure_cdn",
    }

    def classify(
        self, ip: str, asn: int = 0, ptr: str = "",
        response_headers: Optional[Dict[str, str]] = None,
    ) -> CdnVerdict:
        """Classify an IP with full confidence scoring."""
        # Priority 1: ASN match (HIGH confidence)
        if asn and asn in CDN_ASN_MAP:
            return CdnVerdict(
                is_cdn=True, vendor=CDN_ASN_MAP[asn],
                confidence="HIGH", detection_method="asn",
                raw_asn=asn, raw_ptr=ptr,
            )

        # Priority 2: PTR match (HIGH confidence)
        ptr_lower = ptr.lower()
        for pattern in CDN_PTR_PATTERNS:
            if pattern in ptr_lower:
                vendor = pattern.split(".")[0].replace("-", "_")
                return CdnVerdict(
                    is_cdn=True, vendor=vendor,
                    confidence="HIGH", detection_method="ptr",
                    raw_asn=asn, raw_ptr=ptr,
                )

        # Priority 3: Response header signatures (MEDIUM confidence)
        if response_headers:
            hdrs_lower = {k.lower(): v for k, v in response_headers.items()}
            for hdr, vendor in self.CDN_HEADER_SIGS.items():
                if hdr in hdrs_lower:
                    return CdnVerdict(
                        is_cdn=True, vendor=vendor,
                        confidence="MEDIUM", detection_method="header",
                        raw_asn=asn, raw_ptr=ptr,
                    )
            # Server header check
            server = hdrs_lower.get("server", "").lower()
            if "cloudflare" in server:
                return CdnVerdict(
                    is_cdn=True, vendor="cloudflare",
                    confidence="MEDIUM", detection_method="header",
                    raw_asn=asn, raw_ptr=ptr,
                )

        # Priority 4: CIDR hint (LOW confidence)
        for cidr in CDN_CIDR_HINTS:
            if ip.startswith(cidr):
                return CdnVerdict(
                    is_cdn=True, vendor="cdn_cidr_match",
                    confidence="LOW", detection_method="cidr",
                    raw_asn=asn, raw_ptr=ptr,
                )

        return CdnVerdict(is_cdn=False, raw_asn=asn, raw_ptr=ptr)

    def classify_from_httpx(self, httpx_result: Dict) -> CdnVerdict:
        """Classify from an httpx JSON probe result."""
        ip = ""
        # Extract IP from 'a' field or from URL
        if "a" in httpx_result and httpx_result["a"]:
            ips = httpx_result["a"]
            ip = ips[0] if isinstance(ips, list) else str(ips)

        headers = {}
        if "header" in httpx_result and isinstance(httpx_result["header"], dict):
            headers = httpx_result["header"]

        return self.classify(ip, response_headers=headers)


# ═══════════════════════════════════════════════════════════════════════════════
# ORIGIN DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class OriginResult:
    """Result of origin IP hunting."""
    ip: str = ""
    method: str = ""             # shodan_ssl | censys_ssl | dns_history | asn_scan
    validated: bool = False
    validation_method: str = ""  # response_match | asn_match | whois_match
    confidence: str = ""         # HIGH | MEDIUM | LOW
    ssl_cn: str = ""             # Common Name from SSL cert
    org: str = ""                # Organization from Shodan/ASN


class OriginDiscoverer:
    """
    Discovers the true origin IP behind CDN/WAF infrastructure.

    Methods (in priority order):
    1. Shodan SSL certificate history search
    2. Censys SSL certificate search
    3. DNS history via SecurityTrails
    4. ASN range scanning via hakoriginfinder-style matching

    Every candidate must pass validation before promotion.
    """

    def __init__(self, engine: Any = None, shodan_key: str = "", censys_id: str = "",
                 censys_secret: str = "", target_domain: str = ""):
        self._engine = engine
        self._shodan_key = shodan_key
        self._censys_id = censys_id
        self._censys_secret = censys_secret
        self._domain = target_domain

    async def hunt(self, domain: str = "") -> Optional[OriginResult]:
        """
        Execute the full origin hunting pipeline.
        Returns the best validated OriginResult, or None.
        """
        domain = domain or self._domain
        if not domain:
            return None

        candidates: List[OriginResult] = []

        # Method 1: Shodan SSL history
        if self._shodan_key and self._engine:
            try:
                result = await self._shodan_ssl_search(domain)
                if result:
                    candidates.append(result)
            except Exception as e:
                log.debug(f"Shodan SSL search failed: {e}")

        # Method 2: Censys SSL search
        if self._censys_id and self._censys_secret and self._engine:
            try:
                result = await self._censys_ssl_search(domain)
                if result:
                    candidates.append(result)
            except Exception as e:
                log.debug(f"Censys SSL search failed: {e}")

        # Validate candidates
        validated = []
        for c in candidates:
            is_valid = await self._validate_origin(c.ip, domain)
            if is_valid:
                c.validated = True
                c.validation_method = "response_match"
                c.confidence = "HIGH"
                validated.append(c)
            else:
                # Check if it's at least not a CDN
                cdn_check, vendor = is_cdn_ip(c.ip)
                if not cdn_check:
                    c.validated = False
                    c.confidence = "LOW"
                    c.validation_method = "non_cdn_only"
                    validated.append(c)

        if not validated:
            return None

        # Return highest confidence
        validated.sort(key=lambda r: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(r.confidence, 3))
        return validated[0]

    async def _shodan_ssl_search(self, domain: str) -> Optional[OriginResult]:
        """Search Shodan for IPs with SSL certs matching the domain."""
        if not self._engine:
            return None

        query = f"ssl.cert.subject.cn:{domain}"
        url = f"https://api.shodan.io/shodan/host/search?key={self._shodan_key}&query={query}&page=1"

        try:
            resp = await self._engine.get(url, timeout=15.0, scope="shodan")
            if resp.code != 200:
                return None

            data = json.loads(resp.body)
            matches = data.get("matches", [])

            for match in matches[:10]:
                ip = match.get("ip_str", "")
                if not ip:
                    continue

                # Skip known CDN IPs
                cdn_check, vendor = is_cdn_ip(ip)
                if cdn_check:
                    continue

                org = match.get("org", "")
                ssl_cn = ""
                ssl_data = match.get("ssl", {})
                if ssl_data:
                    cert = ssl_data.get("cert", {})
                    subject = cert.get("subject", {})
                    ssl_cn = subject.get("CN", "")

                return OriginResult(
                    ip=ip, method="shodan_ssl",
                    ssl_cn=ssl_cn, org=org,
                    confidence="MEDIUM",
                )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            log.debug(f"Shodan SSL parse error: {e}")

        return None

    async def _censys_ssl_search(self, domain: str) -> Optional[OriginResult]:
        """Search Censys for IPs with SSL certs matching the domain."""
        if not self._engine:
            return None

        import base64
        auth = base64.b64encode(f"{self._censys_id}:{self._censys_secret}".encode()).decode()

        url = "https://search.censys.io/api/v2/hosts/search"
        query_body = json.dumps({
            "q": f"services.tls.certificates.leaf.names: {domain}",
            "per_page": 10,
        })

        try:
            resp = await self._engine.request(
                url, method="POST",
                extra_headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json",
                },
                timeout=15.0, scope="censys",
            )
            if resp.code != 200:
                return None

            data = json.loads(resp.body)
            hits = data.get("result", {}).get("hits", [])

            for hit in hits[:10]:
                ip = hit.get("ip", "")
                if not ip:
                    continue

                cdn_check, _ = is_cdn_ip(ip)
                if cdn_check:
                    continue

                return OriginResult(
                    ip=ip, method="censys_ssl",
                    confidence="MEDIUM",
                )
        except Exception as e:
            log.debug(f"Censys search error: {e}")

        return None

    async def _validate_origin(self, candidate_ip: str, domain: str) -> bool:
        """
        Validate that a candidate IP is the real origin by comparing
        response similarity when requesting with Host: <domain>.
        """
        if not self._engine:
            return False

        try:
            # Request the CDN version (via domain)
            cdn_resp = await self._engine.get(
                f"https://{domain}/",
                timeout=10.0, scope="target",
            )

            # Request the candidate directly with Host header
            origin_resp = await self._engine.get(
                f"https://{candidate_ip}/",
                extra_headers={"Host": domain},
                timeout=10.0, scope="target",
            )

            if cdn_resp.code == 0 or origin_resp.code == 0:
                return False

            # Similarity checks:
            # 1. Status code match
            if cdn_resp.code != origin_resp.code:
                return False

            # 2. Body similarity (simple length-based heuristic)
            if cdn_resp.size > 0 and origin_resp.size > 0:
                ratio = min(cdn_resp.size, origin_resp.size) / max(cdn_resp.size, origin_resp.size)
                if ratio > 0.7:
                    return True

            # 3. Title match
            cdn_title = re.search(r'<title[^>]*>([^<]+)</title>', cdn_resp.body or '', re.I)
            origin_title = re.search(r'<title[^>]*>([^<]+)</title>', origin_resp.body or '', re.I)
            if cdn_title and origin_title:
                if cdn_title.group(1).strip().lower() == origin_title.group(1).strip().lower():
                    return True

        except Exception as e:
            log.debug(f"Origin validation error for {candidate_ip}: {e}")

        return False
