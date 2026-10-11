"""
GHOST RECON v2.0 — core/authz_matrix.py
Multi-role access-control (BOLA/BFLA/IDOR) differential testing.

Idea
----
Given the same set of endpoints requested under N identities
(anonymous, low-priv user A, low-priv user B, admin), compare the responses.
A broken-access-control finding is any endpoint where a lower-privilege identity
receives substantially the same successful content as a higher-privilege one,
or where anonymous access succeeds on something meant to be protected.

This is the class of bug scanners miss because it requires *comparing across
sessions*, not testing one request in isolation.

Usage (from a step module):
    matrix = AuthzMatrix(ctx.http_factory)   # factory builds a client per identity
    await matrix.add_identity("anon", cookies={})
    await matrix.add_identity("userA", cookies=userA_cookies)
    await matrix.add_identity("admin", cookies=admin_cookies)
    findings = await matrix.probe(endpoints)
    for f in findings: ctx.add_finding(**f)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = ["AuthzMatrix", "Identity", "Probe"]

# Privilege ranking: higher number = more privilege. Anything a lower rank can
# reach that matches a higher rank's successful response is suspicious.
_DEFAULT_RANK = {"anon": 0, "guest": 0, "user": 1, "usera": 1, "userb": 1,
                 "member": 1, "staff": 2, "manager": 3, "admin": 4, "superadmin": 5}


def _rank(name: str) -> int:
    return _DEFAULT_RANK.get(name.lower(), 1)


def _fingerprint(status: int, body: str) -> str:
    # Coarse fingerprint: status + normalised length bucket + content hash of
    # the first 2KB (ignins volatile tails like CSRF tokens / timestamps).
    snippet = (body or "")[:2048]
    h = hashlib.sha1(snippet.encode("utf-8", "replace")).hexdigest()[:12]
    bucket = len(body or "") // 256
    return f"{status}:{bucket}:{h}"


def _similar(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


@dataclass
class Identity:
    name: str
    client: Any                       # an HttpClient bound to this identity's auth
    rank: int = 0


@dataclass
class Probe:
    url: str
    method: str = "GET"
    # per-identity result: name -> (status, body_text, fingerprint)
    results: Dict[str, Tuple[int, str, str]] = field(default_factory=dict)


class AuthzMatrix:
    def __init__(self, similarity_threshold: float = 0.90) -> None:
        self.identities: List[Identity] = []
        self.threshold = similarity_threshold

    def add_identity(self, name: str, client: Any, rank: Optional[int] = None) -> None:
        self.identities.append(Identity(name=name, client=client,
                                        rank=rank if rank is not None else _rank(name)))
        self.identities.sort(key=lambda i: i.rank)

    async def _fetch(self, ident: Identity, url: str, method: str) -> Tuple[int, str, str]:
        resp = await ident.client.request(method, url)
        if resp is None:
            return (0, "", "0:0:none")
        body = getattr(resp, "_ghost_text", "") or ""
        return (resp.status, body, _fingerprint(resp.status, body))

    async def probe(self, endpoints: List[str], method: str = "GET") -> List[Dict[str, Any]]:
        """Request every endpoint as every identity and diff the results."""
        if len(self.identities) < 2:
            return []

        findings: List[Dict[str, Any]] = []
        highest = self.identities[-1]

        for url in endpoints:
            probe = Probe(url=url, method=method)
            for ident in self.identities:
                probe.results[ident.name] = await self._fetch(ident, url, method)

            findings.extend(self._analyse(probe, highest))
        return findings

    def _analyse(self, probe: Probe, highest: Identity) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        hi_status, hi_body, hi_fp = probe.results.get(highest.name, (0, "", ""))
        hi_ok = 200 <= hi_status < 300 and len(hi_body) > 0

        for ident in self.identities:
            if ident.name == highest.name:
                continue
            lo_status, lo_body, lo_fp = probe.results[ident.name]
            lo_ok = 200 <= lo_status < 300

            # Case 1: lower-priv identity gets a successful response that closely
            # matches the privileged one → horizontal/vertical access control gap.
            if hi_ok and lo_ok:
                sim = _similar(hi_body, lo_body)
                if sim >= self.threshold and ident.rank < highest.rank:
                    sev = "HIGH" if ident.rank == 0 else "MEDIUM"
                    out.append({
                        "severity": sev,
                        "category": "Broken Access Control",
                        "url": probe.url,
                        "title": f"Privileged content reachable as '{ident.name}'",
                        "detail": (
                            f"'{ident.name}' (rank {ident.rank}) received a response "
                            f"{int(sim*100)}% similar to '{highest.name}' (rank "
                            f"{highest.rank}). status {lo_status} vs {hi_status}."
                        ),
                        "impact": "Lower-privilege or anonymous user can access "
                                  "data/functionality intended for higher privilege.",
                        "exploit": f"curl -s '{probe.url}'  # as {ident.name} session",
                        "confidence": "HIGH" if sim >= 0.97 else "MEDIUM",
                        "cwe": "CWE-639" if ident.rank > 0 else "CWE-284",
                        "phase": "authz",
                    })

            # Case 2: anonymous 200 on something that looks protected (redirects
            # everyone else to login) — pure missing auth.
            if ident.rank == 0 and lo_ok and hi_status in (301, 302, 401, 403):
                out.append({
                    "severity": "HIGH",
                    "category": "Broken Access Control",
                    "url": probe.url,
                    "title": "Endpoint accessible without authentication",
                    "detail": f"anon status {lo_status}; authenticated identity got {hi_status}.",
                    "impact": "Unauthenticated access to a protected resource.",
                    "exploit": f"curl -s '{probe.url}'",
                    "confidence": "MEDIUM",
                    "cwe": "CWE-306",
                    "phase": "authz",
                })
        return out
