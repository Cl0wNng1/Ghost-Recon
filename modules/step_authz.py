"""
GHOST RECON v2.0 — modules/step_authz.py
Access-control / IDOR / BOLA / BFLA testing via multi-role response diffing.

Operator supplies role sessions in config.authz_roles, e.g.:

    config.authz_roles = {
        "anon":  {},                                  # no auth
        "userA": {"cookie": "session=aaa"},
        "userB": {"cookie": "session=bbb"},
        "admin": {"bearer": "eyJ..."},
    }

For each role we build a lightweight HttpClient sharing the scan's ScopeGuard and
rate limiter, then request every candidate endpoint under every role and diff.

Candidate endpoints are drawn from discovered URLs that look like they carry
object references (numeric / uuid / id params or REST-style /resource/{id} paths).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

STEP_NAME = "Access Control & IDOR Testing"

_ID_HINTS = re.compile(
    r"(?:[?&](?:id|uid|user|account|order|invoice|doc|file|obj|pid|gid|num)="
    r"|/\d{1,12}(?:/|$)"
    r"|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.I,
)


def _candidate_endpoints(ctx: Any, limit: int = 300) -> List[str]:
    urls: List[str] = []
    try:
        urls = list(ctx.urls) if ctx.urls else []
    except Exception:
        urls = []
    scored = [u for u in urls if _ID_HINTS.search(u)]
    # Always include the base + any known 200 paths as sanity anchors.
    try:
        scored.extend(list(ctx.paths_200)[:50])  # v2.0: property, not method
    except Exception:
        pass
    # de-dup, cap
    seen, out = set(), []
    for u in scored:
        if u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= limit:
            break
    return out


def _client_for_role(base_http, spec: Dict[str, str]):
    """Clone the scan HttpClient's config but with this role's auth."""
    from core.http import HttpClient, AuthSession

    auth = AuthSession()
    if spec.get("cookie"):
        for part in spec["cookie"].split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                auth.cookies[k.strip()] = v.strip()
    if spec.get("bearer"):
        auth.bearer = spec["bearer"]
    if spec.get("headers"):
        auth.headers.update(spec["headers"])

    return HttpClient(
        base_http.scope,
        rate=base_http.bucket.rate,
        concurrency=1,                 # gentle: per-role serial
        jitter=base_http.jitter,
        cooldown=base_http.cooldown,
        cooldown_every=base_http.cooldown_every,
        auth=auth,
        proxy=getattr(base_http, "proxy", "") or "",
        user_agent=base_http.user_agent,
    )


async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    roles: Dict[str, Dict[str, str]] = getattr(config, "authz_roles", {}) or {}
    if len(roles) < 2:
        if hasattr(ctx, "log"):
            ctx.log(f"[{STEP_NAME}] skipped — need >=2 roles in config.authz_roles")
        return ctx

    base_http = getattr(ctx, "http", None)
    if base_http is None:
        if hasattr(ctx, "log"):
            ctx.log(f"[{STEP_NAME}] skipped — no shared HttpClient on ctx")
        return ctx

    from core.authz_matrix import AuthzMatrix

    matrix = AuthzMatrix(similarity_threshold=getattr(config, "authz_similarity", 0.90))
    clients = []
    for name, spec in roles.items():
        c = _client_for_role(base_http, spec)
        clients.append(c)
        matrix.add_identity(name, c, rank=spec.get("rank") if isinstance(spec, dict) else None)

    endpoints = _candidate_endpoints(ctx, limit=getattr(config, "authz_max_endpoints", 300))
    if hasattr(ctx, "log"):
        ctx.log(f"[{STEP_NAME}] {len(roles)} roles x {len(endpoints)} endpoints")

    try:
        findings = await matrix.probe(endpoints)
        for f in findings:
            ctx.add_finding(**f)
        if hasattr(ctx, "log"):
            ctx.log(f"[{STEP_NAME}] {len(findings)} access-control findings")
    finally:
        for c in clients:
            try:
                await c.close()
            except Exception:
                pass
    return ctx
