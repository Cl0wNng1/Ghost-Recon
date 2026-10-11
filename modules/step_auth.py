"""
GHOST RECON v2.0 — modules/step_auth.py
Authenticated scanning: establish and maintain a logged-in session that every
later step reuses via ctx.http / ctx.auth.

Supported auth strategies (config.auth_mode):
  * "none"    — anonymous (default; no-op)
  * "cookie"  — operator supplies a raw Cookie header / cookie pairs
  * "bearer"  — operator supplies a bearer token
  * "form"    — replay a form login (username/password) and capture cookies+CSRF
  * "raw"     — operator supplies arbitrary headers (e.g. from Burp)

The module verifies the session by requesting a protected URL and checking for
logged-in markers, and writes a session snapshot to the workspace so --resume
keeps you authenticated.

Contract matches every other step: `async def execute(ctx, engine, config)`.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

STEP_NAME = "Authentication & Session Setup"


def _parse_cookie_string(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _extract_csrf(html: str) -> str:
    """Best-effort CSRF token scrape from a login page."""
    if not html:
        return ""
    patterns = [
        r'name=["\']?csrf[_-]?token["\']?[^>]*value=["\']([^"\']+)',
        r'name=["\']?_token["\']?[^>]*value=["\']([^"\']+)',
        r'name=["\']?authenticity_token["\']?[^>]*value=["\']([^"\']+)',
        r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)',
    ]
    for p in patterns:
        m = re.search(p, html, re.I)
        if m:
            return m.group(1)
    return ""


async def _verify_session(http, verify_url: str, success_markers: List[str],
                          failure_markers: List[str]) -> bool:
    resp = await http.get(verify_url)
    if resp is None:
        return False
    body = (getattr(resp, "_ghost_text", "") or "").lower()
    status = resp.status
    if any(m.lower() in body for m in failure_markers):
        return False
    if success_markers and not any(m.lower() in body for m in success_markers):
        # markers configured but none present → treat as not logged in
        return False
    # default heuristic: a protected page that doesn't bounce to /login
    return status < 400 and "login" not in str(resp.url).lower()


async def _form_login(http, config) -> bool:
    login_url = getattr(config, "auth_login_url", "")
    if not login_url:
        return False

    # GET the login page to capture CSRF + set initial cookies
    page = await http.get(login_url)
    csrf = _extract_csrf(getattr(page, "_ghost_text", "")) if page else ""
    if csrf:
        http.auth.csrf_token = csrf

    user_field = getattr(config, "auth_user_field", "username")
    pass_field = getattr(config, "auth_pass_field", "password")
    data = {
        user_field: getattr(config, "auth_username", ""),
        pass_field: getattr(config, "auth_password", ""),
    }
    extra = getattr(config, "auth_extra_fields", {}) or {}
    data.update(extra)
    if csrf:
        csrf_field = getattr(config, "auth_csrf_field", "csrf_token")
        data[csrf_field] = csrf

    post_url = getattr(config, "auth_post_url", "") or login_url
    resp = await http.post(post_url, data=data, allow_redirects=True)
    if resp is None:
        return False

    # Capture any Set-Cookie into the shared AuthSession
    try:
        for c in resp.cookies.values():
            http.auth.cookies[c.key] = c.value
    except Exception:
        pass
    return True


async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    mode = (getattr(config, "auth_mode", "none") or "none").lower()
    http = getattr(ctx, "http", None)

    if mode == "none" or http is None:
        if hasattr(ctx, "log"):
            ctx.log(f"[{STEP_NAME}] anonymous scan (auth_mode=none)")
        return ctx

    auth = http.auth

    if mode == "cookie":
        raw = getattr(config, "auth_cookie", "")
        auth.cookies.update(_parse_cookie_string(raw))
    elif mode == "bearer":
        auth.bearer = getattr(config, "auth_bearer", "")
    elif mode == "raw":
        auth.headers.update(getattr(config, "auth_headers", {}) or {})
    elif mode == "form":
        await _form_login(http, config)

    # Verify
    verify_url = getattr(config, "auth_verify_url", "") or ctx.url
    success = list(getattr(config, "auth_success_markers", []) or [])
    failure = list(getattr(config, "auth_failure_markers", ["log in", "sign in", "invalid"]) or [])
    ok = await _verify_session(http, verify_url, success, failure)
    auth.logged_in = ok

    # Persist session snapshot for --resume. Owner-only permissions: this
    # file holds live session cookies / tokens.
    try:
        ws = getattr(config, "workspace", "") or "."
        os.makedirs(ws, exist_ok=True)
        path = os.path.join(ws, "auth_session.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(auth.to_dict(), fh, indent=2)
        os.chmod(path, 0o600)
    except Exception:
        pass

    # v2.0: hand the session to the shared engine too. In v15 only ctx.http
    # carried it, so most steps (which use the engine) scanned anonymously.
    if ok and engine is not None and hasattr(engine, "auth_headers"):
        from core.http import auth_engine_headers
        engine.auth_headers = auth_engine_headers(auth)

    if not ok and hasattr(ctx, "log"):
        ctx.log(f"[{STEP_NAME}] WARNING: session could not be verified at "
                f"{verify_url} — downstream steps will run unauthenticated")
    if hasattr(ctx, "log"):
        ctx.log(f"[{STEP_NAME}] auth_mode={mode} logged_in={ok}")
    return ctx
