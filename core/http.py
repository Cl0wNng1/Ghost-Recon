"""
GHOST RECON v2.0 — core/http.py
One shared, rate-limited, scope-aware async HTTP client for every module.

Why this exists
---------------
v14 let each step open its own aiohttp session and fire at will, so three
concurrent tools could each hammer the target independently and blow past the
stealth "rate". v15 funnels in-process HTTP through a single client that:

  * enforces a GLOBAL token-bucket rate limit (requests/sec from stealth profile),
  * applies jitter + periodic cooldowns from the stealth profile,
  * bounds concurrency with a shared semaphore,
  * refuses out-of-scope requests via ScopeGuard,
  * carries the AuthSession (cookies / headers) so authenticated scans "just work",
  * retries idempotent requests with exponential backoff.

External CLI tools (nuclei, ffuf, ...) can't share this session, but they get
the same rate ceiling via HttpClient.subprocess_rate_args() / the operator's
--rate wiring, and every target handed to them is scope-filtered first.

Dependency: aiohttp (already a project dep). Import is lazy so core/scope.py and
step00 stay importable without it.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .scope import ScopeGuard, ScopeError

__all__ = ["HttpClient", "TokenBucket", "AuthSession", "build_http_client", "auth_engine_headers"]


# ═══════════════════════════════════════════════════════════════════════════
# Token bucket (global rate limiter)
# ═══════════════════════════════════════════════════════════════════════════
class TokenBucket:
    """Async token bucket. rate = sustained requests/sec, burst = bucket size."""

    def __init__(self, rate: float, burst: Optional[float] = None) -> None:
        self.rate = max(0.01, float(rate))
        self.capacity = float(burst if burst is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                await asyncio.sleep(deficit / self.rate)


# ═══════════════════════════════════════════════════════════════════════════
# Auth session (cookies + headers shared across all steps)
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class AuthSession:
    """Holds credentials/state that authenticated scanning needs.

    Populated by modules/step_auth (login replay) and read by every request.
    """
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    bearer: str = ""
    csrf_token: str = ""
    csrf_header: str = "X-CSRF-Token"
    logged_in: bool = False

    def as_headers(self) -> Dict[str, str]:
        h = dict(self.headers)
        if self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}"
        if self.csrf_token:
            h[self.csrf_header] = self.csrf_token
        return h

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cookies": self.cookies, "headers": self.headers, "bearer": self.bearer,
            "csrf_token": self.csrf_token, "csrf_header": self.csrf_header,
            "logged_in": self.logged_in,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthSession":
        return cls(**{k: d.get(k, v) for k, v in cls().__dict__.items()})


def auth_engine_headers(auth: AuthSession) -> Dict[str, str]:
    """Flatten an AuthSession into plain headers (incl. Cookie) for the
    ghost_core engine, which has no cookie jar of its own."""
    h = auth.as_headers()
    if auth.cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in auth.cookies.items())
    return h


# ═══════════════════════════════════════════════════════════════════════════
# HTTP client
# ═══════════════════════════════════════════════════════════════════════════
class HttpClient:
    """Shared async HTTP client. Create once per scan; close on teardown."""

    _IDEMPOTENT = {"GET", "HEAD", "OPTIONS"}

    def __init__(
        self,
        scope: ScopeGuard,
        *,
        rate: float = 10.0,
        concurrency: int = 8,
        jitter: float = 0.3,
        cooldown: float = 8.0,
        cooldown_every: int = 100,
        auth: Optional[AuthSession] = None,
        user_agent: str = "GhostRecon/2.0",
        timeout: float = 30.0,
        max_retries: int = 2,
        verify_ssl: bool = False,
        proxy: str = "",
    ) -> None:
        self.scope = scope
        self.bucket = TokenBucket(rate, burst=max(rate, concurrency))
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self.jitter = max(0.0, jitter)
        self.cooldown = cooldown
        self.cooldown_every = max(1, cooldown_every)
        self.auth = auth or AuthSession()
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.proxy = proxy or None
        self._concurrency = max(1, concurrency)
        self._session = None            # lazily created aiohttp.ClientSession
        self._loop = None               # loop the session/locks belong to
        self._count = 0
        self.rejected_count = 0
        self.request_count = 0

    async def _ensure_session(self):
        loop = asyncio.get_running_loop()
        if self._loop is not loop:
            # aiohttp sessions, semaphores and locks are bound to the loop they
            # were first used on. Rebuild them if we are on a different loop.
            self._session = None
            self.sem = asyncio.Semaphore(self._concurrency)
            self.bucket = TokenBucket(self.bucket.rate, burst=self.bucket.capacity)
            self._loop = loop
        if self._session is None:
            import aiohttp
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=0)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                trust_env=True,
            )
        return self._session

    async def _throttle(self) -> None:
        await self.bucket.acquire()
        if self.jitter:
            await asyncio.sleep(random.uniform(0, self.jitter))
        self._count += 1
        if self._count % self.cooldown_every == 0 and self.cooldown:
            await asyncio.sleep(self.cooldown)

    def _merge_headers(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        h = {"User-Agent": self.user_agent}
        h.update(self.auth.as_headers())
        if extra:
            h.update(extra)
        return h

    async def request(self, method: str, url: str, **kwargs) -> Optional["aiohttp.ClientResponse"]:
        """Scope-checked, rate-limited, retrying request.

        Redirects are followed by hand (max 5 hops) and every hop is scope
        checked, so a 302 to a third-party host is returned, never followed.

        Returns an aiohttp response whose body has already been read into
        ``resp._ghost_body`` (bytes) and ``resp._ghost_text`` (str), so callers
        can inspect it after the context manager closes. Returns None if the
        target is out of scope (non-enforcing mode) or all retries failed.
        """
        method = method.upper()
        follow = kwargs.pop("allow_redirects", True)
        for _hop in range(6):
            resp = await self._request_once(method, url, **kwargs)
            if resp is None or not follow or not (300 <= resp.status < 400):
                return resp
            loc = resp.headers.get("Location", "")
            if not loc:
                return resp
            from urllib.parse import urljoin
            nxt = urljoin(url, loc)
            if not self.scope.is_in_scope(nxt):
                self.rejected_count += 1
                return resp  # hand back the 3xx; never leave scope
            if resp.status not in (307, 308):
                method = "GET"
                kwargs.pop("data", None); kwargs.pop("json", None)
            url = nxt
        return resp

    async def _request_once(self, method: str, url: str, **kwargs):
        if not self.scope.is_in_scope(url):
            self.rejected_count += 1
            if self.scope.enforce:
                raise ScopeError(f"Refusing out-of-scope request: {url}")
            return None

        session = await self._ensure_session()
        if self.proxy and "proxy" not in kwargs:
            kwargs["proxy"] = self.proxy
        headers = self._merge_headers(kwargs.pop("headers", None))
        cookies = {**self.auth.cookies, **(kwargs.pop("cookies", None) or {})}
        attempts = self.max_retries + 1 if method in self._IDEMPOTENT else 1

        for attempt in range(attempts):
            async with self.sem:
                await self._throttle()
                try:
                    self.request_count += 1
                    async with session.request(
                        method, url, headers=headers, cookies=cookies,
                        allow_redirects=False, **kwargs
                    ) as resp:
                        body = await resp.read()
                        resp._ghost_body = body
                        try:
                            resp._ghost_text = body.decode(resp.charset or "utf-8", "replace")
                        except Exception:
                            resp._ghost_text = ""
                        return resp
                except Exception:  # noqa: BLE001 — network errors are expected
                    if attempt < attempts - 1:
                        await asyncio.sleep(min(8.0, 0.5 * (2 ** attempt)) + random.uniform(0, 0.4))
                    continue
        return None

    async def get(self, url: str, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw):
        return await self.request("POST", url, **kw)

    async def head(self, url: str, **kw):
        return await self.request("HEAD", url, **kw)

    def subprocess_rate_args(self, tool: str) -> list:
        """Best-effort rate flags for external CLI tools so they respect the
        same ceiling as in-process requests."""
        r = int(max(1, self.bucket.rate))
        c = self._session is not None  # noqa: F841
        mapping = {
            "ffuf":     ["-rate", str(r)],
            "feroxbuster": ["--rate-limit", str(r)],
            "nuclei":   ["-rate-limit", str(r)],
            "httpx":    ["-rate-limit", str(r)],
            "dalfox":   ["--delay", str(int(1000 / r))],
        }
        return mapping.get(tool, [])

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> "HttpClient":
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()


def build_http_client(config, scope: ScopeGuard, auth: Optional[AuthSession] = None) -> HttpClient:
    """Construct an HttpClient from the stealth profile on Config.

    v2.0 fix: ``Config.stealth_profile`` is a *property*. v15 called it like a
    method, the resulting TypeError was swallowed, and jitter/cooldown from the
    stealth profile were silently never applied.
    """
    profile = getattr(config, "stealth_profile", None)
    if callable(profile):
        try:
            profile = profile()
        except Exception:
            profile = None
    if not isinstance(profile, dict):
        profile = {}
    # Explicit --rate / --concurrency (already folded into config) win.
    return HttpClient(
        scope,
        rate=float(getattr(config, "rate", 0) or profile.get("rate", 10.0)),
        concurrency=int(getattr(config, "concurrency", 0) or profile.get("concurrency", 8)),
        jitter=float(profile.get("jitter", 0.3)),
        cooldown=float(profile.get("cooldown", 8)),
        cooldown_every=int(profile.get("cooldown_every", 100)),
        auth=auth,
        proxy=getattr(config, "proxy", "") or "",
        user_agent=getattr(config, "user_agent", "") or "GhostRecon/2.0",
    )
