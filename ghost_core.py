"""
GHOST RECON v2.0 — Unified Core Engine (ghost_core.py)
P1: Async HTTP Engine + Adaptive Rate Control
P0: 3-Layer Response Validation Pipeline
P2: Intelligent Triage & Data Pipeline

Replaces: curl() subprocess, Stealth.throttle(), naive 200+30B validation, first-N selection.
Compat: curl_sync()/curl_head_sync() provide identical return signatures. Zero hardcoded domains.
"""

from __future__ import annotations
import asyncio, hashlib, json, random, re, time, logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

try:
    import httpx
except ImportError:
    raise ImportError("ghost_core requires httpx. Install: pip install 'httpx[http2]' --break-system-packages")

CORE_VERSION = "2.0.0"
log = logging.getLogger("ghost.core")

# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HttpResponse:
    """Unified HTTP response."""
    code: int = 0; body: str = ""; size: int = 0; content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0; url: str = ""; error: str = ""
    was_throttled: bool = False
    def as_tuple(self) -> Tuple[int, str, int, str]:
        return (self.code, self.body, self.size, self.content_type)

@dataclass
class HostBaseline:
    """Layer 1 fingerprint for a host."""
    host: str; is_catchall: bool = False
    status_codes: List[int] = field(default_factory=list)
    sizes: List[int] = field(default_factory=list)
    body_hash: str = ""; content_type: str = ""
    probes_ok: int = 0; error: str = ""

@dataclass
class Verdict:
    """3-layer validation result."""
    is_real: bool; severity: str; confidence: str; reason: str

@dataclass
class TriageResult:
    """P2 triage output."""
    live_urls: List[str] = field(default_factory=list)
    dead_urls: List[str] = field(default_factory=list)
    deduped_count: int = 0; original_count: int = 0
    js_prioritized: List[str] = field(default_factory=list)
    js_skipped: int = 0

@dataclass
class RateState:
    """Per-scope rate limiter state."""
    scope: str; base_rate: float; current_rate: float
    consecutive_ok: int = 0; consecutive_throttle: int = 0
    backoff_until: float = 0.0; total_requests: int = 0
    total_throttled: int = 0; total_errors: int = 0

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

BROWSER_HEADERS: Dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1", "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
}

UA_POOL: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
]

# v10.0 expanded CDN Server header filter (fixes GSE/UploadServer FP class)
CDN_SERVER_NAMES: List[str] = [
    "cloudflare", "akamaighost", "amazons3", "cloudfront", "varnish",
    "nginx", "apache", "gws", "bigip", "yunjiasu", "cdn77",
    "gse", "uploadserver", "gfe", "sffe", "googlehttpserver",
    "google frontend", "cafe", "openresty", "tengine", "envoy",
    "istio-envoy", "awselb", "elb", "gunicorn", "uvicorn",
    "cowboy", "flywheel", "pepyaka",
]

SOFT_404_MARKERS: List[str] = [
    "404", "not found", "page not found", "access denied", "error 404",
    "does not exist", "no such file", "cannot be found", "file not found",
    "resource not found", "invalid url", "page you requested",
    "nothing here", "this page doesn", "oops", "we couldn't find",
    "page is missing", "no longer available", "has been removed",
]

MARKETING_PARAMS: FrozenSet[str] = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "gad_source", "gad", "gbraid", "wbraid",
    "adgroup", "clickid", "matchtype", "placement", "network", "device",
    "extension", "targetid", "campaign", "campaignid", "adgroupid",
    "creative", "keyword", "mc_cid", "mc_eid", "msclkid", "twclid",
    "li_fat_id", "_ga", "_gl", "sxsrf", "ref", "ref_", "referer",
})

CDN_JS_HOSTS: FrozenSet[str] = frozenset({
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "fonts.googleapis.com", "use.fontawesome.com",
    "cdn.shopify.com", "cdn.datatables.net", "cdnjs.com", "rawgit.com",
    "cdn.bootcss.com", "polyfill.io", "cdn.staticfile.org",
    "cdn.cloudflare.com", "cdn.tailwindcss.com", "esm.sh",
    "ga.jspm.io", "cdn.skypack.dev", "maps.googleapis.com",
    "www.google-analytics.com", "connect.facebook.net",
    "platform.twitter.com", "www.googletagmanager.com",
    "snap.licdn.com", "bat.bing.com", "js.stripe.com",
    "cdn.segment.com", "cdn.amplitude.com", "widget.intercom.io",
    "js.intercomcdn.com", "cdn.heapanalytics.com", "js.sentry-cdn.com",
    "cdn.optimizely.com", "cdn.cookielaw.org",
})

_NON_HTML_EXT: FrozenSet[str] = frozenset({
    ".json", ".yml", ".yaml", ".xml", ".env", ".php", ".py", ".rb",
    ".sql", ".key", ".pem", ".crt", ".conf", ".cfg", ".ini", ".toml",
    ".properties", ".lock", ".mod", ".txt", ".log", ".bak", ".db",
})

_JS_PRIO_RE = re.compile(r'(?:app|main|bundle|index|chunk|config|env|settings|constants|api|auth|routes)[\.-]', re.I)
_JS_SKIP_RE = re.compile(r'(?:polyfill|jquery|lodash|moment|react-dom|angular[\.-]|vue[\.-]|analytics|tracking|gtm|gtag|pixel|hotjar|font-?awesome|bootstrap)', re.I)

# ═══════════════════════════════════════════════════════════════════════════════
# P1: ASYNC HTTP ENGINE + ADAPTIVE RATE CONTROL
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveRateLimiter:
    """Signal-driven rate limiter with independent per-scope buckets.
    
    v9.0 problems fixed:
    - Static cooldown every 25 req regardless of server state → signal-driven
    - Single counter for target+Shodan+GitHub → independent scope buckets
    - 75x40s=50min blind idle → zero blind idle, backs off only on actual 429/503
    - Never parsed Retry-After/cf-mitigated → full header signal parsing
    """
    def __init__(self, default_rate: float = 10.0):
        self._scopes: Dict[str, RateState] = {}
        self._default_rate = default_rate

    def configure_scope(self, scope: str, rate: float) -> None:
        self._scopes[scope] = RateState(scope=scope, base_rate=rate, current_rate=rate)

    def _get(self, scope: str) -> RateState:
        if scope not in self._scopes:
            self._scopes[scope] = RateState(scope=scope, base_rate=self._default_rate, current_rate=self._default_rate)
        return self._scopes[scope]

    async def acquire(self, scope: str = "target") -> None:
        """Wait until safe to send. Replaces Stealth.throttle()."""
        rs = self._get(scope)
        now = time.monotonic()
        if now < rs.backoff_until:
            await asyncio.sleep(rs.backoff_until - now)
        if rs.current_rate > 0:
            delay = 1.0 / rs.current_rate
            await asyncio.sleep(delay + random.uniform(0, delay * 0.3))
        rs.total_requests += 1

    def record(self, scope: str, status: int, headers: Dict[str, str]) -> None:
        """Adapt rate based on server response signals."""
        rs = self._get(scope)
        # 429/503 → exponential backoff
        if status in (429, 503):
            rs.consecutive_throttle += 1; rs.consecutive_ok = 0; rs.total_throttled += 1
            retry = headers.get("retry-after", "")
            if retry:
                try:
                    rs.backoff_until = time.monotonic() + float(retry); return
                except ValueError: pass
            backoff = min(2 ** rs.consecutive_throttle, 120)
            rs.backoff_until = time.monotonic() + backoff + random.uniform(0, backoff * 0.3)
            rs.current_rate = max(0.1, rs.current_rate * 0.5)
            log.warning(f"[rate:{scope}] {status} #{rs.consecutive_throttle} → backoff {backoff:.0f}s, rate→{rs.current_rate:.2f}/s")
            return
        # Cloudflare challenge
        if "challenge" in headers.get("cf-mitigated", "").lower():
            rs.consecutive_throttle += 1; rs.consecutive_ok = 0
            backoff = min(2 ** min(rs.consecutive_throttle, 4), 30)
            rs.backoff_until = time.monotonic() + backoff
            rs.current_rate = max(0.2, rs.current_rate * 0.7)
            return
        # X-RateLimit-Remaining preemptive
        rem = headers.get("x-ratelimit-remaining", "")
        if rem:
            try:
                if int(rem) <= 2: rs.backoff_until = time.monotonic() + 10; return
            except ValueError: pass
        # Success → recovery
        if 200 <= status < 400:
            rs.consecutive_ok += 1; rs.consecutive_throttle = 0
            if rs.consecutive_ok % 20 == 0 and rs.current_rate < rs.base_rate:
                rs.current_rate = min(rs.base_rate, rs.current_rate * 1.25)
        elif status == 0:
            rs.total_errors += 1

    def halve_for_cdn(self, scope: str = "target") -> None:
        rs = self._get(scope)
        rs.base_rate = max(0.5, rs.base_rate / 2)
        rs.current_rate = max(0.5, rs.current_rate / 2)

    def stats(self, scope: str = "target") -> Dict[str, Any]:
        rs = self._get(scope)
        return {"scope": scope, "base": rs.base_rate, "current": round(rs.current_rate, 2),
                "reqs": rs.total_requests, "throttled": rs.total_throttled, "errors": rs.total_errors}


class AsyncHttpEngine:
    """Async HTTP client with connection pooling, HTTP/2, and adaptive rate.
    
    v9.0 problems fixed:
    - subprocess.run(["curl",...]) per request → httpx.AsyncClient connection pool
    - No connection reuse/HTTP2 → persistent connections with multiplexing
    - ~0.3 req/s effective throughput → configurable, signal-adaptive rate
    """
    def __init__(self, rate: float = 10.0, max_concurrency: int = 10,
                 proxy: str = "", verify_ssl: bool = False, http2: bool = True):
        self.rate_limiter = AdaptiveRateLimiter(default_rate=rate)
        self._sem = asyncio.Semaphore(max_concurrency)
        self._proxy = proxy or None; self._verify = verify_ssl
        self._http2 = http2; self._client: Optional[httpx.AsyncClient] = None
        self._req_count = 0
        self._max_concurrency = max_concurrency
        self._client_loop: Optional[asyncio.AbstractEventLoop] = None
        # v2.0: optional ScopeGuard. Requests on the "target" rate bucket (the
        # default) must be in scope — including every redirect hop. Third-party
        # intel lookups (crtsh, shodan, github, ...) use their own bucket labels.
        self.scope_guard: Any = None
        self.blocked_count = 0
        # v2.0: authenticated-session headers (set by the auth step) applied to
        # every in-scope "target" request. Caller-supplied headers still win.
        self.auth_headers: Dict[str, str] = {}

    def _target_scoped(self, scope: str) -> bool:
        return self.scope_guard is not None and scope == "target"

    async def _client_init(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is not None and self._client_loop is not loop:
            # Created on a different (likely closed) loop: its pooled
            # connections are unusable here. Drop it and start fresh.
            self._client = None
            self._sem = asyncio.Semaphore(self._max_concurrency)
        if self._client is None or self._client.is_closed:
            self._client_loop = loop
            transport = httpx.AsyncHTTPTransport(http2=self._http2, retries=0, verify=self._verify)
            kw: Dict[str, Any] = {"transport": transport, "follow_redirects": True,
                                   "max_redirects": 5, "timeout": httpx.Timeout(12.0, connect=8.0),
                                   "verify": self._verify}
            if self._proxy: kw["proxy"] = self._proxy
            self._client = httpx.AsyncClient(**kw)
        return self._client

    async def request(self, url: str, method: str = "GET",
                      extra_headers: Optional[Dict[str, str]] = None,
                      timeout: float = 12.0, follow_redirects: bool = True,
                      scope: str = "target") -> HttpResponse:
        hdrs = dict(BROWSER_HEADERS)
        hdrs["User-Agent"] = random.choice(UA_POOL)
        hdrs["X-Forwarded-For"] = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if self.auth_headers and scope == "target":
            hdrs.update(self.auth_headers)
        if extra_headers: hdrs.update(extra_headers)
        scoped = self._target_scoped(scope)
        if scoped and not self.scope_guard.is_in_scope(url):
            self.blocked_count += 1
            return HttpResponse(code=0, error="out-of-scope", url=url)
        await self.rate_limiter.acquire(scope)
        client = await self._client_init()
        async with self._sem:
            try:
                t0 = time.monotonic()
                to = httpx.Timeout(timeout, connect=min(timeout, 8.0))
                if scoped and follow_redirects:
                    # Follow redirects by hand so no hop can leave scope.
                    resp = await client.request(method=method, url=url, headers=hdrs,
                                                timeout=to, follow_redirects=False)
                    for _ in range(5):
                        nxt = resp.next_request
                        if nxt is None:
                            break
                        if not self.scope_guard.is_in_scope(str(nxt.url)):
                            self.blocked_count += 1
                            break  # keep the 3xx response; do not follow off-scope
                        resp = await client.send(nxt, follow_redirects=False)
                else:
                    resp = await client.request(method=method, url=url, headers=hdrs,
                        timeout=to, follow_redirects=follow_redirects)
                elapsed = (time.monotonic() - t0) * 1000
                rh = dict(resp.headers)
                self.rate_limiter.record(scope, resp.status_code, rh)
                self._req_count += 1
                return HttpResponse(code=resp.status_code, body=resp.text, size=len(resp.content),
                    content_type=resp.headers.get("content-type", ""), headers=rh,
                    elapsed_ms=elapsed, url=str(resp.url),
                    was_throttled=resp.status_code in (429, 503))
            except httpx.TimeoutException:
                self.rate_limiter.record(scope, 0, {}); return HttpResponse(code=0, error="timeout", url=url)
            except httpx.ConnectError as e:
                self.rate_limiter.record(scope, 0, {}); return HttpResponse(code=0, error=f"connect:{e}", url=url)
            except Exception as e:
                self.rate_limiter.record(scope, 0, {}); return HttpResponse(code=0, error=str(e), url=url)

    async def get(self, url: str, **kw) -> HttpResponse:
        return await self.request(url, method="GET", **kw)
    async def head(self, url: str, **kw) -> HttpResponse:
        kw.setdefault("timeout", 8.0); return await self.request(url, method="HEAD", **kw)
    async def batch_get(self, urls: List[str], **kw) -> List[HttpResponse]:
        return await asyncio.gather(*[self.get(u, **kw) for u in urls])
    async def batch_head(self, urls: List[str], scope: str = "target", timeout: float = 6.0) -> Dict[str, int]:
        results: Dict[str, int] = {}
        async def _c(u):
            r = await self.head(u, scope=scope, timeout=timeout); results[u] = r.code
        await asyncio.gather(*[_c(u) for u in urls]); return results
    async def close(self):
        if self._client and not self._client.is_closed:
            try:
                await self._client.aclose()
            except RuntimeError:
                pass  # client bound to a loop that is already gone
        self._client = None
    @property
    def request_count(self) -> int: return self._req_count

# ═══════════════════════════════════════════════════════════════════════════════
# SYNC BRIDGE — Legacy Compatibility Layer
# ═══════════════════════════════════════════════════════════════════════════════

_engine: Optional[AsyncHttpEngine] = None
_loop: Optional[asyncio.AbstractEventLoop] = None

def init_engine(rate: float = 10.0, max_concurrency: int = 10,
                proxy: str = "", verify_ssl: bool = False, http2: bool = True) -> AsyncHttpEngine:
    """Initialize global async engine. Call ONCE at scan start."""
    global _engine, _loop
    _engine = AsyncHttpEngine(rate=rate, max_concurrency=max_concurrency,
                              proxy=proxy, verify_ssl=verify_ssl, http2=http2)
    try: _loop = asyncio.get_running_loop()
    except RuntimeError: _loop = asyncio.new_event_loop(); asyncio.set_event_loop(_loop)
    return _engine

def get_engine() -> AsyncHttpEngine:
    if _engine is None: raise RuntimeError("Call init_engine() first.")
    return _engine

def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    """v2.0: make the sync bridge share the orchestrator's persistent loop."""
    global _loop
    _loop = loop

def _run_async(coro):
    try:
        asyncio.get_running_loop()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        global _loop
        if _loop is None or _loop.is_closed():
            _loop = asyncio.new_event_loop(); asyncio.set_event_loop(_loop)
        return _loop.run_until_complete(coro)

def curl_sync(url: str, extra_headers: Optional[Dict[str, str]] = None,
              method: str = "GET", timeout: float = 12.0, follow: bool = True,
              raw_headers: bool = False, scope: str = "target") -> Tuple[int, str, int, str]:
    """DROP-IN replacement for v9.0 curl(). Returns (code, body, size, ct)."""
    if _engine is None: raise RuntimeError("Call init_engine() first.")
    resp = _run_async(_engine.request(url=url, method=method, extra_headers=extra_headers,
                                       timeout=timeout, follow_redirects=follow, scope=scope))
    if raw_headers:
        hdr_text = "\r\n".join([f"HTTP/2 {resp.code}"] + [f"{k}: {v}" for k, v in resp.headers.items()]) + "\r\n\r\n" + resp.body
        return (resp.code, hdr_text, resp.size, resp.content_type)
    return resp.as_tuple()

def curl_head_sync(url: str, extra_headers: Optional[Dict[str, str]] = None,
                   timeout: float = 10.0, scope: str = "target") -> str:
    """DROP-IN replacement for v9.0 curl_head(). Returns raw header text."""
    if _engine is None: raise RuntimeError("Call init_engine() first.")
    resp = _run_async(_engine.request(url=url, method="HEAD", extra_headers=extra_headers,
                                       timeout=timeout, follow_redirects=True, scope=scope))
    return "\r\n".join([f"HTTP/2 {resp.code}"] + [f"{k}: {v}" for k, v in resp.headers.items()])

def shutdown_engine():
    if _engine: _run_async(_engine.close())

# ═══════════════════════════════════════════════════════════════════════════════
# P0: 3-LAYER RESPONSE VALIDATION PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _hash_body(body: str, window: int = 2048) -> str:
    if not body: return ""
    return hashlib.md5(body[:window].encode("utf-8", errors="replace")).hexdigest()

def _make_baseline_paths() -> List[str]:
    r = lambda: str(random.randint(100000, 999999))
    exts = ["bhtml", "aspxx", "jspf", "phps", "cpy"]
    return [f"gh0st_fp_{r()}.{random.choice(exts)}", f"api/v99/_ghost_probe/{r()}", f"ghost/validate/check/{r()}.tmp"]

class _ClusterTracker:
    __slots__ = ("_tol", "_thresh", "_sizes", "_hashes", "_n200")
    def __init__(self, tolerance: int = 50, threshold: float = 0.60):
        self._tol = tolerance; self._thresh = threshold
        self._sizes: List[int] = []; self._hashes: List[str] = []; self._n200 = 0
    def record(self, code: int, size: int, body: str = ""):
        if code != 200: return
        self._n200 += 1; self._sizes.append(size)
        if body: self._hashes.append(_hash_body(body))
    def is_clustered(self) -> Tuple[bool, str]:
        if self._n200 < 5: return False, f"insufficient ({self._n200})"
        buckets: Dict[int, int] = {}
        for sz in self._sizes:
            k = (sz // self._tol) * self._tol; buckets[k] = buckets.get(k, 0) + 1
        if buckets:
            peak = max(buckets.values()); ratio = peak / self._n200
            if ratio >= self._thresh:
                return True, f"{peak}/{self._n200} ({ratio:.0%}) cluster at ~{max(buckets, key=buckets.get)}B"
        if self._hashes:
            hc: Dict[str, int] = {}
            for h in self._hashes: hc[h] = hc.get(h, 0) + 1
            hp = max(hc.values())
            if hp / self._n200 >= self._thresh: return True, f"{hp}/{self._n200} identical hash"
        return False, "diverse"

# ─── Layer 3: Content Validators ──────────────────────────────────────────────

def _v_env(b):
    h = re.findall(r'^[A-Z][A-Z0-9_]{2,}=.+', b[:5000], re.M)
    if len(h) >= 2: return True, f"{len(h)} env vars"
    h2 = re.findall(r'^export\s+[A-Z][A-Z0-9_]+=', b[:5000], re.M)
    return (True, f"{len(h2)} exports") if h2 else (False, "no KEY=VALUE")

def _v_git_head(b):
    s = b.strip()
    if s.startswith("ref: refs/"): return True, f"ref: {s[:60]}"
    if re.match(r'^[0-9a-f]{40}$', s): return True, "detached HEAD"
    return False, f"invalid: {s[:80]}"

def _v_git_config(b):
    return (True, "[core] found") if "[core]" in b and ("repositoryformatversion" in b.lower() or "bare" in b.lower()) else (False, "no [core]")

def _v_json_keys(keys, label):
    def _f(b):
        try:
            d = json.loads(b)
            if isinstance(d, dict):
                f = [k for k in keys if k in d]
                if f: return True, f"{label} ({f[:3]})"
            return False, f"no {label} keys"
        except: return False, "not JSON"
    return _f

def _v_graphql(b):
    try:
        d = json.loads(b)
        if isinstance(d, dict) and any(k in d for k in ("data", "errors", "__schema")): return True, "GraphQL JSON"
    except: pass
    low = b[:3000].lower()
    if "graphiql" in low or "graphql-playground" in low: return True, "GraphiQL"
    return False, "no GraphQL"

def _v_phpinfo(b):
    ms = ["phpinfo()", "PHP Version", "php.ini", "Configuration File"]
    f = [m for m in ms if m.lower() in b[:10000].lower()]
    return (True, f"phpinfo({','.join(f[:2])})") if len(f) >= 2 else (False, "no phpinfo")

def _v_actuator(b):
    try:
        d = json.loads(b)
        if isinstance(d, dict) and any(k in d for k in ("propertySources", "activeProfiles")): return True, "actuator"
    except: pass
    return False, "no actuator"

def _v_status(b):
    ms = ["Apache Server Status", "Server Version", "Total accesses", "scoreboard"]
    f = [m for m in ms if m.lower() in b[:8000].lower()]
    return (True, f"Apache({len(f)})") if len(f) >= 2 else (False, "no status")

def _v_wp(b):
    ms = ["DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY", "table_prefix"]
    f = [m for m in ms if m in b[:8000]]
    return (True, f"wp({','.join(f[:2])})") if len(f) >= 2 else (False, "no wp-config")

def _v_ds(b): return (True, "Bud1") if "Bud1" in b[:16] else ((True, "nulls") if b[:20].count("\x00") >= 2 else (False, "not binary"))
def _v_tele(b):
    for m in ["Laravel Telescope", "TelescopeRecorder"]:
        if m.lower() in b[:5000].lower(): return True, m
    return False, "no Telescope"
def _v_trace(b):
    ms = ["Application Trace", "Request Details", "System.Web"]
    f = [m for m in ms if m.lower() in b[:8000].lower()]
    return (True, f"trace({len(f)})") if len(f) >= 2 else (False, "no trace")
def _v_prof(b):
    for m in ["sf-toolbar", "Symfony", "_profiler/search"]:
        if m.lower() in b[:5000].lower(): return True, m
    return False, "no profiler"
def _v_debug(b):
    for m in ["stack trace", "traceback", "xdebug", "var_dump", "debugbar"]:
        if m.lower() in b[:5000].lower(): return True, m
    return False, "no debug"
def _v_htpw(b):
    h = re.findall(r'^[a-zA-Z0-9._-]+:\S{10,}$', b[:3000], re.M)
    return (True, f"{len(h)} entries") if h else (False, "no htpasswd")
def _v_pkey(b): return (True, "PEM") if "-----BEGIN" in b and "PRIVATE KEY-----" in b else (False, "no PEM")
def _v_docker(b):
    ds = ["FROM ", "RUN ", "CMD ", "EXPOSE ", "WORKDIR ", "COPY "]
    f = [d for d in ds if d in b[:5000]]
    return (True, f"Docker({len(f)})") if len(f) >= 2 else (False, "no directives")
def _v_sql(b):
    for m in ["CREATE TABLE", "INSERT INTO", "mysqldump", "pg_dump"]:
        if m.lower() in b[:5000].lower(): return True, f"SQL({m})"
    return False, "no SQL"
def _v_pkg(b):
    try:
        d = json.loads(b)
        if isinstance(d, dict) and any(k in d for k in ("name", "version", "dependencies")): return True, f"pkg({d.get('name','?')})"
    except: pass
    return False, "not pkg"
def _v_json(b):
    try:
        d = json.loads(b)
        return (True, "JSON") if isinstance(d, (dict, list)) else (False, "not obj")
    except: return False, "not JSON"
def _v_yaml(b):
    h = re.findall(r'^[a-zA-Z_]\w*:\s*.+', b[:4000], re.M)
    return (True, f"{len(h)} yaml") if len(h) >= 3 else (False, "no yaml")
def _v_xml(b):
    s = b.strip()[:500]
    return (True, "XML") if s.startswith("<?xml") or re.match(r'<[a-zA-Z]\w*[\s>]', s) else (False, "not XML")

_VALIDATORS: List[Tuple[str, Callable]] = [
    (".git/HEAD", _v_git_head), (".git/config", _v_git_config), (".git/logs/HEAD", _v_git_head),
    (".env", _v_env), (".aws/credentials", _v_env), ("application.properties", _v_env),
    (".htpasswd", _v_htpw), ("id_rsa", _v_pkey), ("server.key", _v_pkey),
    ("wp-config", _v_wp),
    ("swagger.json", _v_json_keys(["swagger","openapi","paths","info"], "Swagger")),
    ("swagger/v1", _v_json_keys(["swagger","openapi","paths"], "Swagger")),
    ("openapi.json", _v_json_keys(["openapi","paths"], "OpenAPI")),
    ("api-docs", _v_json_keys(["swagger","openapi","paths"], "APIDocs")),
    ("graphql", _v_graphql), ("graphiql", _v_graphql), ("phpinfo", _v_phpinfo),
    ("actuator/env", _v_actuator), ("actuator/health", _v_json),
    ("actuator/configprops", _v_json), ("actuator/mappings", _v_json),
    ("actuator/heapdump", lambda b: (len(b) > 10000, f"heap {len(b)}B")),
    ("server-status", _v_status), ("server-info", _v_status),
    ("telescope", _v_tele), ("trace.axd", _v_trace), ("elmah.axd", _v_trace),
    ("_profiler", _v_prof), ("__debug__", _v_debug), ("debug", _v_debug),
    (".DS_Store", _v_ds), ("package.json", _v_pkg), ("package-lock.json", _v_json),
    ("composer.json", _v_json), ("dump.sql", _v_sql), ("database.sql", _v_sql),
    ("Dockerfile", _v_docker), ("docker-compose", _v_yaml), (".gitlab-ci.yml", _v_yaml),
    ("config.json", _v_json), ("config.yml", _v_yaml), ("config.xml", _v_xml),
    ("settings.json", _v_json), ("settings.py", _v_env),
    ("application.yml", _v_yaml), ("appsettings.json", _v_json),
    ("web.config", _v_xml), ("firebase.json", _v_json), ("credentials.json", _v_json),
    ("manifest.json", _v_json), ("crossdomain.xml", _v_xml), ("sitemap.xml", _v_xml),
    (".well-known/openid-configuration", _v_json),
]

def _lookup_validator(path: str) -> Optional[Callable]:
    pl = path.lower()
    for pat, fn in _VALIDATORS:
        if pat.lower() in pl: return fn
    return None


class ResponseValidator:
    """3-Layer Response Validation Pipeline.

    Layer 1: Host Baseline → catch-all/SPA detection via random-path probes
    Layer 2: Response Cluster → runtime size/hash clustering
    Layer 3: Content Semantic → per-file-type body structure validation
    """
    def __init__(self, engine: Optional[AsyncHttpEngine] = None,
                 curl_fn: Optional[Callable] = None,
                 log_fn: Optional[Callable] = None, warn_fn: Optional[Callable] = None):
        self._engine = engine; self._curl = curl_fn
        self._log = log_fn or (lambda m: None); self._warn = warn_fn or (lambda m: None)
        self._baselines: Dict[str, HostBaseline] = {}
        self._clusters: Dict[str, _ClusterTracker] = {}

    async def _fetch(self, url, eh=None, to=8.0):
        if self._engine:
            r = await self._engine.get(url, extra_headers=eh, timeout=to)
            return r.code, r.body, r.size, r.content_type
        elif self._curl: return self._curl(url, extra_headers=eh, timeout=to)
        return 0, "", 0, ""

    async def baseline_host(self, host_url: str, extra_headers: Optional[Dict] = None, timeout: float = 8.0) -> HostBaseline:
        key = host_url.rstrip("/")
        if key in self._baselines: return self._baselines[key]
        bl = HostBaseline(host=key)
        codes, sizes, hashes = [], [], []
        for p in _make_baseline_paths():
            try:
                code, body, sz, ct = await self._fetch(f"{key}/{p}", eh=extra_headers, to=timeout)
                if code == 0: continue
                codes.append(code); sizes.append(sz); hashes.append(_hash_body(body))
            except Exception as e: bl.error = str(e)
        bl.probes_ok = len(codes); bl.status_codes = codes; bl.sizes = sizes
        if bl.probes_ok < 2:
            bl.error = bl.error or f"only {bl.probes_ok}/3 OK"
            self._log(f"  ⚠ Baseline {key}: insufficient ({bl.probes_ok}/3)")
        else:
            all200 = all(c == 200 for c in codes)
            uniq = set(h for h in hashes if h)
            spread = max(sizes) - min(sizes) if sizes else 9999
            if all200 and len(uniq) == 1:
                bl.is_catchall = True; bl.body_hash = hashes[0] if hashes else ""
                self._warn(f"CATCH-ALL: {key} — identical body ({sizes[0]}B, hash={bl.body_hash[:12]}…)")
            elif all200 and spread <= 100:
                bl.is_catchall = True; bl.body_hash = hashes[0] if hashes else ""
                self._warn(f"CATCH-ALL (size): {key} — sizes={sizes} spread={spread}B")
            else:
                bl.body_hash = hashes[0] if hashes else ""
                self._log(f"  ✓ Baseline {key}: codes={codes} sizes={sizes}")
        self._baselines[key] = bl; self._clusters[key] = _ClusterTracker()
        return bl

    def baseline_host_sync(self, host_url: str, extra_headers: Optional[Dict] = None) -> HostBaseline:
        return _run_async(self.baseline_host(host_url, extra_headers))

    def host_is_catchall(self, host_url: str, **kw) -> bool:
        return self.baseline_host_sync(host_url, **kw).is_catchall

    def record(self, host_url: str, code: int, size: int, body: str = ""):
        key = host_url.rstrip("/")
        if key not in self._clusters: self._clusters[key] = _ClusterTracker()
        self._clusters[key].record(code, size, body)

    def check_cluster(self, host_url: str) -> Tuple[bool, str]:
        ct = self._clusters.get(host_url.rstrip("/"))
        return ct.is_clustered() if ct else (False, "no data")

    def validate(self, host_url: str, path: str, status: int, body: str, size: int,
                 content_type: str = "", severity: str = "HIGH", waf_baseline_size: int = 0) -> Verdict:
        key = host_url.rstrip("/")
        if status != 200: return Verdict(False, severity, "FP", f"HTTP {status}")
        if size <= 20: return Verdict(False, severity, "FP", f"too small ({size}B)")
        # Layer 1
        bl = self._baselines.get(key)
        if bl and bl.is_catchall:
            return Verdict(False, severity, "FP", f"catch-all (baseline={bl.sizes[0] if bl.sizes else '?'}B)")
        if bl and bl.body_hash and _hash_body(body) == bl.body_hash:
            return Verdict(False, severity, "FP", "body=baseline hash")
        if waf_baseline_size > 0 and abs(size - waf_baseline_size) < 50:
            return Verdict(False, severity, "FP", f"WAF baseline ({waf_baseline_size}B±50)")
        # Soft-404
        if body:
            low = body[:500].lower()
            for marker in SOFT_404_MARKERS:
                if marker in low:
                    if f"={marker}" in low or f'"{marker}' in low: continue
                    return Verdict(False, severity, "FP", f"soft-404: '{marker}'")
        if bl and bl.sizes:
            for bsz in bl.sizes:
                if abs(size - bsz) < 100: return Verdict(False, severity, "FP", f"size≈baseline ({bsz}B±100)")
        # Pre-Layer3: data file served as HTML → guaranteed FP
        ct_low = (content_type or "").lower()
        if any(path.lower().endswith(e) for e in _NON_HTML_EXT):
            if "text/html" in ct_low and size > 200:
                return Verdict(False, severity, "FP", f"data file as HTML ({size}B)")
        # Layer 3
        validator = _lookup_validator(path)
        if validator:
            try: valid, reason = validator(body)
            except Exception as e: valid, reason = None, f"error: {e}"
            if valid is True: return Verdict(True, severity, "CONFIRMED", f"validated: {reason}")
            if valid is False:
                if size > 500: return Verdict(False, severity, "FP", f"mismatch: {reason}")
                lo = {"CRITICAL":"HIGH","HIGH":"MEDIUM","MEDIUM":"LOW"}.get(severity, severity)
                return Verdict(True, lo, "LOW", f"small, unverified: {reason}")
        return Verdict(True, severity, "HIGH", "passed all layers")

# ═══════════════════════════════════════════════════════════════════════════════
# P2: INTELLIGENT TRIAGE & DATA PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_url(url: str) -> str:
    try:
        p = urlparse(url)
        params = parse_qs(p.query, keep_blank_values=True)
        filtered = {k: v for k, v in params.items() if k.lower() not in MARKETING_PARAMS}
        sq = urlencode(sorted(filtered.items()), doseq=True) if filtered else ""
        return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/") or "/", p.params, sq, ""))
    except: return url

def endpoint_key(url: str) -> str:
    try:
        p = urlparse(url)
        pnames = sorted(k for k in parse_qs(p.query).keys() if k.lower() not in MARKETING_PARAMS)
        return f"{p.netloc.lower()}|{p.path.rstrip('/') or '/'}|{'&'.join(pnames)}"
    except: return url

def dedup_urls(urls: List[str]) -> List[str]:
    seen: Set[str] = set(); result: List[str] = []
    for u in urls:
        n = normalize_url(u)
        if n not in seen: seen.add(n); result.append(u)
    return result

def dedup_by_endpoint(urls: List[str]) -> List[str]:
    seen: Set[str] = set(); result: List[str] = []
    for u in urls:
        k = endpoint_key(u)
        if k not in seen: seen.add(k); result.append(u)
    return result

def prioritize_js(js_urls: List[str], target_domain: str, max_files: int = 50) -> Tuple[List[str], int]:
    target_root = target_domain.lower(); own: List[str] = []; skipped = 0
    for u in js_urls:
        try: host = urlparse(u).netloc.lower()
        except: skipped += 1; continue
        if any(cdn in host for cdn in CDN_JS_HOSTS): skipped += 1; continue
        own.append(u)
    # Path dedup (strip content hashes)
    seen: Set[str] = set(); unique: List[str] = []
    for u in own:
        try:
            p = re.sub(r'[.-](?:[0-9a-f]{8,32}|[0-9]+)(?=\.js)', '', urlparse(u).path.lower())
            if p not in seen: seen.add(p); unique.append(u)
            else: skipped += 1
        except: unique.append(u)
    # Score and sort
    def _sc(u):
        fn = urlparse(u).path.split("/")[-1].lower()
        if _JS_SKIP_RE.search(fn): return 0
        if _JS_PRIO_RE.search(fn): return 100
        return 50 if re.search(r'[0-9a-f]{8,}', fn) else 25
    unique.sort(key=_sc, reverse=True)
    return unique[:max_files], skipped

async def alive_check(urls: List[str], engine: AsyncHttpEngine,
                      scope: str = "target", timeout: float = 6.0, max_batch: int = 50) -> Tuple[List[str], List[str]]:
    alive, dead = [], []
    for i in range(0, len(urls), max_batch):
        results = await engine.batch_head(urls[i:i+max_batch], scope=scope, timeout=timeout)
        for u, s in results.items():
            (alive if s > 0 else dead).append(u)
    return alive, dead

def alive_check_sync(urls: List[str], **kw) -> Tuple[List[str], List[str]]:
    if _engine is None: raise RuntimeError("Call init_engine() first.")
    return _run_async(alive_check(urls, _engine, **kw))

async def triage_urls(urls: List[str], engine: AsyncHttpEngine,
                      scope: str = "target", alive_check_enabled: bool = True,
                      max_alive_check: int = 200) -> TriageResult:
    result = TriageResult(original_count=len(urls))
    step1 = dedup_urls(urls)
    step2 = dedup_by_endpoint(step1)
    result.deduped_count = len(urls) - len(step2)
    if alive_check_enabled and engine and step2:
        batch = step2[:max_alive_check]
        alive, dead = await alive_check(batch, engine, scope=scope)
        result.live_urls = alive + step2[max_alive_check:]
        result.dead_urls = dead
    else:
        result.live_urls = step2
    return result

def triage_urls_sync(urls: List[str], **kw) -> TriageResult:
    if _engine is None: raise RuntimeError("Call init_engine() first.")
    return _run_async(triage_urls(urls, _engine, **kw))
