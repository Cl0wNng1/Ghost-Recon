# modules/step05_javascript.py
"""
GHOST RECON v2.0 — STEP 5: JavaScript Analysis
Fetch JS files, extract secrets/API routes/cloud services, Shannon entropy scoring.
"""
from __future__ import annotations
import asyncio, hashlib, json, math, os, re
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 5
STEP_NAME = "JavaScript Analysis"

CDN_JS_HOSTS = frozenset({
    "cdnjs.cloudflare.com","cdn.jsdelivr.net","unpkg.com","ajax.googleapis.com",
    "code.jquery.com","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com",
    "fonts.googleapis.com","use.fontawesome.com","cdn.shopify.com",
    "cdn.datatables.net","polyfill.io","cdn.tailwindcss.com",
    "www.google-analytics.com","connect.facebook.net","platform.twitter.com",
    "www.googletagmanager.com","js.stripe.com","cdn.segment.com",
})

JS_SKIP_RE = re.compile(r'(?:polyfill|jquery|lodash|moment|react-dom|angular[\.-]|vue[\.-]|analytics|tracking|gtm|gtag|pixel|hotjar|bootstrap)', re.I)
JS_PRIO_RE = re.compile(r'(?:app|main|bundle|index|chunk|config|env|settings|constants|api|auth|routes)[\.-]', re.I)

API_ROUTE_RE = re.compile(r'''["'](/(?:api|v[1-9]|internal|admin|auth|user|account|graphql|rest|service)[/][a-zA-Z0-9/_-]{3,60})["']''')
FETCH_RE = re.compile(r'''(?:fetch|axios|\.get|\.post|\.put|\.delete)\s*\(\s*["'`]([^"'`]{5,80})["'`]''')
ROUTER_RE = re.compile(r'''path:\s*["']([^"']{3,60})["']''')
WS_RE = re.compile(r'''(?:ws|wss)://[^\s"'`<>]{5,80}''')

CLOUD_PATTERNS = [
    (re.compile(r'([a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com)'), "AWS_S3"),
    (re.compile(r'storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9._-]+\.storage\.googleapis\.com'), "GCS"),
    (re.compile(r'[a-z0-9]+\.blob\.core\.windows\.net'), "AZURE_BLOB"),
    (re.compile(r'[a-z0-9-]+\.firebaseio\.com|[a-z0-9-]+\.firebaseapp\.com'), "FIREBASE"),
    (re.compile(r'[a-z0-9-]+\.digitaloceanspaces\.com'), "DO_SPACES"),
]

SECRET_PATTERNS_JS = {
    "AWS Access Key":     (re.compile(r'AKIA[0-9A-Z]{16}'), "CRITICAL"),
    "AWS Secret":         (re.compile(r'(?:aws_secret|secret_key|AWS_SECRET)["\':\s=]+[A-Za-z0-9/+=]{40}'), "CRITICAL"),
    "Stripe Live Key":    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "CRITICAL"),
    "Slack Token":        (re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}'), "HIGH"),
    "GitHub Token":       (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "HIGH"),
    "Private Key":        (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "CRITICAL"),
    "SendGrid Key":       (re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'), "CRITICAL"),
    "Google API Key":     (re.compile(r'AIza[0-9A-Za-z\\-_]{35}'), "MEDIUM"),
    "Firebase Config":    (re.compile(r'apiKey["\':\s]+["\']AIza[A-Za-z0-9_-]{35}'), "HIGH"),
    "OpenAI Key":         (re.compile(r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'), "CRITICAL"),
    "Generic API Key":    (re.compile(r'(?:api[_-]?key|apikey|api_secret)["\':\s=]+["\']?[A-Za-z0-9_\-]{20,}'), "MEDIUM"),
    "Bearer Token":       (re.compile(r'[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}'), "MEDIUM"),
    "Database URL":       (re.compile(r'(?:postgres|mysql|mongodb|redis)://[^\s"\'<>]{10,}'), "CRITICAL"),
    "Hardcoded Password": (re.compile(r'(?:password|passwd|pwd)["\':\s=]+["\'][^\s"\']{6,}["\']'), "HIGH"),
    "JWT Token":          (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'), "MEDIUM"),
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    length = len(s)
    return -sum((count/length) * math.log2(count/length) for count in c.values())


def _score_js(url: str) -> int:
    fn = urlparse(url).path.split("/")[-1].lower()
    if JS_SKIP_RE.search(fn):
        return 0
    if JS_PRIO_RE.search(fn):
        return 100
    if re.search(r'[0-9a-f]{8,}', fn):
        return 50
    return 25


def _is_cdn_js(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
        return any(cdn in host for cdn in CDN_JS_HOSTS)
    except Exception:
        return False


async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None
    def _p(m):
        (console.print if console else lambda x: print(__import__('re').sub(r'\[/?[^\]]*\]','',x)))(m)

    all_js = list(ctx.js_files)

    # Also extract from URL table
    for u in ctx.urls:
        if re.search(r'\.js(\?|$)', u, re.I) and u not in all_js:
            all_js.append(u)

    if not all_js:
        _p("  [yellow]No JavaScript files discovered[/yellow]")
        return ctx

    # Filter CDN and deduplicate
    own_js = [u for u in all_js if not _is_cdn_js(u)]
    skipped = len(all_js) - len(own_js)
    if skipped > 0:
        _p(f"  [dim]Filtered {skipped} CDN/third-party JS files[/dim]")

    # Score and sort
    scored = sorted(own_js, key=_score_js, reverse=True)
    max_files = 50
    to_analyze = scored[:max_files]
    if len(scored) > max_files:
        _p(f"  [dim]Analyzing top {max_files}/{len(scored)} by priority score[/dim]")

    _p(f"  [bold]Analyzing {len(to_analyze)} JavaScript files[/bold]")

    if engine is None:
        _p("  [yellow]⚠ No HTTP engine — JS analysis requires ghost_core or httpx[/yellow]")
        return ctx

    total_routes: Set[str] = set()
    total_secrets: List[Tuple[str, str, str, str]] = []
    total_cloud: Set[str] = set()
    sem = asyncio.Semaphore(10)

    async def _analyze_one(js_url: str) -> Dict[str, Any]:
        async with sem:
            result = {"url": js_url, "routes": set(), "secrets": [], "cloud": set(), "error": None}
            try:
                resp = await engine.get(js_url, timeout=12.0, scope="target")
                if resp.code != 200 or not resp.body or resp.size < 100:
                    result["error"] = f"HTTP {resp.code}"
                    return result

                body = resp.body
                h = hashlib.sha256(body[:4096].encode(errors="replace")).hexdigest()[:16]
                ctx.add_js_file(js_url, hash_=h, size=resp.size, priority_score=_score_js(js_url))

                # API routes
                for m in API_ROUTE_RE.finditer(body):
                    result["routes"].add(m.group(1))
                for m in FETCH_RE.finditer(body):
                    result["routes"].add(m.group(1))
                for m in ROUTER_RE.finditer(body):
                    result["routes"].add(m.group(1))
                for m in WS_RE.finditer(body):
                    result["routes"].add(m.group())

                # Secrets
                for name, (pattern, severity) in SECRET_PATTERNS_JS.items():
                    for m in pattern.finditer(body):
                        val = m.group()[:80]
                        if _shannon_entropy(val) > 3.0 or severity == "CRITICAL":
                            result["secrets"].append((name, val, severity, js_url))

                # Cloud services
                for pat, svc_type in CLOUD_PATTERNS:
                    for m in pat.finditer(body):
                        result["cloud"].add(f"{svc_type}:{m.group()}")

                ctx.mark_js_analyzed(js_url, secrets=len(result["secrets"]), routes=len(result["routes"]))

            except Exception as e:
                result["error"] = str(e)[:60]
            return result

    if _RICH and console:
        with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                      BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                      console=console, transient=True) as prog:
            task = prog.add_task("Analyzing JS files...", total=len(to_analyze))
            results = []
            for coro in asyncio.as_completed([_analyze_one(u) for u in to_analyze]):
                r = await coro
                results.append(r)
                prog.update(task, advance=1)
    else:
        _p(f"  Analyzing {len(to_analyze)} files...")
        results = await asyncio.gather(*[_analyze_one(u) for u in to_analyze], return_exceptions=True)

    # Aggregate
    for r in results:
        if isinstance(r, Exception):
            continue
        if r.get("error"):
            continue
        total_routes.update(r.get("routes", set()))
        total_secrets.extend(r.get("secrets", []))
        total_cloud.update(r.get("cloud", set()))

    # Ingest routes as API endpoints
    for route in total_routes:
        ctx.add_api_endpoint(route, source="js_mine")
        if route.startswith("/") or route.startswith("http"):
            ctx.add_url(urljoin(ctx.url, route), source="js_mine")

    _p(f"  [green]✓[/green]  API routes extracted: {len(total_routes)}")
    for r in sorted(total_routes)[:8]:
        _p(f"    [dim]{r}[/dim]")
    if len(total_routes) > 8:
        _p(f"    [dim]... +{len(total_routes)-8} more[/dim]")

    # Ingest secrets
    for name, val, severity, source_url in total_secrets:
        ctx.add_secret(name, val, source_url=source_url, source_type="js",
                       severity=severity, cwe="CWE-798")
        ctx.add_finding(severity=severity, category="SECRET_LEAK", url=source_url,
                        title=f"{name} in JavaScript", detail=f"Pattern match in {urlparse(source_url).path.split('/')[-1]}",
                        impact="Credential exposure, unauthorized access",
                        exploit=f"curl -sk '{source_url}' | grep -oP '{val[:20]}...'",
                        confidence="HIGH", cwe="CWE-798", phase="5")

    if total_secrets:
        _p(f"  [red]🔑 Secrets found: {len(total_secrets)}[/red]")
        for name, val, sev, src in total_secrets[:5]:
            _p(f"    [{('red' if sev=='CRITICAL' else 'yellow')}]{sev}[/] {name}: {val[:30]}...")

    # Ingest cloud services
    for cs in total_cloud:
        svc_type, svc_url = cs.split(":", 1) if ":" in cs else ("CLOUD", cs)
        ctx.add_finding(severity="MEDIUM", category="CLOUD_SERVICE_LEAK", url=svc_url,
                        title=f"{svc_type} reference in JS", detail=f"Cloud resource: {svc_url}",
                        impact="Potential data exposure via misconfigured access",
                        confidence="MEDIUM", cwe="CWE-200", phase="5")

    if total_cloud:
        _p(f"  [yellow]☁ Cloud services: {len(total_cloud)}[/yellow]")

    # Save to workspace
    ws = getattr(config, 'workspace', '.')
    try:
        if total_routes:
            with open(os.path.join(ws, "enum", "js_api_routes.txt"), "w") as f:
                f.write("\n".join(sorted(total_routes)) + "\n")
        if total_secrets:
            with open(os.path.join(ws, "secrets", "js_secrets.txt"), "w") as f:
                for name, val, sev, src in total_secrets:
                    f.write(f"{sev}|{name}|{val[:40]}|{src}\n")
    except Exception:
        pass

    _p(f"\n  [bold]Step 5 Summary:[/bold] {len(to_analyze)} JS analyzed, "
       f"{len(total_routes)} routes, {len(total_secrets)} secrets, {len(total_cloud)} cloud")
    return ctx
