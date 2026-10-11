# modules/step04_urls.py
"""
GHOST RECON v2.0 — STEP 4: URL & Endpoint Discovery
OOM-PROOF: Streams gau/waybackurls line-by-line via async iterator.
Flushes to SQLite in CHUNK_SIZE=5000 batches via ctx.add_urls_bulk().
Compiled regexes. Zombie-proof subprocesses. Active crawl fallback.
"""
from __future__ import annotations
import asyncio, json, os, re, shutil
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, quote, urljoin

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 4
STEP_NAME = "URL & Endpoint Discovery"

_HEAVY_SEM = asyncio.Semaphore(3)
CHUNK_SIZE = 5000

# Compiled regexes — avoid recompiling per-URL
_RE_HTTP = re.compile(r'^https?://', re.I)
_RE_JS = re.compile(r'https?://[^\s"\']+\.js(?:\?[^\s"\']*)?$', re.I)
_RE_PARAM = re.compile(r'[?&]([a-zA-Z0-9_]+)=')
_RE_SENSITIVE = re.compile(
    r'(admin|config|backup|\.env|\.git|debug|phpinfo|wp-login|\.sql|\.bak|'
    r'api/|swagger|graphql|internal|actuator|\.key|\.pem|token)', re.I)
_RE_HREF = re.compile(r'(?:href|src|action)=["\']([^"\']{5,200})["\']', re.I)
_RE_ABSURL = re.compile(r'https?://[^\s"\'<>]{10,200}')

URLSCAN_DORKS = [
    "page.url:.php", "page.url:admin", "page.url:api",
    "page.url:login", "page.url:config", "page.url:swagger",
    "page.url:graphql",
]

def _has(b): return shutil.which(b) is not None


async def _stream_url_tool(name: str, cmd_str: str, root_domain: str,
                           ctx: Any, timeout: float = 600.0, _p=None):
    """OOM-PROOF: Stream stdout line-by-line. Flush to DB every CHUNK_SIZE URLs.
    Uses async for line in proc.stdout instead of communicate()."""
    _log = _p or (lambda m: None)
    async with _HEAVY_SEM:
        proc = None
        total = 0
        buf: List[str] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Stream stdout line-by-line — never holds full output in memory
            async def _read_lines():
                nonlocal total
                async for raw_line in proc.stdout:
                    line = raw_line.decode("utf-8", errors="ignore").strip()
                    if line and _RE_HTTP.match(line) and root_domain in urlparse(line).netloc.lower():
                        buf.append(line)
                        if len(buf) >= CHUNK_SIZE:
                            n = ctx.add_urls_bulk(buf, source=name)
                            total += n
                            buf.clear()

            try:
                await asyncio.wait_for(_read_lines(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc:
                    proc.kill()
                    await proc.wait()
                _log(f"  [yellow]⚠[/yellow]  {name}: timed out after {timeout:.0f}s ({total} flushed)")
                # Flush remaining buffer
                if buf:
                    total += ctx.add_urls_bulk(buf, source=name)
                    buf.clear()
                return name, total, f"Timed out ({total} saved)"

            # Wait for process to finish
            await proc.wait()

            # Drain stderr (small, safe to read fully)
            # Don't care about stderr content, just prevent pipe leak
            try:
                await asyncio.wait_for(proc.stderr.read(), timeout=5.0)
            except:
                pass

            # Flush remaining buffer
            if buf:
                total += ctx.add_urls_bulk(buf, source=name)
                buf.clear()

            return name, total, None

        except FileNotFoundError:
            return name, 0, f"Binary not found"
        except Exception as e:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except:
                    pass
            # Flush whatever we got
            if buf:
                total += ctx.add_urls_bulk(buf, source=name)
            return name, total, str(e)[:100]


async def _katana_stream(url: str, root_domain: str, ctx: Any,
                         rate: int = 10, _p=None):
    """Katana with streaming output."""
    if not _has("katana"):
        return "katana", 0, "Not installed"
    cmd = f"katana -u {url} -d 3 -jc -silent -rl {rate} -timeout 10 -no-color 2>/dev/null"
    return await _stream_url_tool("katana", cmd, root_domain, ctx, timeout=600.0, _p=_p)


async def _wayback_stream(domain: str, root_domain: str, ctx: Any, _p=None):
    if not _has("waybackurls"):
        return "waybackurls", 0, "Not installed"
    cmd = f"echo {domain} | waybackurls 2>/dev/null"
    return await _stream_url_tool("waybackurls", cmd, root_domain, ctx, timeout=600.0, _p=_p)


async def _gau_stream(domain: str, root_domain: str, ctx: Any, _p=None):
    if not _has("gau"):
        return "gau", 0, "Not installed"
    cmd = f"echo {domain} | gau --threads 3 2>/dev/null"
    return await _stream_url_tool("gau", cmd, root_domain, ctx, timeout=600.0, _p=_p)


async def _urlscan_dork(rd: str, engine: Any, ctx: Any):
    """URLScan uses engine (small responses, communicate is fine)."""
    if not engine:
        return "urlscan", 0, "No engine"
    urls: List[str] = []
    for dork in URLSCAN_DORKS:
        try:
            resp = await engine.get(
                f"https://urlscan.io/api/v1/search/?q={quote(f'domain:{rd} AND {dork}')}&size=100",
                timeout=12.0, scope="urlscan")
            if resp.code == 200 and resp.body:
                for r in json.loads(resp.body).get("results", []):
                    u = r.get("page", {}).get("url", "")
                    if u and rd in urlparse(u).netloc.lower():
                        urls.append(u)
            await asyncio.sleep(1.0)
        except:
            continue
    if urls:
        ctx.add_urls_bulk(urls, source="urlscan")
    return "urlscan", len(urls), None


async def _active_crawl(target_url: str, engine: Any, rd: str, ctx: Any):
    """Fallback: shallow DOM crawl via engine."""
    if not engine:
        return "crawl", 0, "No engine"
    urls: List[str] = []
    try:
        resp = await engine.get(target_url, timeout=12.0, scope="target")
        if resp.code == 200 and resp.body:
            for m in _RE_HREF.finditer(resp.body):
                full = urljoin(target_url, m.group(1))
                if rd in urlparse(full).netloc.lower():
                    urls.append(full)
            for m in _RE_ABSURL.finditer(resp.body):
                if rd in urlparse(m.group()).netloc.lower():
                    urls.append(m.group())
            # Depth-1 crawl on top pages
            sem = asyncio.Semaphore(5)
            page_urls = [u for u in urls[:20] if u.endswith(('.html', '.php', '/')) or '?' not in u]

            async def _fetch(u):
                async with sem:
                    try:
                        r2 = await engine.get(u, timeout=8.0, scope="target")
                        if r2.code == 200 and r2.body:
                            for m in _RE_HREF.finditer(r2.body):
                                full = urljoin(u, m.group(1))
                                if rd in urlparse(full).netloc.lower():
                                    urls.append(full)
                    except:
                        pass

            await asyncio.gather(*[_fetch(u) for u in page_urls[:10]])
    except Exception as e:
        return "crawl", 0, str(e)[:80]
    if urls:
        ctx.add_urls_bulk(urls, source="crawl")
    return "crawl", len(urls), None


async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None

    def _p(m):
        (console.print if console else lambda x: print(
            __import__('re').sub(r'\[/?[^\]]*\]', '', x)))(m)

    domain = ctx.domain
    rd = ctx.root_domain
    url = ctx.url
    rate = int(getattr(config, 'rate', 10))
    ws = getattr(config, 'workspace', '.') or '.'

    _p(f"  [bold]OOM-proof streaming URL harvest for {domain}[/bold]")

    # Build concurrent tasks — streaming tools + API sources
    tasks = {
        "waybackurls": _wayback_stream(domain, rd, ctx, _p),
        "gau": _gau_stream(domain, rd, ctx, _p),
        "katana": _katana_stream(url, rd, ctx, rate, _p),
        "urlscan": _urlscan_dork(rd, engine, ctx),
        "crawl": _active_crawl(url, engine, rd, ctx),
    }
    if domain != rd:
        tasks["wayback_root"] = _wayback_stream(rd, rd, ctx, _p)

    names = list(tasks.keys())
    coros = list(tasks.values())

    if _RICH and console:
        with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                      TimeElapsedColumn(), console=console, transient=True) as prog:
            prog.add_task(f"Streaming {len(tasks)} URL sources...", total=None)
            results = await asyncio.gather(*coros, return_exceptions=True)
    else:
        _p(f"  Running {len(tasks)} sources...")
        results = await asyncio.gather(*coros, return_exceptions=True)

    # Report results
    grand_total = 0
    for name, result in zip(names, results):
        if isinstance(result, Exception):
            _p(f"  [red]✗[/red]  {name}: {result}")
            continue
        tn, count, err = result
        grand_total += count
        icon = "⚠" if err else "✓"
        color = "yellow" if err else "green"
        _p(f"  [{color}]{icon}[/{color}]  {tn}: {count} URLs"
           + (f" — {err}" if err else ""))

    # Extract JS files from DB URLs (avoid loading all into memory)
    _p(f"\n  [bold]Post-processing[/bold]")
    url_count = ctx.url_count()
    _p(f"  [green]✓[/green]  {url_count} total URLs in database")

    # JS file extraction — query DB directly
    rows = ctx.db.fetch_all(
        "SELECT url FROM urls WHERE scan_id = ? AND url LIKE '%.js%'",
        (ctx.scan_id,))
    js_urls = [r["url"] for r in rows if _RE_JS.match(r["url"])]

    # Also extract from index page
    if engine:
        try:
            resp = await engine.get(url, timeout=12.0, scope="target")
            if resp.code == 200 and resp.body:
                for m in re.finditer(r'src=["\']([^"\']*\.js[^"\']*)', resp.body):
                    js_urls.append(urljoin(url, m.group(1)))
        except:
            pass

    if js_urls:
        ctx.bulk_insert_js_files(js_urls)
    _p(f"  [green]✓[/green]  JS files: {len(js_urls)}")

    # Param extraction — query DB directly, never load all URLs into Python
    param_rows = ctx.db.fetch_all(
        "SELECT url FROM urls WHERE scan_id = ? AND url LIKE '%?%'",
        (ctx.scan_id,))
    param_set: Set[str] = set()
    for row in param_rows:
        for p in _RE_PARAM.findall(row["url"]):
            param_set.add(p)
    if param_set:
        ctx.bulk_insert_params(list(param_set), source="url_extract")
    _p(f"  [green]✓[/green]  Parameters: {len(param_set)}")

    # Sensitive URL flagging — query DB
    sens_rows = ctx.db.fetch_all(
        """SELECT url FROM urls WHERE scan_id = ? AND (
            url LIKE '%admin%' OR url LIKE '%.env%' OR url LIKE '%.git%'
            OR url LIKE '%config%' OR url LIKE '%swagger%' OR url LIKE '%graphql%'
            OR url LIKE '%backup%' OR url LIKE '%debug%' OR url LIKE '%actuator%'
        )""", (ctx.scan_id,))
    if sens_rows:
        _p(f"  [yellow]⚠[/yellow]  Sensitive URLs: {len(sens_rows)}")
        try:
            os.makedirs(os.path.join(ws, "enum"), exist_ok=True)
            with open(os.path.join(ws, "enum", "sensitive_urls.txt"), "w") as f:
                for r in sens_rows:
                    f.write(r["url"] + "\n")
        except:
            pass

    # Save params and JS list to workspace
    try:
        os.makedirs(os.path.join(ws, "enum"), exist_ok=True)
        with open(os.path.join(ws, "enum", "params.txt"), "w") as f:
            f.write("\n".join(sorted(param_set)) + "\n")
        with open(os.path.join(ws, "enum", "js_files.txt"), "w") as f:
            f.write("\n".join(sorted(set(js_urls))) + "\n")
    except:
        pass

    _p(f"\n  [bold]Step 4:[/bold] {url_count} URLs, {len(js_urls)} JS, {len(param_set)} params")
    return ctx
