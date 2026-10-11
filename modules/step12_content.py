# modules/step12_content.py
"""
GHOST RECON v2.0 — STEP 12: Content Discovery
ffuf directory fuzzing with auto-calibrate + 403 bypass engine.
"""
from __future__ import annotations
import asyncio, json, os, re, shutil, tempfile, random
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 12
STEP_NAME = "Content Discovery"

BYPASS_TECHNIQUES = [
    # Path mutations
    lambda p: f"{p}/",
    lambda p: f"{p}/.",
    lambda p: f"{p}/./",
    lambda p: f"{p}..;/",
    lambda p: f"{p};/",
    lambda p: f"{p}%20",
    lambda p: f"{p}%09",
    lambda p: f"{p}%00",
    lambda p: f"{p}..%00",
    lambda p: f"{p}..%0d",
    lambda p: f"{p}#",
    lambda p: f"{p}?",
    # Case swaps
    lambda p: p.upper() if p.islower() else p.lower(),
    lambda p: p[0].upper() + p[1:] if len(p) > 1 else p.upper(),
    # Double URL encode
    lambda p: p.replace("/", "%252f"),
    # Unicode
    lambda p: p.replace("/", "%ef%bc%8f"),
]

BYPASS_HEADERS = [
    {"X-Original-URL": None},  # Will be set to path
    {"X-Rewrite-URL": None},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
]

BYPASS_METHODS = ["GET", "POST", "PUT", "PATCH"]

def _has(b: str) -> bool:
    return shutil.which(b) is not None


async def _ffuf_scan(target: str, wordlist: str, output_file: str, host_header: str = "",
                     rate: int = 10, threads: int = 8, fs: str = "",
                     timeout: float = 300.0) -> Tuple[List[Dict], Optional[str]]:
    if not _has("ffuf"):
        return [], "ffuf not installed"
    args = ["ffuf", "-u", target, "-w", wordlist,
            "-H", f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "-mc", "200,201,204,301,302,307,401,403,405,500",
            "-ac", "-ach",
            "-rate", str(rate), "-t", str(threads), "-timeout", "15",
            "-s", "-o", output_file, "-of", "json"]
    if host_header:
        args.extend(["-H", f"Host: {host_header}"])
    if fs:
        args.extend(["-fs", fs])
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
        results = []
        if os.path.exists(output_file):
            try:
                data = json.loads(open(output_file).read())
                results = data.get("results", [])
            except Exception:
                pass
        return results, None
    except asyncio.TimeoutError:
        return [], "Timed out"
    except Exception as e:
        return [], str(e)[:80]


async def _bypass_403(url: str, engine: Any, host_header: str = "") -> Optional[Tuple[str, int, int]]:
    if engine is None:
        return None
    path = "/" + url.split("/", 3)[-1] if url.count("/") >= 3 else "/"

    for technique in BYPASS_TECHNIQUES:
        try:
            mutated_path = technique(path)
            base = url.rsplit(path, 1)[0] if path != "/" else url.rstrip("/")
            test_url = base + mutated_path
            extra = {"Host": host_header} if host_header else {}
            resp = await engine.get(test_url, extra_headers=extra or None, timeout=8.0, scope="target")
            if resp.code == 200 and resp.size > 50:
                return (test_url, resp.code, resp.size)
        except Exception:
            continue

    for hdr_set in BYPASS_HEADERS:
        try:
            headers = {}
            for k, v in hdr_set.items():
                headers[k] = v if v else path
            if host_header:
                headers["Host"] = host_header
            resp = await engine.get(url, extra_headers=headers, timeout=8.0, scope="target")
            if resp.code == 200 and resp.size > 50:
                hdr_name = list(hdr_set.keys())[0]
                return (f"{url} [Header: {hdr_name}]", resp.code, resp.size)
        except Exception:
            continue

    for method in BYPASS_METHODS[1:]:
        try:
            extra = {"Host": host_header} if host_header else {}
            resp = await engine.request(url, method=method, extra_headers=extra or None,
                                         timeout=8.0, scope="target")
            if resp.code == 200 and resp.size > 50:
                return (f"{url} [Method: {method}]", resp.code, resp.size)
        except Exception:
            continue

    return None


async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None
    def _p(m):
        (console.print if console else lambda x: print(__import__('re').sub(r'\[/?[^\]]*\]','',x)))(m)

    ws = getattr(config, 'workspace', '.') or '.'
    rate = int(getattr(config, 'rate', 10))
    threads = int(getattr(config, 'threads', 8))

    _p(f"  [bold]Content discovery & 403 bypass[/bold]")

    # Prepare wordlist
    wl_path = os.path.join(ws, "fuzz", "dynamic_wordlist.txt")
    if not os.path.exists(wl_path):
        wl_path = os.path.join(ws, "fuzz", "wordlist.txt")
    if not os.path.exists(wl_path):
        _p("  [yellow]⚠ No wordlist found — generating minimal list[/yellow]")
        from core.config import STEALTH_PROFILES  # avoid circular
        wl_path = os.path.join(ws, "fuzz", "wordlist.txt")
        os.makedirs(os.path.dirname(wl_path), exist_ok=True)
        with open(wl_path, "w") as f:
            f.write("\n".join([
                "admin", "login", "api", "dashboard", "config", ".env", ".git/HEAD",
                "swagger.json", "graphql", "debug", "phpinfo.php", "actuator",
                "server-status", "robots.txt", "sitemap.xml",
            ]) + "\n")

    # Get baseline 404 size
    baseline_sz = 0
    if engine:
        try:
            nonce = f"ghost_nonexist_{random.randint(10000,99999)}"
            extra = {"Host": ctx.host_header} if ctx.host_header else {}
            resp = await engine.get(ctx.probe_url(nonce), extra_headers=extra or None,
                                     timeout=8.0, scope="target")
            baseline_sz = resp.size
        except Exception:
            pass

    fs = str(baseline_sz) if baseline_sz > 0 else ""

    # ffuf main scan
    if _has("ffuf"):
        target = ctx.probe_url("FUZZ")
        host_h = ctx.host_header or ""
        ffuf_out = os.path.join(ws, "fuzz", "results.json")
        os.makedirs(os.path.dirname(ffuf_out), exist_ok=True)

        _p(f"  [cyan]→[/cyan]  ffuf directory scan (baseline 404: {baseline_sz}B)")
        if _RICH and console:
            with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), TimeElapsedColumn(),
                          console=console, transient=True) as prog:
                prog.add_task("ffuf fuzzing...", total=None)
                results, err = await _ffuf_scan(target, wl_path, ffuf_out, host_h, rate, threads, fs)
        else:
            results, err = await _ffuf_scan(target, wl_path, ffuf_out, host_h, rate, threads, fs)

        if err:
            _p(f"  [yellow]⚠[/yellow]  ffuf: {err}")
        else:
            # Filter FP clusters
            sizes = {}
            for r in results:
                sz = r.get("length", 0)
                sizes[sz] = sizes.get(sz, 0) + 1
            fp_sizes = {s for s, c in sizes.items() if c >= 5}

            for r in results:
                if r.get("length", 0) in fp_sizes:
                    continue
                st = r.get("status", 0)
                url = r.get("url", "")
                ln = r.get("length", 0)
                if st == 200:
                    sev = "HIGH" if any(k in url.lower() for k in ['.env','.git','admin','config','debug','backup','.sql','phpinfo','actuator']) else "MEDIUM"
                    ctx.add_finding(severity=sev, category="CONTENT_DISCOVERY", url=url,
                                    title=f"Accessible [{st}] {ln}B", detail=f"Content at {url}",
                                    impact="Hidden content may contain sensitive data",
                                    exploit=f"curl -sk '{url}'", confidence="CONFIRMED",
                                    cwe="CWE-538", phase="12")
                    ctx.add_path(url, 200, size=ln, source="ffuf")
                elif st == 403:
                    ctx.add_path(url, 403, size=ln, source="ffuf")

            _p(f"  [green]✓[/green]  ffuf: {len(results)} results (200: {sum(1 for r in results if r.get('status')==200)}, 403: {sum(1 for r in results if r.get('status')==403)})")

    # 403 Bypass engine
    paths_403 = ctx.get_untested_403s()
    if paths_403 and engine:
        _p(f"\n  [cyan]→[/cyan]  403 bypass engine ({len(paths_403)} paths)")
        sem = asyncio.Semaphore(3)
        bypassed = 0

        async def _try_bypass(url: str):
            nonlocal bypassed
            async with sem:
                result = await _bypass_403(url, engine, ctx.host_header)
                ctx.mark_403_tested(url)
                if result:
                    bypass_url, code, size = result
                    bypassed += 1
                    ctx.add_finding(severity="HIGH", category="CONTENT_DISCOVERY",
                                    url=bypass_url, title=f"403 Bypass: {url.split('/')[-1]}",
                                    detail=f"Bypassed to HTTP {code}, {size}B",
                                    impact="Access control bypass on restricted endpoint",
                                    exploit=f"curl -sk '{bypass_url}'",
                                    confidence="CONFIRMED", cwe="CWE-284", phase="12")

        if _RICH and console:
            with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                          BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                          console=console, transient=True) as prog:
                task = prog.add_task("403 bypass testing...", total=len(paths_403))
                for coro in asyncio.as_completed([_try_bypass(u) for u in paths_403[:30]]):
                    await coro
                    prog.update(task, advance=1)
        else:
            await asyncio.gather(*[_try_bypass(u) for u in paths_403[:30]])

        _p(f"  [green]✓[/green]  403 bypasses: {bypassed}/{len(paths_403)}")

    _p(f"\n  [bold]Step 12 Summary:[/bold] {len(ctx.paths_200)} accessible, {len(ctx.paths_403)} blocked")
    return ctx
