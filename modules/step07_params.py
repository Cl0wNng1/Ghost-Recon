# modules/step07_params.py
"""
GHOST RECON v2.0 — STEP 7: Parameter Discovery
Arjun/ParamSpider + Active Heuristic Fuzzer (40 params, canary injection,
length variance >5% detection). Auto-categorize via ctx.payload_registry['gf_patterns'].
"""
from __future__ import annotations
import asyncio, json, os, random, re, shutil
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 7
STEP_NAME = "Parameter Discovery"
_HEAVY_SEM = asyncio.Semaphore(3)
GF_CLI = ["xss","sqli","ssrf","redirect","lfi","idor","rce"]

def _has(b): return shutil.which(b) is not None

async def _arjun(url, out, timeout=120.0):
    if not _has("arjun"): return set(), "Not installed"
    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec("arjun","-u",url,"--passive","-oT",out,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try: stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc: proc.kill(); await proc.wait()
                return set(), "Timed out"
            params = set()
            if os.path.exists(out):
                for l in open(out): p=l.strip(); (params.add(p) if p and not p.startswith("#") else None)
            return params, None
        except Exception as e:
            if proc and proc.returncode is None:
                try: proc.kill(); await proc.wait()
                except: pass
            return set(), str(e)[:80]

async def _paramspider(domain, out, timeout=120.0):
    if not _has("paramspider"): return set(), set(), "Not installed"
    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec("paramspider","-d",domain,
                "--exclude","woff,css,js,png,jpg,svg,gif","--output",out,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try: stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc: proc.kill(); await proc.wait()
                return set(), set(), "Timed out"
            params, urls = set(), set()
            if os.path.exists(out):
                for l in open(out):
                    u=l.strip()
                    if u: urls.add(u)
                    for p in re.findall(r'[?&]([a-zA-Z0-9_]+)=', u): params.add(p)
            return params, urls, None
        except Exception as e:
            if proc and proc.returncode is None:
                try: proc.kill(); await proc.wait()
                except: pass
            return set(), set(), str(e)[:80]

async def _gf_classify(urls_file, ws, timeout=60.0):
    if not _has("gf"): return {}
    results = {}
    for pat in GF_CLI:
        proc = None
        try:
            # v2.0: feed the file on stdin instead of building a `bash -c`
            # string from the workspace path (spaces/metacharacters broke it).
            with open(urls_file, "rb") as _fin:
                proc = await asyncio.create_subprocess_exec("gf", pat,
                    stdin=_fin, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            try: stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc: proc.kill(); await proc.wait(); continue
            lines = [l.strip() for l in (stdout or b"").decode("utf-8",errors="ignore").split("\n") if l.strip()]
            if lines:
                results[pat] = lines
                try:
                    os.makedirs(os.path.join(ws,"enum"),exist_ok=True)
                    with open(os.path.join(ws,"enum",f"gf_{pat}.txt"),"w") as f: f.write("\n".join(lines)+"\n")
                except: pass
        except: continue
    return results

async def _active_heuristic_fuzz(ctx, engine, params, _p):
    """Chunk 40 params. Inject random canary. Flag length variance >5% or status change."""
    if not engine: return []
    _p(f"\n  [cyan]→[/cyan]  Active heuristic fuzzer ({min(len(params),40)} params)")
    base_url = ctx.probe_url()
    extra_h = {"Host": ctx.host_header} if ctx.host_header else None
    try:
        baseline = await engine.get(base_url, extra_headers=extra_h, timeout=10.0, scope="target")
        base_size, base_code = baseline.size, baseline.code
    except: _p("  [dim]Baseline fetch failed[/dim]"); return []
    if base_size == 0: return []
    interesting = []; sem = asyncio.Semaphore(8)
    async def _fuzz(param):
        async with sem:
            canary = f"gh0st{random.randint(10000,99999)}"
            try:
                url = f"{base_url}?{param}={canary}"
                resp = await engine.get(url, extra_headers=extra_h, timeout=8.0, scope="target")
                size_pct = abs(resp.size - base_size) / max(base_size, 1) * 100
                reflected = canary in (resp.body or "")
                if resp.code != base_code or size_pct > 5 or reflected:
                    interesting.append({"param":param,"canary":canary,"code":resp.code,
                        "size":resp.size,"base_size":base_size,"pct":f"{size_pct:.1f}%",
                        "reflected":reflected,"status_change":resp.code != base_code})
            except: pass
    test_params = list(params)[:40]
    if _RICH:
        c = Console()
        with Progress(SpinnerColumn(),TextColumn("[bold blue]{task.description}"),BarColumn(),
                      MofNCompleteColumn(),TimeElapsedColumn(),console=c,transient=True) as prog:
            task = prog.add_task("Fuzzing...", total=len(test_params))
            for coro in asyncio.as_completed([_fuzz(p) for p in test_params]):
                await coro; prog.update(task, advance=1)
    else:
        await asyncio.gather(*[_fuzz(p) for p in test_params])
    if interesting:
        _p(f"  [yellow]⚠[/yellow]  {len(interesting)} anomalous params:")
        for i in interesting[:10]:
            tags = []
            if i["reflected"]: tags.append("REFLECTED")
            if i["status_change"]: tags.append(f"STATUS:{i['code']}")
            if not tags: tags.append(f"{i['pct']} variance")
            _p(f"    {i['param']}: {' '.join(tags)} ({i['size']}B vs {i['base_size']}B)")
    return interesting

async def execute(ctx, engine, config):
    console = Console() if _RICH else None
    def _p(m): (console.print if console else lambda x: print(__import__('re').sub(r'\[/?[^\]]*\]','',x)))(m)
    domain, url = ctx.domain, ctx.url
    ws = getattr(config,'workspace','.') or '.'
    existing = ctx.params.copy()
    _p(f"  [bold]Parameter discovery ({len(existing)} existing)[/bold]")
    new_params, new_urls = set(), set()
    # Tool discovery
    arjun_out = os.path.join(ws,"enum","arjun.txt"); os.makedirs(os.path.dirname(arjun_out),exist_ok=True)
    ps_out = os.path.join(ws,"enum","paramspider.txt")
    tasks = {"arjun":_arjun(url, arjun_out), "paramspider":_paramspider(domain, ps_out)}
    names, coros = list(tasks.keys()), list(tasks.values())
    if _RICH and console:
        with Progress(SpinnerColumn(),TextColumn("[bold blue]{task.description}"),TimeElapsedColumn(),console=console,transient=True) as prog:
            prog.add_task("Param tools...",total=None); results = await asyncio.gather(*coros, return_exceptions=True)
    else: results = await asyncio.gather(*coros, return_exceptions=True)
    for name, result in zip(names, results):
        if isinstance(result, Exception): _p(f"  [red]✗[/red]  {name}: {result}"); continue
        if name == "arjun":
            params, err = result
            _p(f"  [{'yellow' if err else 'green'}]{'⚠' if err else '✓'}[/]  arjun: {len(params)}" + (f" — {err}" if err else ""))
            new_params.update(params)
        elif name == "paramspider":
            params, urls, err = result
            _p(f"  [{'yellow' if err else 'green'}]{'⚠' if err else '✓'}[/]  paramspider: {len(params)} params, {len(urls)} URLs" + (f" — {err}" if err else ""))
            new_params.update(params); new_urls.update(urls)
    truly_new = new_params - existing
    if truly_new: ctx.bulk_insert_params(list(truly_new), source="param_tools")
    if new_urls: ctx.add_urls_bulk(list(new_urls), source="paramspider")
    _p(f"  [green]✓[/green]  {len(truly_new)} new params added")
    # GF classification
    urls_file = os.path.join(ws,"enum","all_urls.txt")
    if _has("gf") and os.path.exists(urls_file):
        _p(f"\n  [cyan]→[/cyan]  GF pattern classification")
        gf_results = await _gf_classify(urls_file, ws)
        for pat, matches in gf_results.items():
            _p(f"  [yellow]⚠[/yellow]  gf {pat}: {len(matches)} candidates")
            for u in matches:
                for p in re.findall(r'[?&]([a-zA-Z0-9_]+)=', u): ctx.tag_param_gf(p, [pat])
    # Auto-categorize from payload_registry if gf not available
    elif hasattr(ctx, 'payload_registry') and 'gf_patterns' in getattr(ctx, 'payload_registry', {}):
        _p(f"  [cyan]→[/cyan]  Auto-categorize from payload registry")
        gf_data = ctx.payload_registry['gf_patterns']
        all_p = ctx.params
        for vtype, info in gf_data.items():
            if isinstance(info, dict) and 'params' in info:
                hits = [p for p in all_p if p.lower() in [x.lower() for x in info['params']]]
                for p in hits: ctx.tag_param_gf(p, [vtype])
                if hits: _p(f"  [dim]{vtype}: {len(hits)} matches[/dim]")
    # Active heuristic fuzzer
    if engine:
        await _active_heuristic_fuzz(ctx, engine, ctx.params, _p)
    _p(f"\n  [bold]Step 7:[/bold] {len(ctx.params)} total params")
    return ctx
