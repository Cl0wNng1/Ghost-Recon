# modules/step11_backups.py
"""
GHOST RECON v2.0 — STEP 11: Backup & Artifact Discovery
Smart artifacts: .bak/.old for files, .zip/.tar.gz for dirs.
Async HEAD probes validating Content-Type (non-HTML) + Content-Length > 1024.
CeWL with zombie-proof subprocess.
"""
from __future__ import annotations
import asyncio, os, re, shutil
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 11
STEP_NAME = "Backup & Artifact Discovery"
_HEAVY_SEM = asyncio.Semaphore(3)

FILE_EXTS = [".bak",".backup",".old",".orig",".save",".swp","~",".tmp",".copy"]
ARCHIVE_EXTS = [".zip",".tar.gz",".tar",".tgz",".rar",".7z",".gz",".sql",".sql.gz",".dump"]
NON_HTML = frozenset(["application/zip","application/x-tar","application/gzip",
    "application/sql","application/octet-stream","application/x-gzip",
    "text/plain","application/json","application/xml","application/x-yaml",
    "text/x-python","text/x-php","application/x-httpd-php"])

def _has(b): return shutil.which(b) is not None

async def _cewl(url, out, timeout=120.0):
    if not _has("cewl"): return 0, "Not installed"
    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec("cewl",url,"-d","2","-m","4",
                "--lowercase","-w",out,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc: proc.kill(); await proc.wait()
                return 0, "Timed out"
            return (sum(1 for _ in open(out)) if os.path.exists(out) else 0), None
        except Exception as e:
            if proc and proc.returncode is None:
                try: proc.kill(); await proc.wait()
                except: pass
            return 0, str(e)[:80]

def _smart_artifacts(domain, dname, paths):
    """Generate .bak/.old for file-like paths, .zip/.tar.gz for dir-like paths."""
    words = set()
    bases = [dname, domain, domain.replace(".","_"), domain.replace(".","-"),
             f"{dname}_backup", f"{dname}_db"]
    # Archive candidates for common names
    for b in bases + ["backup","www","site","web","public","html","src","db","database"]:
        for ext in ARCHIVE_EXTS: words.add(f"{b}{ext}")
    # Smart: file-like paths get file exts, dir-like get archive exts
    for path in paths[:80]:
        clean = path.strip("/").split("/")[-1]
        if "." in clean:  # File-like
            name = clean.rsplit(".",1)[0]
            for ext in FILE_EXTS: words.add(f"{clean}{ext}"); words.add(f"{name}{ext}")
        else:  # Dir-like
            for ext in ARCHIVE_EXTS: words.add(f"{clean}{ext}")
    return sorted(words)

async def _head_validate(engine, url, host_hdr=""):
    """HEAD probe: non-HTML Content-Type AND Content-Length > 1024 = real backup."""
    if not engine: return False, 0, ""
    try:
        extra = {"Host": host_hdr} if host_hdr else None
        resp = await engine.request(url, method="HEAD", extra_headers=extra,
                                     timeout=8.0, scope="target")
        ct = resp.headers.get("content-type","").lower()
        try: cl = int(resp.headers.get("content-length","0"))
        except: cl = 0
        if resp.code == 200:
            is_valid = (any(t in ct for t in NON_HTML) or "text/html" not in ct) and cl > 1024
            return is_valid, cl, ct
        return False, cl, ct
    except: return False, 0, ""

async def execute(ctx, engine, config):
    console = Console() if _RICH else None
    def _p(m): (console.print if console else lambda x: print(__import__('re').sub(r'\[/?[^\]]*\]','',x)))(m)
    ws = getattr(config,'workspace','.') or '.'
    domain, dname = ctx.domain, ctx.dname
    _p(f"  [bold]Smart backup & artifact discovery[/bold]")
    existing_paths = ctx.paths_200 + ctx.paths_403
    words = _smart_artifacts(domain, dname, existing_paths)
    _p(f"  [green]✓[/green]  {len(words)} smart artifact candidates")
    # CeWL
    cewl_count = 0
    if _has("cewl"):
        _p(f"  [cyan]→[/cyan]  CeWL contextual wordlist")
        cewl_out = os.path.join(ws,"fuzz","cewl_words.txt"); os.makedirs(os.path.dirname(cewl_out),exist_ok=True)
        if _RICH and console:
            with Progress(SpinnerColumn(),TextColumn("[bold blue]{task.description}"),TimeElapsedColumn(),console=console,transient=True) as prog:
                prog.add_task("CeWL...",total=None); cewl_count, ce = await _cewl(ctx.url, cewl_out)
        else: cewl_count, ce = await _cewl(ctx.url, cewl_out)
        _p(f"  [green]✓[/green]  CeWL: {cewl_count} words" if not ce else f"  [yellow]⚠[/yellow]  CeWL: {ce}")
    if not engine:
        _p("  [yellow]⚠ No engine — saving wordlist only[/yellow]")
        try:
            os.makedirs(os.path.join(ws,"fuzz"),exist_ok=True)
            with open(os.path.join(ws,"fuzz","backup_wordlist.txt"),"w") as f: f.write("\n".join(words)+"\n")
        except: pass
        return ctx
    # HEAD-validated probing
    _p(f"\n  [cyan]→[/cyan]  HEAD-validated backup probing ({len(words)} paths)")
    sem = asyncio.Semaphore(8); found = 0
    async def _probe(path):
        nonlocal found
        async with sem:
            url = f"{ctx.probe_url()}/{path}"
            valid, cl, ct = await _head_validate(engine, url, ctx.host_header)
            if valid:
                found += 1
                sev = "HIGH" if any(e in path for e in [".sql",".env",".key",".pem","credential"]) else "MEDIUM"
                ctx.add_finding(severity=sev, category="CONTENT_DISCOVERY", url=url,
                    title=f"Backup: {path} [{cl}B {ct[:25]}]",
                    detail=f"HEAD validated: CL={cl}, CT={ct}",
                    impact="Source code or data exposure",
                    exploit=f"curl -sk '{url}' -o {path.split('/')[-1]}",
                    confidence="HIGH", cwe="CWE-530", phase="11")
                ctx.add_path(url, 200, size=cl, source="backup_scan")
    if _RICH and console:
        with Progress(SpinnerColumn(),TextColumn("[bold blue]{task.description}"),BarColumn(),
                      MofNCompleteColumn(),TimeElapsedColumn(),console=console,transient=True) as prog:
            task = prog.add_task("HEAD probing...", total=len(words))
            for coro in asyncio.as_completed([_probe(p) for p in words]):
                await coro; prog.update(task, advance=1)
    else: await asyncio.gather(*[_probe(p) for p in words])
    _p(f"  [green]✓[/green]  Backups found: {found}")
    # Save combined wordlist
    try:
        combined = os.path.join(ws,"fuzz","dynamic_wordlist.txt"); all_w = set(words)
        cp = os.path.join(ws,"fuzz","cewl_words.txt")
        if os.path.exists(cp): all_w.update(l.strip() for l in open(cp) if l.strip())
        with open(combined,"w") as f: f.write("\n".join(sorted(all_w))+"\n")
        _p(f"  [green]✓[/green]  Dynamic wordlist: {len(all_w)} entries")
    except: pass
    _p(f"\n  [bold]Step 11:[/bold] {found} backups, {cewl_count} CeWL words")
    return ctx
