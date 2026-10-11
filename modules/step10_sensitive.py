# modules/step10_sensitive.py
"""
GHOST RECON v2.0 — STEP 10: Sensitive Data Discovery
Google dorking, GitHub intel, cloud bucket hunting, URLScan deep dorking.
"""
from __future__ import annotations
import asyncio, json, os, re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 10
STEP_NAME = "Sensitive Data Discovery"

GITHUB_DORKS = [
    "password", "api_key", "secret", "token", "db_password",
    "database_url", "aws_access_key", "BEGIN PRIVATE KEY",
    "smtp", ".env", "Authorization: Bearer", "client_secret",
]

BUCKET_PATTERNS = [
    "{domain}.s3.amazonaws.com", "{dname}.s3.amazonaws.com",
    "{dname}-backup.s3.amazonaws.com", "{dname}-dev.s3.amazonaws.com",
    "{dname}-staging.s3.amazonaws.com", "{dname}-prod.s3.amazonaws.com",
    "{dname}-assets.s3.amazonaws.com", "{dname}-uploads.s3.amazonaws.com",
    "{dname}.storage.googleapis.com", "{dname}-backup.storage.googleapis.com",
    "{dname}.blob.core.windows.net", "{dname}-dev.blob.core.windows.net",
]


async def _github_search(root_domain: str, github_token: str, engine: Any) -> List[Tuple[str, str, str]]:
    if not github_token or engine is None:
        return []
    findings: List[Tuple[str, str, str]] = []
    headers = {"Authorization": f"token {github_token}", "Accept": "application/vnd.github.v3+json"}

    for dork in GITHUB_DORKS[:8]:
        try:
            q = quote(f'"{root_domain}" {dork}')
            resp = await engine.get(
                f"https://api.github.com/search/code?q={q}&per_page=10",
                extra_headers=headers, timeout=12.0, scope="github")
            if resp.code == 200 and resp.body:
                data = json.loads(resp.body)
                for item in data.get("items", [])[:3]:
                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    html_url = item.get("html_url", "")
                    if repo:
                        findings.append((dork, repo, html_url))
            elif resp.code == 403:
                break
            await asyncio.sleep(2.0)
        except Exception:
            continue
    return findings


async def _bucket_check(domain: str, dname: str, engine: Any) -> List[Tuple[str, str]]:
    if engine is None:
        return []
    found: List[Tuple[str, str]] = []
    sem = asyncio.Semaphore(5)

    async def _check(bucket_url: str):
        async with sem:
            try:
                resp = await engine.get(f"https://{bucket_url}", timeout=8.0, scope="buckets")
                if resp.code in (200, 403):
                    status = "PUBLIC" if resp.code == 200 else "EXISTS"
                    found.append((bucket_url, status))
            except Exception:
                pass

    urls = [p.format(domain=domain, dname=dname) for p in BUCKET_PATTERNS]
    await asyncio.gather(*[_check(u) for u in urls])
    return found


_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}=.+$", re.M)


def _content_proves(path: str, body: str) -> bool:
    """Signature check for tiny sensitive files that a size threshold misses."""
    head = body[:2048]
    if path == ".git/HEAD":
        return head.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-f]{40}\s*", head))
    if path == ".env":
        return "<html" not in head.lower() and len(_ENV_LINE.findall(head)) >= 1
    return False


async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None
    def _p(m):
        (console.print if console else lambda x: print(__import__('re').sub(r'\[/?[^\]]*\]','',x)))(m)

    if not getattr(config, 'osint', False):
        _p("  [dim]OSINT disabled (use --osint to enable GitHub/bucket scanning)[/dim]")
        # Still do basic URLScan
        pass

    ws = getattr(config, 'workspace', '.') or '.'
    github_token = getattr(config, 'github_token', '') or os.environ.get("GITHUB_TOKEN", "")
    root_domain = ctx.root_domain
    dname = ctx.dname

    _p(f"  [bold]Sensitive data discovery for {root_domain}[/bold]")
    tasks = {}

    # GitHub search
    if github_token and getattr(config, 'osint', False):
        tasks["github"] = _github_search(root_domain, github_token, engine)

    # Cloud bucket hunting
    if engine and getattr(config, 'osint', False):
        tasks["buckets"] = _bucket_check(root_domain, dname, engine)

    if tasks:
        task_names = list(tasks.keys())
        if _RICH and console:
            with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), TimeElapsedColumn(),
                          console=console, transient=True) as prog:
                prog.add_task("OSINT scanning...", total=None)
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        else:
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, result in zip(task_names, results):
            if isinstance(result, Exception):
                _p(f"  [red]✗[/red]  {name}: {result}")
                continue

            if name == "github" and isinstance(result, list):
                _p(f"  [green]✓[/green]  GitHub: {len(result)} matches")
                for dork, repo, url in result[:10]:
                    _p(f"    [yellow]⚠[/yellow]  '{dork}' in {repo}")
                    ctx.add_finding(severity="MEDIUM", category="SECRET_LEAK",
                                    url=url or f"https://github.com/{repo}",
                                    title=f"GitHub leak: '{dork}' in {repo}",
                                    detail=f"Dork: {dork}, Repo: {repo}",
                                    impact="Credential exposure via public repository",
                                    confidence="MEDIUM", cwe="CWE-798", phase="10")
                try:
                    with open(os.path.join(ws, "osint", "github_dorks.txt"), "w") as f:
                        for dork, repo, url in result:
                            f.write(f"{dork}|{repo}|{url}\n")
                except Exception:
                    pass

            elif name == "buckets" and isinstance(result, list):
                _p(f"  [green]✓[/green]  Buckets: {len(result)} found")
                for bucket, status in result:
                    sev = "HIGH" if status == "PUBLIC" else "LOW"
                    _p(f"    [{'red' if status=='PUBLIC' else 'yellow'}]{status}[/] {bucket}")
                    ctx.add_finding(severity=sev, category="CLOUD_SERVICE_LEAK", url=bucket,
                                    title=f"Cloud bucket {status}: {bucket}",
                                    detail=f"Bucket responds with HTTP {'200 (public)' if status=='PUBLIC' else '403 (exists)'}",
                                    impact="Data exposure" if status == "PUBLIC" else "Bucket exists, may be misconfigured",
                                    exploit=f"aws s3 ls s3://{bucket.split('.')[0]} --no-sign-request",
                                    confidence="CONFIRMED" if status == "PUBLIC" else "LOW",
                                    cwe="CWE-200", phase="10")

    # Subdomain-level sensitive file scan
    live_urls = ctx.live_host_urls()[:15]
    if live_urls and engine:
        _p(f"\n  [cyan]→[/cyan]  Sensitive file scan on {len(live_urls)} live hosts")
        SENSITIVE_PATHS = [".env", ".git/HEAD", "actuator/env", "swagger.json",
                           "phpinfo.php", "server-status", ".DS_Store", "debug",
                           "wp-config.php.bak", "config.json"]
        sem = asyncio.Semaphore(5)
        sub_finds = 0

        async def _probe_sub(base_url: str, path: str):
            nonlocal sub_finds
            async with sem:
                try:
                    url = f"{base_url.rstrip('/')}/{path}"
                    resp = await engine.get(url, timeout=8.0, scope="target")
                    # v2.0: small-but-real files (.git/HEAD is ~21 bytes, a
                    # short .env ~40) were dropped by the old size>50 cut-off.
                    if resp.code == 200 and (resp.size > 50 or _content_proves(path, resp.body or "")):
                        low = (resp.body or "")[:300].lower()
                        if any(k in low for k in ["404","not found","access denied"]):
                            return
                        sev = "CRITICAL" if any(k in path for k in ['.env','.git','key','credential']) else "HIGH"
                        ctx.add_finding(severity=sev, category="SUB_EXPOSED", url=url,
                                        title=f"{path} on {base_url}", detail=f"HTTP 200, {resp.size}B",
                                        impact="Sensitive file exposure",
                                        exploit=f"curl -sk '{url}'",
                                        confidence="HIGH", cwe="CWE-538", phase="10")
                        sub_finds += 1
                except Exception:
                    pass

        probe_tasks = [_probe_sub(u, p) for u in live_urls for p in SENSITIVE_PATHS]
        if _RICH and console:
            with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), TimeElapsedColumn(),
                          console=console, transient=True) as prog:
                prog.add_task(f"Probing {len(probe_tasks)} paths...", total=None)
                await asyncio.gather(*probe_tasks)
        else:
            await asyncio.gather(*probe_tasks)
        _p(f"  [green]✓[/green]  Sensitive files: {sub_finds} exposed")

    _p(f"\n  [bold]Step 10 Summary:[/bold] {ctx.finding_count()} total findings")
    return ctx
