# modules/step06_secrets.py
"""
GHOST RECON v2.0 — STEP 6: Secret Discovery
Scan HTML responses, headers, and known paths for secrets across all live hosts.
"""
from __future__ import annotations
import asyncio, json, math, os, re
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 6
STEP_NAME = "Secret Discovery"

SECRET_PATTERNS = {
    "AWS Access Key":     (r'AKIA[0-9A-Z]{16}', "CRITICAL", "CWE-798"),
    "AWS Secret Key":     (r'(?:aws_secret|secret_key|AWS_SECRET)["\':\s=]+[A-Za-z0-9/+=]{40}', "CRITICAL", "CWE-798"),
    "GCP Service Key":    (r'"type":\s*"service_account"', "CRITICAL", "CWE-798"),
    "OpenAI API Key":     (r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}', "CRITICAL", "CWE-798"),
    "OpenAI Key v2":      (r'sk-proj-[A-Za-z0-9_-]{40,}', "CRITICAL", "CWE-798"),
    "Anthropic Key":      (r'sk-ant-[A-Za-z0-9_-]{80,}', "CRITICAL", "CWE-798"),
    "Stripe Live Key":    (r'sk_live_[0-9a-zA-Z]{24,}', "CRITICAL", "CWE-798"),
    "Slack Token":        (r'xox[baprs]-[0-9a-zA-Z-]{10,}', "HIGH", "CWE-798"),
    "Discord Webhook":    (r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', "HIGH", "CWE-798"),
    "GitHub Token":       (r'gh[pousr]_[A-Za-z0-9_]{36,}', "HIGH", "CWE-798"),
    "GitLab Token":       (r'glpat-[A-Za-z0-9\-]{20,}', "HIGH", "CWE-798"),
    "NPM Token":          (r'npm_[A-Za-z0-9]{36}', "CRITICAL", "CWE-798"),
    "SendGrid Key":       (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', "CRITICAL", "CWE-798"),
    "Twilio SID":         (r'AC[a-z0-9]{32}', "HIGH", "CWE-798"),
    "Mailgun Key":        (r'key-[0-9a-zA-Z]{32}', "HIGH", "CWE-798"),
    "Private Key":        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "CRITICAL", "CWE-321"),
    "Database URL":       (r'(?:postgres|mysql|mongodb|redis|amqp)://[^\s"\'<>]{10,}', "CRITICAL", "CWE-798"),
    "Google API Key":     (r'AIza[0-9A-Za-z\\-_]{35}', "MEDIUM", "CWE-798"),
    "Bearer Token":       (r'[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}', "MEDIUM", "CWE-200"),
    "Basic Auth":         (r'[Bb]asic\s+[A-Za-z0-9+/=]{20,}', "HIGH", "CWE-798"),
    "Hardcoded Cred":     (r'(?:admin|root|test|user)[:@](?:admin|root|test|password|pass123|12345)', "HIGH", "CWE-798"),
    "S3 Bucket":          (r'[a-z0-9.-]+\.s3\.amazonaws\.com|s3://[a-z0-9.-]+', "MEDIUM", "CWE-200"),
    "Firebase URL":       (r'https?://[a-z0-9-]+\.firebaseio\.com', "HIGH", "CWE-200"),
    "Shopify Token":      (r'shpat_[a-fA-F0-9]{32}', "HIGH", "CWE-798"),
    "Sentry DSN":         (r'https://[a-f0-9]{32}@(?:o\d+\.)?sentry\.io/\d+', "MEDIUM", "CWE-200"),
    "Internal IP":        (r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}', "LOW", "CWE-200"),
    "React Env Var":      (r'REACT_APP_[A-Z_]+=["\'"]?[^\s"\']{8,}', "MEDIUM", "CWE-200"),
    "Next.js Public Var": (r'NEXT_PUBLIC_[A-Z_]+=["\'"]?[^\s"\']{8,}', "MEDIUM", "CWE-200"),
}

_compiled = {name: (re.compile(pat), sev, cwe) for name, (pat, sev, cwe) in SECRET_PATTERNS.items()}

HIGH_VALUE_PATHS = [
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/HEAD", ".git/config", ".aws/credentials",
    "config.json", "config.yml", "settings.json", "secrets.json",
    "wp-config.php.bak", "web.config.bak", "application.properties",
    "firebase.json", "credentials.json",
]

def _entropy(s: str) -> float:
    if not s: return 0.0
    c = Counter(s)
    ln = len(s)
    return -sum((n/ln)*math.log2(n/ln) for n in c.values())


async def _scan_url(engine: Any, url: str, ctx: Any) -> List[Tuple[str, str, str, str]]:
    found: List[Tuple[str, str, str, str]] = []
    try:
        resp = await engine.get(url, timeout=10.0, scope="target")
        if resp.code != 200 or not resp.body:
            return found
        body = resp.body
        # Scan body for secret patterns
        for name, (pat, sev, cwe) in _compiled.items():
            for m in pat.finditer(body[:50000]):
                val = m.group()[:80]
                if sev in ("CRITICAL", "HIGH") or _entropy(val) > 3.5:
                    found.append((name, val, sev, url))
        # Scan headers
        header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        for name, (pat, sev, cwe) in _compiled.items():
            for m in pat.finditer(header_text):
                val = m.group()[:80]
                found.append((name, val, sev, url))
    except Exception:
        pass
    return found


async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None
    def _p(m):
        (console.print if console else lambda x: print(__import__('re').sub(r'\[/?[^\]]*\]','',x)))(m)

    if engine is None:
        _p("  [yellow]⚠ No HTTP engine — secret scanning requires ghost_core[/yellow]")
        return ctx

    live_urls = ctx.live_host_urls()
    if not live_urls:
        live_urls = [ctx.url]

    _p(f"  [bold]Scanning {len(live_urls)} hosts for secrets[/bold]")

    all_secrets: List[Tuple[str, str, str, str]] = []
    sem = asyncio.Semaphore(8)

    # Layer 1: Scan index pages of all live hosts
    async def _scan_host(host_url: str):
        async with sem:
            return await _scan_url(engine, host_url, ctx)

    _p(f"\n  [cyan]→[/cyan]  Layer 1: Index page scanning ({len(live_urls)} hosts)")
    if _RICH and console:
        with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                      BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                      console=console, transient=True) as prog:
            task = prog.add_task("Scanning index pages...", total=len(live_urls))
            for coro in asyncio.as_completed([_scan_host(u) for u in live_urls]):
                secrets = await coro
                all_secrets.extend(secrets)
                prog.update(task, advance=1)
    else:
        results = await asyncio.gather(*[_scan_host(u) for u in live_urls], return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_secrets.extend(r)

    _p(f"  [green]✓[/green]  Layer 1: {len(all_secrets)} secrets from index pages")

    # Layer 2: Probe high-value paths on primary target + top subdomains
    scan_bases = [ctx.url] + live_urls[:10]
    scan_bases = list(dict.fromkeys(scan_bases))  # dedup preserving order

    _p(f"  [cyan]→[/cyan]  Layer 2: High-value path probing ({len(scan_bases)} hosts × {len(HIGH_VALUE_PATHS)} paths)")
    path_tasks = []
    for base in scan_bases:
        base_clean = base.rstrip("/")
        for path in HIGH_VALUE_PATHS:
            path_tasks.append(f"{base_clean}/{path}")

    async def _probe_path(url: str):
        async with sem:
            return await _scan_url(engine, url, ctx)

    if _RICH and console:
        with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                      BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                      console=console, transient=True) as prog:
            task = prog.add_task("Probing sensitive paths...", total=len(path_tasks))
            for coro in asyncio.as_completed([_probe_path(u) for u in path_tasks]):
                secrets = await coro
                all_secrets.extend(secrets)
                prog.update(task, advance=1)
    else:
        results = await asyncio.gather(*[_probe_path(u) for u in path_tasks], return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_secrets.extend(r)

    _p(f"  [green]✓[/green]  Layer 2: {len(all_secrets)} total secrets (cumulative)")

    # Deduplicate by (pattern_name, value_prefix, source_url)
    seen: Set[str] = set()
    unique_secrets: List[Tuple[str, str, str, str]] = []
    for name, val, sev, url in all_secrets:
        key = f"{name}|{val[:30]}|{url}"
        if key not in seen:
            seen.add(key)
            unique_secrets.append((name, val, sev, url))

    # Ingest
    for name, val, sev, source_url in unique_secrets:
        cwe = _compiled[name][2] if name in _compiled else "CWE-798"
        ctx.add_secret(name, val, source_url=source_url, source_type="response",
                       severity=sev, cwe=cwe)
        ctx.add_finding(severity=sev, category="SECRET_LEAK", url=source_url,
                        title=f"{name} exposed", detail=f"Match in {urlparse(source_url).path}",
                        impact="Credential exposure, unauthorized API access",
                        confidence="HIGH", cwe=cwe, phase="6")

    if unique_secrets:
        _p(f"\n  [red]🔑 {len(unique_secrets)} unique secrets discovered:[/red]")
        sev_counts = Counter(s[2] for s in unique_secrets)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in sev_counts:
                _p(f"    {sev}: {sev_counts[sev]}")

    ws = getattr(config, 'workspace', '.')
    try:
        if unique_secrets:
            with open(os.path.join(ws, "secrets", "all_secrets.txt"), "w") as f:
                for name, val, sev, src in unique_secrets:
                    f.write(f"{sev}|{name}|{val[:40]}|{src}\n")
    except Exception:
        pass

    _p(f"\n  [bold]Step 6 Summary:[/bold] {len(unique_secrets)} secrets across {len(scan_bases)} hosts")
    return ctx
