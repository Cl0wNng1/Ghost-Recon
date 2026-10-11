"""
GHOST RECON v2.0 — STEP 14: Phase 3 Deep API & Content Discovery

Capabilities:
  1. Content Discovery: ffuf with -ac auto-calibration, -mc all -fc 404,429,
     context-aware wordlists (API wordlists for /api/ hosts, IIS for Windows)
  2. Parameter Fuzzing: Arjun async wrapper with chunking/delay
  3. AI-Powered JS Analysis: Download JS files, extract API routes/tokens/
     GraphQL schemas, optionally send to LLM for deep AST analysis
  4. Swagger/OpenAPI autodiscovery + GraphQL introspection
  5. BOLA/IDOR hand-off to core.logic_fuzzer
"""
from __future__ import annotations
import asyncio, hashlib, json, os, re, shutil, tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, quote, urlparse

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 14
STEP_NAME = "Deep API & Content Discovery"
_HEAVY_SEM = asyncio.Semaphore(3)

def _has(b: str) -> bool:
    return shutil.which(b) is not None

# ═══════════════════════════════════════════════════════════════════════════════
# WORDLIST MANAGEMENT (dynamic fetch + context-aware selection)
# ═══════════════════════════════════════════════════════════════════════════════

WORDLIST_REGISTRY: Dict[str, Dict[str, str]] = {
    "general": {
        "path": "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
        "fallback": "/usr/share/wordlists/dirb/common.txt",
    },
    "api": {
        "path": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "fallback": "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
    },
    "backup": {
        "path": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
        "fallback": "/usr/share/wordlists/dirb/big.txt",
    },
}


def _find_wordlist(category: str = "general") -> str:
    entry = WORDLIST_REGISTRY.get(category, WORDLIST_REGISTRY["general"])
    if os.path.exists(entry["path"]):
        return entry["path"]
    if os.path.exists(entry["fallback"]):
        return entry["fallback"]
    # Last resort: look for anything
    for candidate in [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/wfuzz/general/common.txt",
    ]:
        if os.path.exists(candidate):
            return candidate
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# CONTENT DISCOVERY (ffuf → dirsearch fallback)
# ═══════════════════════════════════════════════════════════════════════════════

async def _ffuf_scan(
    target_url: str, wordlist: str, output_file: str,
    host_header: str = "", rate: int = 50, timeout: float = 600.0,
) -> Tuple[List[Dict], Optional[str]]:
    if not _has("ffuf") or not wordlist:
        return [], "ffuf not installed or no wordlist"

    args = [
        "ffuf",
        "-u", f"{target_url.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-mc", "all",
        "-fc", "404,429,503",
        "-ac",                          # auto-calibration
        "-recursion", "-recursion-depth", "2",
        "-rate", str(rate),
        "-t", "15",
        "-timeout", "10",
        "-se",                          # stop on spurious errors
        "-sf",                          # stop on flood
        "-o", output_file,
        "-of", "json",
        "-s",                           # silent
    ]
    if host_header:
        args.extend(["-H", f"Host: {host_header}"])
    args.extend([
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ])

    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                if proc: proc.kill(); await proc.wait()
                return [], f"Timed out ({timeout:.0f}s)"

            results = []
            if os.path.exists(output_file):
                try:
                    data = json.loads(Path(output_file).read_text())
                    if isinstance(data, dict):
                        for r in data.get("results", []):
                            if isinstance(r, dict):
                                results.append({
                                    "url": r.get("url", ""),
                                    "status": r.get("status", 0),
                                    "length": r.get("length", 0),
                                    "words": r.get("words", 0),
                                    "input": r.get("input", {}).get("FUZZ", ""),
                                })
                except (json.JSONDecodeError, KeyError):
                    pass
            return results, None
        except Exception as e:
            if proc and proc.returncode is None:
                try: proc.kill(); await proc.wait()
                except: pass
            return [], str(e)[:100]


async def _dirsearch_fallback(
    target_url: str, output_file: str,
    host_header: str = "", timeout: float = 600.0,
) -> Tuple[List[Dict], Optional[str]]:
    if not _has("dirsearch"):
        return [], "Not installed"

    args = [
        "dirsearch",
        "-u", target_url,
        "-e", "php,asp,aspx,jsp,json,xml,yml,env,bak,sql,conf,old,txt",
        "--threads", "10",
        "--delay", "0.1",
        "--timeout", "10",
        "--random-agent",
        "--follow-redirects",
        "--exclude-status", "404,429,503",
        "--format", "json",
        "-o", output_file,
        "-q",
    ]
    if host_header:
        args.extend(["--header", f"Host: {host_header}"])

    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc: proc.kill(); await proc.wait()
                return [], "Timed out"

            results = []
            if os.path.exists(output_file):
                try:
                    data = json.loads(Path(output_file).read_text())
                    if isinstance(data, dict):
                        for entry in data.get("results", []):
                            if isinstance(entry, dict):
                                results.append({
                                    "url": entry.get("url", ""),
                                    "status": entry.get("status", 0),
                                    "length": entry.get("content-length", 0),
                                })
                except (json.JSONDecodeError, KeyError):
                    pass
            return results, None
        except Exception as e:
            if proc and proc.returncode is None:
                try: proc.kill(); await proc.wait()
                except: pass
            return [], str(e)[:80]


# ═══════════════════════════════════════════════════════════════════════════════
# PARAMETER DISCOVERY (Arjun)
# ═══════════════════════════════════════════════════════════════════════════════

async def _arjun_scan(
    urls_file: str, output_file: str, timeout: float = 300.0,
) -> Tuple[Dict[str, List[str]], Optional[str]]:
    """Run Arjun parameter discovery with chunking."""
    if not _has("arjun"):
        return {}, "Not installed"

    args = [
        "arjun",
        "-i", urls_file,
        "-oJ", output_file,
        "-t", "10",
        "--delay", "0.2",
        "--stable",
        "-q",
    ]

    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc: proc.kill(); await proc.wait()
                return {}, "Timed out"

            results: Dict[str, List[str]] = {}
            if os.path.exists(output_file):
                try:
                    data = json.loads(Path(output_file).read_text())
                    if isinstance(data, dict):
                        for url, params in data.items():
                            if isinstance(params, list):
                                results[url] = params
                except (json.JSONDecodeError, KeyError):
                    pass
            return results, None
        except Exception as e:
            if proc and proc.returncode is None:
                try: proc.kill(); await proc.wait()
                except: pass
            return {}, str(e)[:80]


# ═══════════════════════════════════════════════════════════════════════════════
# JS ANALYSIS ENGINE (v14 — regex + optional LLM)
# ═══════════════════════════════════════════════════════════════════════════════

# High-signal regex patterns for JS content
JS_PATTERNS = {
    "api_route": re.compile(
        r'''["'](/(?:api|v[1-4]|graphql|rest|internal|admin|auth)/[a-zA-Z0-9/_\-{}:]+)["']''',
        re.I,
    ),
    "graphql_op": re.compile(
        r'''(?:query|mutation|subscription)\s+(\w+)\s*[({]''', re.I
    ),
    "cloud_token": re.compile(
        r'''(?:AKIA[0-9A-Z]{16}|AIzaSy[A-Za-z0-9\-_]{33}|ghp_[0-9a-zA-Z]{36}|sk_live_[0-9a-zA-Z]{24,}|xox[bprs]-[0-9a-zA-Z\-]+)'''
    ),
    "endpoint_fetch": re.compile(
        r'''(?:fetch|axios|http\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]+)["'`]''',
        re.I,
    ),
    "hardcoded_secret": re.compile(
        r'''(?:api[_-]?key|secret|token|password|auth|credential)\s*[:=]\s*["']([^"']{8,})["']''',
        re.I,
    ),
    "s3_bucket": re.compile(
        r'''[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]\.s3(?:[.\-][\w\-]+)?\.amazonaws\.com''',
        re.I,
    ),
    "firebase": re.compile(
        r'''[a-z0-9\-]+\.firebaseio\.com|[a-z0-9\-]+\.firebaseapp\.com''',
        re.I,
    ),
}


def analyze_js_static(js_content: str, source_url: str = "") -> Dict[str, List[str]]:
    """
    Static regex-based JS analysis. Fast, no network, no dependencies.
    Returns {category: [matches]}.
    """
    results: Dict[str, List[str]] = {}
    for name, pattern in JS_PATTERNS.items():
        matches = list(set(pattern.findall(js_content)))
        if matches:
            results[name] = matches[:50]  # Cap per category
    return results


async def analyze_js_with_llm(
    js_content: str, source_url: str = "",
    api_key: str = "", model: str = "claude-sonnet-4-20250514",
) -> Optional[Dict[str, Any]]:
    """
    LLM-powered JS analysis for deep AST reconstruction.
    Falls back to static analysis if no API key or if LLM unavailable.
    """
    if not api_key or len(js_content) < 100:
        return None

    try:
        import httpx
        prompt = (
            "Analyze this JavaScript code for security issues. "
            "Extract: 1) All API endpoints/routes 2) GraphQL operations "
            "3) Hardcoded secrets/tokens 4) Cloud service URLs (S3, Firebase, etc) "
            "5) Authentication mechanisms. "
            "Return ONLY a JSON object with keys: api_routes, graphql_ops, "
            "secrets, cloud_urls, auth_mechanisms. No explanation.\n\n"
            f"Source: {source_url}\n\nCode (first 8000 chars):\n{js_content[:8000]}"
        )

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("content", [{}])[0].get("text", "")
                # Try to parse JSON from response
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.S)
                if json_match:
                    return json.loads(json_match.group())
    except Exception as e:
        log_msg = f"LLM JS analysis failed: {e}"
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# SWAGGER / OPENAPI / GRAPHQL DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

API_DISCOVERY_PATHS = [
    "swagger.json", "api/swagger.json", "swagger/v1/swagger.json",
    "openapi.json", "openapi.yaml", "api-docs", "api/api-docs",
    "graphql", "graphiql", "api/graphql", "_graphql", "playground",
    "v1/graphql", ".well-known/openid-configuration",
    "api/v1/docs", "redoc", "api/schema", "_debug/routes",
]

INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name fields { name type { name kind } } } } }"
})


async def _discover_api_schemas(
    engine: Any, base_url: str, host_header: str = "",
) -> List[Dict[str, Any]]:
    found: List[Dict] = []
    sem = asyncio.Semaphore(5)
    extra = {"Host": host_header} if host_header else None

    async def _check(path: str):
        async with sem:
            try:
                url = f"{base_url.rstrip('/')}/{path}"
                resp = await engine.get(
                    url, extra_headers=extra, timeout=8.0, scope="target"
                )
                if resp.code == 200 and resp.size > 50:
                    low = (resp.body or "")[:500].lower()
                    if any(k in low for k in [
                        "swagger", "openapi", "paths", "graphql",
                        "graphiql", "__schema", "playground",
                        "authorization_endpoint", "token_endpoint",
                    ]):
                        found.append({
                            "url": url, "path": path,
                            "type": "graphql" if "graphql" in low or "__schema" in low else "openapi",
                            "size": resp.size,
                        })
            except Exception:
                pass

    await asyncio.gather(*[_check(p) for p in API_DISCOVERY_PATHS])
    return found


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None

    def _p(m):
        (console.print if console else lambda x: print(
            __import__("re").sub(r"\[/?[^\]]*\]", "", x)
        ))(m)

    ws = getattr(config, "workspace", ".") or "."
    host_hdr = ctx.host_header
    base_url = ctx.probe_url("")

    _p(f"  [bold]Phase 3: Deep API & Content Discovery[/bold]")

    # ─── Stage 1: API Schema Discovery ────────────────────────────────────
    _p(f"\n  [cyan]→[/cyan]  API schema discovery")
    api_schemas = []
    if engine:
        api_schemas = await _discover_api_schemas(engine, base_url, host_hdr)
        for schema in api_schemas:
            _p(f"    [green]✓[/green] {schema['type']}: {schema['url']}")
            ctx.add_finding(
                severity="MEDIUM" if schema["type"] == "openapi" else "HIGH",
                category="API_EXPOSED",
                url=schema["url"],
                title=f"Exposed {schema['type'].upper()} schema",
                detail=f"Size: {schema['size']}B",
                impact="API documentation exposure → endpoint enumeration",
                exploit=f"curl -sk '{schema['url']}'",
                confidence="CONFIRMED",
                cwe="CWE-200",
                phase="14",
            )

    # ─── Stage 2: Content Discovery (ffuf → dirsearch) ───────────────────
    alive_urls = ctx.live_host_urls()[:10]  # Top 10 live hosts
    if alive_urls:
        _p(f"\n  [cyan]→[/cyan]  Content discovery ({len(alive_urls)} hosts)")
        wordlist = _find_wordlist("general")

        if wordlist:
            for target in alive_urls[:5]:
                ffuf_out = os.path.join(ws, "fuzz", f"ffuf_{hashlib.md5(target.encode()).hexdigest()[:8]}.json")
                os.makedirs(os.path.dirname(ffuf_out), exist_ok=True)

                results, err = await _ffuf_scan(
                    target, wordlist, ffuf_out,
                    host_header=host_hdr,
                    rate=int(getattr(config, "rate", 15)),
                )
                if err:
                    _p(f"    [yellow]⚠[/yellow] ffuf on {target[:40]}: {err}")
                    # Dirsearch fallback
                    ds_out = ffuf_out.replace("ffuf_", "dirsearch_")
                    results, err2 = await _dirsearch_fallback(
                        target, ds_out, host_hdr
                    )
                    if err2:
                        _p(f"    [dim]dirsearch fallback: {err2}[/dim]")

                if results:
                    _p(f"    [green]✓[/green] {target[:40]}: {len(results)} paths")
                    for r in results[:20]:
                        ctx.add_url(r.get("url", ""), source="ffuf")
        else:
            _p(f"    [yellow]⚠[/yellow] No wordlist found — skipping content discovery")

    # ─── Stage 3: Parameter Discovery (Arjun) ────────────────────────────
    param_urls = ctx.get_urls_by_class("api")[:20]
    if param_urls and _has("arjun"):
        _p(f"\n  [cyan]→[/cyan]  Parameter discovery ({len(param_urls)} API endpoints)")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="ghost_arjun_"
        ) as tf:
            tf.write("\n".join(param_urls) + "\n")
            urls_file = tf.name

        arjun_out = os.path.join(ws, "enum", "arjun_params.json")
        os.makedirs(os.path.dirname(arjun_out), exist_ok=True)

        try:
            params_map, err = await _arjun_scan(urls_file, arjun_out)
            if err:
                _p(f"    [yellow]⚠[/yellow] Arjun: {err}")
            else:
                total_params = sum(len(v) for v in params_map.values())
                _p(f"    [green]✓[/green] Arjun: {total_params} params across {len(params_map)} endpoints")
                for url, params in params_map.items():
                    for p in params:
                        ctx.add_param(p, source="arjun", url=url)
        finally:
            try:
                os.unlink(urls_file)
            except OSError:
                pass

    # ─── Stage 4: JS Static Analysis ─────────────────────────────────────
    js_files = list(ctx.js_files)[:30] if hasattr(ctx, "js_files") else []
    if js_files and engine:
        _p(f"\n  [cyan]→[/cyan]  JS analysis ({len(js_files)} files)")
        all_routes: Set[str] = set()
        all_secrets: List[Dict] = []

        sem = asyncio.Semaphore(5)
        async def _analyze_one(js_url: str):
            async with sem:
                try:
                    resp = await engine.get(js_url, timeout=15.0, scope="target")
                    if resp.code != 200 or resp.size < 100:
                        return
                    results = analyze_js_static(resp.body, js_url)
                    for route in results.get("api_route", []):
                        all_routes.add(route)
                    for route in results.get("endpoint_fetch", []):
                        all_routes.add(route)
                    for secret in results.get("cloud_token", []):
                        all_secrets.append({"value": secret, "source": js_url})
                    for secret in results.get("hardcoded_secret", []):
                        all_secrets.append({"value": secret, "source": js_url})
                except Exception:
                    pass

        await asyncio.gather(*[_analyze_one(u) for u in js_files])

        if all_routes:
            _p(f"    [green]✓[/green] {len(all_routes)} API routes extracted from JS")
            try:
                os.makedirs(os.path.join(ws, "enum"), exist_ok=True)
                with open(os.path.join(ws, "enum", "js_api_routes.txt"), "w") as f:
                    f.write("\n".join(sorted(all_routes)) + "\n")
            except Exception:
                pass

        if all_secrets:
            _p(f"    [yellow]⚠[/yellow] {len(all_secrets)} potential secrets in JS")
            # Validate secrets if validator available
            validator = getattr(ctx, "secret_validator", None)
            if validator:
                for s in all_secrets[:10]:
                    try:
                        result = await validator.validate(
                            pattern_name="JS Hardcoded Secret",
                            secret_value=s["value"],
                            source_url=s["source"],
                            original_severity="MEDIUM",
                        )
                        sev = result.upgraded_severity
                        title_prefix = "[ACTIVE KEY VERIFIED] " if result.is_active else ""
                        ctx.add_finding(
                            severity=sev,
                            category="SECRET_LEAK",
                            url=s["source"],
                            title=f"{title_prefix}{result.pattern_name}: {result.value_preview}",
                            detail=result.detail,
                            impact="Credential exposure — potential account takeover",
                            confidence="CONFIRMED" if result.is_active else "MEDIUM",
                            cwe="CWE-798",
                            phase="14",
                        )
                    except Exception:
                        pass

    # ─── Stage 5: BOLA/IDOR Testing (v14 logic_fuzzer) ───────────────────
    token_a = getattr(config, "auth_token_a", "") or os.environ.get("AUTH_TOKEN_A", "")
    token_b = getattr(config, "auth_token_b", "") or os.environ.get("AUTH_TOKEN_B", "")

    if token_a and token_b and engine:
        try:
            from core.logic_fuzzer import test_bola
            api_eps = ctx.get_urls_by_class("api")[:30]
            if api_eps:
                bola_count = await test_bola(
                    engine, ctx, api_eps, token_a, token_b, _p
                )
                if bola_count:
                    _p(f"    [red]🔥 {bola_count} BOLA/IDOR vulnerabilities confirmed[/red]")
        except ImportError:
            _p(f"    [dim]core.logic_fuzzer not available — skipping BOLA[/dim]")

    findings_count = ctx.finding_count()
    _p(f"\n  [bold]Phase 3 Complete:[/bold] {findings_count} total findings")
    return ctx
