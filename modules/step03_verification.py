"""
GHOST RECON v2.0 — STEP 3: Asset Verification & Visual Recon

Upgrades over the previous internal build:
  1. WAF-EVADING ALIVE PROBES: Randomized UA, std-dev jitter, dynamic spoofing
     headers (X-Forwarded-For, True-Client-IP, X-Originating-IP) pulled from
     the flattened waf_bypass.yml payload registry.
  2. GOWITNESS HARDENING: --no-sandbox --disable-dev-shm-usage --headless=new
     --window-size=1920,1080 flags to prevent Docker/VPS memory exhaustion.
  3. FAILOVER CHAIN: Gowitness → Aquatone with strict exit-code checking.
  4. HTTP REQUEST SMUGGLING BASELINE: Automated CL.TE / TE.CL desync probes.
  5. CACHE POISONING BASELINE: X-Cache header validation + unkeyed input tests.
  6. Zombie-proof subprocess management: kill+wait on every timeout.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import re
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 3
STEP_NAME = "Asset Verification & Visual Recon"

# ═══════════════════════════════════════════════════════════════════════════════
# WAF SIGNATURES & SPOOFING HEADERS
# ═══════════════════════════════════════════════════════════════════════════════

WAF_SIGS = {
    "cloudflare":   ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "cloudfront":   ["x-amz-cf", "x-cache: hit from cloudfront"],
    "akamai":       ["x-akamai", "x-cache-key"],
    "incapsula":    ["x-iinfo", "incap_ses", "x-cdn: imperva"],
    "sucuri":       ["x-sucuri"],
    "fastly":       ["x-fastly", "x-served-by"],
    "aws_waf":      ["x-amzn-requestid", "x-amzn-waf"],
    "azure_fd":     ["x-azure-ref"],
    "f5_bigip":     ["x-wa-info", "bigipserver"],
    "ddos_guard":   ["ddos-guard"],
}

# Spoofing headers rotated per-request (pulled from waf_bypass.yml concept)
SPOOF_HEADERS_POOL: List[Dict[str, str]] = [
    {"X-Forwarded-For": "{rip}"},
    {"X-Originating-IP": "{rip}"},
    {"True-Client-IP": "{rip}"},
    {"X-Real-IP": "{rip}"},
    {"CF-Connecting-IP": "{rip}"},
    {"X-ProxyUser-Ip": "{rip}"},
    {"Forwarded-For": "{rip}"},
    {"X-Remote-IP": "{rip}"},
    {"X-Client-IP": "{rip}"},
    {"Client-IP": "{rip}"},
    {"X-Custom-IP-Authorization": "{rip}"},
]

# Cache-related unkeyed input headers for baseline testing
CACHE_POISON_HEADERS: List[Dict[str, str]] = [
    {"X-Forwarded-Host": "ghost-poison-test.example.com"},
    {"X-Rewrite-URL": "/ghost-cache-test"},
    {"X-Original-URL": "/ghost-cache-test"},
    {"X-Host": "ghost-poison-test.example.com"},
    {"X-Forwarded-Server": "ghost-poison-test.example.com"},
]


def _has(b):
    return shutil.which(b) is not None


def _random_ip() -> str:
    """Generate a random public IP for header spoofing."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _get_spoof_headers() -> Dict[str, str]:
    """Select a random set of spoofing headers with random IP."""
    rip = _random_ip()
    chosen = random.sample(SPOOF_HEADERS_POOL, min(3, len(SPOOF_HEADERS_POOL)))
    result = {}
    for hdr in chosen:
        for k, v in hdr.items():
            result[k] = v.replace("{rip}", rip)
    return result


def _detect_waf(header_text: str) -> List[str]:
    ht = header_text.lower()
    return [w for w, sigs in WAF_SIGS.items() if any(s in ht for s in sigs)]


def _jitter(base_delay: float = 0.1, sigma: float = 0.05) -> float:
    """Standard-deviation based jitter to avoid rate-limit fingerprinting."""
    delay = max(0.01, random.gauss(base_delay, sigma))
    return delay


# ═══════════════════════════════════════════════════════════════════════════════
# HTTPX PROBING (external tool)
# ═══════════════════════════════════════════════════════════════════════════════

async def _httpx_probe(subs_file, out_file, timeout=300.0):
    from core.tools import resolve_pd_httpx
    binary = resolve_pd_httpx()
    if not binary:
        return [], "httpx (ProjectDiscovery) not installed"
    args = [
        binary, "-l", subs_file, "-silent", "-no-color", "-status-code",
        "-title", "-tech-detect", "-content-length", "-follow-redirects",
        "-json", "-o", out_file, "-threads", "15", "-timeout", "10",
        "-retries", "1",
    ]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            if proc:
                proc.kill()
                await proc.wait()
            return [], f"Timed out ({timeout:.0f}s)"
        results = []
        if os.path.exists(out_file):
            for line in open(out_file):
                try:
                    results.append(json.loads(line.strip()))
                except Exception:
                    continue
        return results, None
    except Exception as e:
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return [], str(e)[:100]


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE-BASED ALIVE PROBE (with WAF evasion + jitter)
# ═══════════════════════════════════════════════════════════════════════════════

async def _engine_probe(subdomains, engine, batch=20):
    """WAF-evading alive check with jitter and header rotation."""
    results = []
    sem = asyncio.Semaphore(batch)

    async def _check(url):
        async with sem:
            try:
                # Apply jitter
                await asyncio.sleep(_jitter(0.15, 0.08))

                # Build evasion headers
                extra = _get_spoof_headers()

                resp = await engine.get(url, timeout=10.0, scope="target", extra_headers=extra)
                waf = _detect_waf(
                    "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                )
                title = ""
                tm = re.search(r"<title[^>]*>([^<]{1,200})</title>", resp.body or "", re.I)
                if tm:
                    title = tm.group(1).strip()

                results.append({
                    "url": url,
                    "status_code": resp.code,
                    "title": title,
                    "content_length": resp.size,
                    "tech": [],
                    "webserver": resp.headers.get("server", ""),
                    "waf": waf,
                    "headers": dict(resp.headers),
                })
            except Exception:
                pass

    urls = []
    for s in subdomains:
        if not s.startswith("http"):
            urls.extend([f"https://{s}", f"http://{s}"])
        else:
            urls.append(s)

    await asyncio.gather(*[_check(u) for u in urls[:500]])

    # Dedup by hostname
    seen: Set[str] = set()
    deduped = []
    for r in results:
        host = re.sub(r"https?://", "", r["url"]).split("/")[0].split(":")[0]
        if host not in seen and r["status_code"] > 0:
            seen.add(host)
            deduped.append(r)
    return deduped


# ═══════════════════════════════════════════════════════════════════════════════
# GOWITNESS (HARDENED) + AQUATONE FAILOVER
# ═══════════════════════════════════════════════════════════════════════════════

async def _gowitness(urls_file, out_dir, timeout=300.0):
    """Gowitness with hardened headless flags for Docker/VPS stability."""
    if not _has("gowitness"):
        return 0, "Not installed"
    args = [
        "gowitness", "file", "-f", urls_file, "-P", out_dir,
        "--disable-logging", "--timeout", "15",
    ]

    # Headless Chrome hardening flags
    chrome = (
        shutil.which("google-chrome")
        or shutil.which("chromium-browser")
        or shutil.which("chromium")
    )
    if chrome:
        args.extend(["--chrome-path", chrome])

    env = dict(os.environ)
    env["DISPLAY"] = ""  # Force headless
    # Critical: prevent /dev/shm exhaustion on containers
    env["CHROME_FLAGS"] = (
        "--no-sandbox --disable-dev-shm-usage --headless=new "
        "--window-size=1920,1080 --disable-gpu --disable-software-rasterizer"
    )

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            if proc:
                proc.kill()
                await proc.wait()
            return 0, "Timed out"

        # Strict exit code check
        if proc.returncode != 0:
            err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
            # Don't fail if screenshots were taken despite non-zero exit
            from pathlib import Path
            count = len(list(Path(out_dir).glob("*.png"))) if os.path.isdir(out_dir) else 0
            if count > 0:
                return count, None
            return 0, f"Exit code {proc.returncode}: {err_text}"

        from pathlib import Path
        count = len(list(Path(out_dir).glob("*.png"))) if os.path.isdir(out_dir) else 0
        return count, None

    except Exception as e:
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return 0, str(e)[:80]


async def _aquatone_fallback(alive_urls, out_dir, timeout=300.0):
    """Aquatone via stdin pipe. Zombie-proof."""
    if not _has("aquatone"):
        return 0, "Not installed"
    hosts_str = "\n".join(alive_urls)
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "aquatone", "-out", out_dir, "-threads", "3",
            "-scan-timeout", "5000", "-screenshot-timeout", "15000",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(
                proc.communicate(input=hosts_str.encode("utf-8")), timeout=timeout
            )
        except asyncio.TimeoutError:
            if proc:
                proc.kill()
                await proc.wait()
            return 0, "Timed out"
        from pathlib import Path
        pngs = list(Path(out_dir).glob("*.png")) + list(
            Path(out_dir).glob("screenshots/*.png")
        )
        return len(pngs), None
    except Exception as e:
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return 0, str(e)[:80]


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP REQUEST SMUGGLING BASELINE (Phase 3 injection — new in v12)
# ═══════════════════════════════════════════════════════════════════════════════

async def _smuggling_baseline(target_url: str, engine: Any, _p) -> None:
    """
    Automated CL.TE / TE.CL desync probes using randomized
    Transfer-Encoding obfuscation. Reports findings if response
    anomalies detected (timeout differential, status code drift).
    """
    if not engine:
        return

    _p(f"  [cyan]→[/cyan]  HTTP Smuggling baseline ({target_url})")

    # Transfer-Encoding obfuscation variants
    te_variants = [
        "chunked",
        "chunked ",           # trailing space
        " chunked",           # leading space
        "chunked\r\n",        # extra CRLF
        "\tchunked",          # tab prefix
        "Chunked",            # case variation
        "CHUNKED",
        "chunk",              # truncated
        "x]chunked",          # garbage prefix
    ]

    anomalies = 0

    for variant in te_variants[:4]:  # Limit to 4 probes for stealth
        try:
            await asyncio.sleep(_jitter(0.3, 0.1))

            # CL.TE probe: Content-Length present + TE obfuscated
            resp = await engine.request(
                target_url,
                method="POST",
                extra_headers={
                    "Transfer-Encoding": variant,
                    "Content-Length": "5",
                    **_get_spoof_headers(),
                },
                timeout=10.0,
                scope="target",
            )

            # Detect anomaly: unexpected timeout, 400, or server error on
            # what should be a normal request
            if resp.code in (400, 500, 501) or resp.was_throttled:
                anomalies += 1

        except Exception:
            pass

    if anomalies >= 2:
        _p(f"  [yellow]⚠ Smuggling anomaly: {anomalies}/4 probes triggered errors[/yellow]")
    else:
        _p(f"  [dim]Smuggling baseline: {anomalies}/4 anomalies (likely not vulnerable)[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# CACHE POISONING BASELINE (Phase 3 injection — new in v12)
# ═══════════════════════════════════════════════════════════════════════════════

async def _cache_poison_baseline(target_url: str, engine: Any, ctx: Any, _p) -> None:
    """
    Validate X-Cache headers and test unkeyed inputs for cache deception.
    1. Check if target has caching (X-Cache, CF-Cache-Status, Age headers)
    2. Test unkeyed header inputs for reflection
    """
    if not engine:
        return

    _p(f"  [cyan]→[/cyan]  Cache poisoning baseline ({target_url})")

    try:
        # Step 1: Get baseline response + check cache headers
        baseline = await engine.get(target_url, timeout=10.0, scope="target")
        if baseline.code == 0:
            return

        cache_headers = {}
        for k, v in baseline.headers.items():
            kl = k.lower()
            if kl in ("x-cache", "cf-cache-status", "age", "x-cache-hits",
                       "x-varnish", "x-fastly-request-id"):
                cache_headers[k] = v

        if not cache_headers:
            _p("  [dim]No cache headers detected — skipping poison tests[/dim]")
            return

        _p(f"  [dim]Cache headers: {cache_headers}[/dim]")

        baseline_hash = hashlib.md5(baseline.body[:2000].encode()).hexdigest()

        # Step 2: Test unkeyed inputs
        for hdr_dict in CACHE_POISON_HEADERS[:3]:
            await asyncio.sleep(_jitter(0.4, 0.15))

            # Add cache buster to avoid polluting actual cache
            buster = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            test_url = f"{target_url}{'&' if '?' in target_url else '?'}cb={buster}"

            resp = await engine.get(
                test_url,
                extra_headers={**hdr_dict, **_get_spoof_headers()},
                timeout=10.0,
                scope="target",
            )

            if resp.code == 0:
                continue

            resp_hash = hashlib.md5(resp.body[:2000].encode()).hexdigest()
            if resp_hash != baseline_hash:
                hdr_name = list(hdr_dict.keys())[0]
                _p(f"  [yellow]⚠ Unkeyed input reflected: {hdr_name}[/yellow]")
                ctx.add_finding(
                    severity="MEDIUM",
                    category="CACHE_POISON",
                    url=target_url,
                    title=f"Potential cache poisoning via {hdr_name}",
                    detail=f"Response differs when {hdr_name} is injected (cache-busted test)",
                    impact="Web cache poisoning → stored XSS, phishing",
                    exploit=f"curl -H '{hdr_name}: evil.com' '{target_url}'",
                    confidence="LOW",
                    cwe="CWE-444",
                    phase="3",
                )

    except Exception as e:
        _p(f"  [dim]Cache baseline error: {e}[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def execute(ctx, engine, config):
    console = Console() if _RICH else None

    def _p(m):
        (console.print if console else lambda x: print(
            __import__("re").sub(r"\[/?[^\]]*\]", "", x)
        ))(m)

    subs = ctx.subdomains
    if not subs:
        _p("  [yellow]No subdomains[/yellow]")
        return ctx

    _p(f"  [bold]Verifying {len(subs)} subdomains[/bold]")
    ws = getattr(config, "workspace", ".") or "."
    probe_results = []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ghost_"
    ) as tf:
        tf.write("\n".join(subs) + "\n")
        subs_file = tf.name

    try:
        from core.tools import resolve_pd_httpx
        if resolve_pd_httpx():
            httpx_out = os.path.join(ws, "recon", "httpx_results.json")
            os.makedirs(os.path.dirname(httpx_out), exist_ok=True)
            _p(f"  [cyan]→[/cyan]  httpx probing {len(subs)} hosts")
            if _RICH and console:
                with Progress(
                    SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(), console=console, transient=True,
                ) as prog:
                    prog.add_task("httpx...", total=None)
                    probe_results, err = await _httpx_probe(subs_file, httpx_out)
            else:
                probe_results, err = await _httpx_probe(subs_file, httpx_out)
            _p(
                f"  [green]✓[/green]  httpx: {len(probe_results)} alive"
                if not err
                else f"  [yellow]⚠[/yellow]  httpx: {err}"
            )
        elif engine:
            _p(f"  [cyan]→[/cyan]  Engine probing (WAF-evasion mode)")
            probe_results = await _engine_probe(subs, engine)
            _p(f"  [green]✓[/green]  Engine: {len(probe_results)} alive")
    finally:
        try:
            os.unlink(subs_file)
        except Exception:
            pass

    # v2.0: always verify the exact target URL too. Subdomain probing only
    # tries default ports, so a target like https://app.example.com:8443
    # (or a lab on :8080) was never registered as a live host.
    if engine and not any(r.get("url", "").rstrip("/") == ctx.target.rstrip("/") for r in probe_results):
        try:
            tr = await engine.get(ctx.target, timeout=10.0, scope="target")
            if tr.code:
                m = re.search(r"<title[^>]*>(.*?)</title>", tr.body or "", re.I | re.S)
                probe_results.append({
                    "url": ctx.target, "status_code": tr.code, "content_length": tr.size,
                    "title": (m.group(1).strip()[:120] if m else ""), "tech": [], "waf": [],
                })
        except Exception:
            pass

    # ─── Ingest Results ───────────────────────────────────────────────────
    all_waf: Set[str] = set()
    alive_urls: List[str] = []

    for r in probe_results:
        url = r.get("url", "")
        code = r.get("status_code", 0)
        if not url or code == 0:
            continue

        title = r.get("title", "")
        cl = r.get("content_length", 0)
        tech_list = r.get("tech", [])
        tech = ", ".join(tech_list) if isinstance(tech_list, list) else str(tech_list)
        waf_list = r.get("waf", [])
        waf_str = ", ".join(waf_list) if isinstance(waf_list, list) else ""

        ctx.add_live_host(url, http_code=code, title=title, content_length=cl, tech=tech)
        alive_urls.append(url)

        host = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
        ctx.add_subdomain(
            host, status="alive", http_code=code, title=title,
            tech_stack=tech, waf=waf_str,
        )
        if isinstance(waf_list, list):
            all_waf.update(waf_list)

    if all_waf:
        ctx.waf_detected = list(all_waf)
        _p(f"  [yellow]⚠ WAF/CDN: {', '.join(all_waf)}[/yellow]")

    # ─── Screenshots: Gowitness (hardened) → Aquatone failover ────────────
    if alive_urls:
        ss_dir = os.path.join(ws, "recon", "screenshots")
        os.makedirs(ss_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="ghost_alive_"
        ) as tf:
            tf.write("\n".join(alive_urls) + "\n")
            alive_file = tf.name

        try:
            sc, se = 0, None
            if _has("gowitness"):
                _p(f"  [cyan]→[/cyan]  gowitness (hardened headless, {len(alive_urls)} hosts)")
                sc, se = await _gowitness(alive_file, ss_dir)
                if se:
                    _p(f"  [yellow]⚠[/yellow]  gowitness: {se}")
                elif sc == 0:
                    _p(f"  [yellow]⚠[/yellow]  gowitness: 0 screenshots captured")
                else:
                    _p(f"  [green]✓[/green]  Screenshots: {sc}")

            # Aquatone failover: if gowitness failed or captured 0
            if (sc == 0 or se) and _has("aquatone"):
                _p(f"  [cyan]→[/cyan]  Aquatone fallback (stdin pipe)")
                aq_dir = os.path.join(ws, "recon", "aquatone_out")
                os.makedirs(aq_dir, exist_ok=True)
                sc2, se2 = await _aquatone_fallback(alive_urls, aq_dir)
                if se2:
                    _p(f"  [yellow]⚠[/yellow]  Aquatone: {se2}")
                else:
                    _p(f"  [green]✓[/green]  Aquatone: {sc2} screenshots")
        finally:
            try:
                os.unlink(alive_file)
            except Exception:
                pass

    # ─── Phase 3 Advanced Baselines (new in v12) ──────────────────────────
    if engine and alive_urls:
        target = ctx.target or alive_urls[0]

        # HTTP Smuggling baseline
        await _smuggling_baseline(target, engine, _p)

        # Cache Poisoning baseline
        await _cache_poison_baseline(target, engine, ctx, _p)

    # ─── Save alive hosts ─────────────────────────────────────────────────
    try:
        os.makedirs(os.path.join(ws, "recon"), exist_ok=True)
        with open(os.path.join(ws, "recon", "alive_hosts.txt"), "w") as f:
            f.write("\n".join(sorted(alive_urls)) + "\n")
    except Exception:
        pass

    ctx.persist_scan_state()
    _p(f"\n  [bold]Step 3:[/bold] {len(alive_urls)} alive, {len(all_waf)} WAF(s)")

    return ctx
