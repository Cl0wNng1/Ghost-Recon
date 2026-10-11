"""
GHOST RECON v2.0 — STEP 2: Data Processing, DNS Resolution & CDN Triage

Upgrades over the previous internal build:
  1. CDN-AWARE RESOLUTION: After DNS resolution, every IP is classified via
     core.cdn_intel (ASN → PTR → CIDR). CDN edges are quarantined into
     ctx.cdn_hosts and excluded from direct port scanning in Step 9.
  2. ORIGIN HUNTING: If CDN is detected, triggers OriginDiscoverer to find
     the real backend IP via Shodan/Censys SSL certificate history.
  3. Wildcard IP detection preserved + enhanced with CDN deconfliction.
  4. All existing fallback chain: massdns → dnsx → dig.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    )
    from rich.table import Table
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

try:
    from core.cdn_intel import CdnTriage, OriginDiscoverer, is_cdn_ip
    _HAS_CDN_INTEL = True
except ImportError:
    _HAS_CDN_INTEL = False

STEP_NUM = 2
STEP_NAME = "Data Processing & Resolution"


def _has(b: str) -> bool:
    return shutil.which(b) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# DNS RESOLUTION (unchanged chain: massdns → dnsx → dig)
# ═══════════════════════════════════════════════════════════════════════════════

async def _resolve_massdns(
    subs_file: str, output_file: str, resolver_file: str, timeout: float = 300.0
) -> Tuple[int, Optional[str]]:
    if not _has("massdns"):
        return 0, "massdns not installed"
    args = [
        "massdns", "-r", resolver_file, "-t", "A", "-o", "J",
        "--hashmap-size", "10000", "-w", output_file, subs_file,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0 and not os.path.exists(output_file):
            return 0, (stderr or b"").decode(errors="replace")[:120]
        count = sum(1 for _ in open(output_file)) if os.path.exists(output_file) else 0
        return count, None
    except asyncio.TimeoutError:
        return 0, f"Timed out ({timeout:.0f}s)"
    except Exception as e:
        return 0, str(e)[:120]


async def _resolve_dnsx(
    subs_file: str, timeout: float = 300.0
) -> Tuple[Dict[str, List[str]], Optional[str]]:
    if not _has("dnsx"):
        return {}, "dnsx not installed"
    args = ["dnsx", "-l", subs_file, "-a", "-resp", "-silent", "-no-color"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        results: Dict[str, List[str]] = {}
        for line in (stdout or b"").decode(errors="replace").split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                fqdn = parts[0].lower().rstrip(".")
                ips = [
                    p.strip("[]")
                    for p in parts[1:]
                    if re.match(r"\d+\.\d+\.\d+\.\d+", p.strip("[]"))
                ]
                if fqdn and ips:
                    results[fqdn] = ips
        return results, None
    except asyncio.TimeoutError:
        return {}, f"Timed out ({timeout:.0f}s)"
    except Exception as e:
        return {}, str(e)[:120]


async def _resolve_dig_fallback(
    subdomains: List[str], batch_size: int = 20
) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    sem = asyncio.Semaphore(batch_size)

    async def _resolve_one(fqdn: str):
        async with sem:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", "A", fqdn, "@8.8.8.8",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8.0)
                ips = [
                    ip.strip()
                    for ip in (stdout or b"").decode().split("\n")
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip.strip())
                ]
                if ips:
                    results[fqdn] = ips
            except (asyncio.TimeoutError, Exception):
                pass

    if _has("dig"):
        await asyncio.gather(*[_resolve_one(s) for s in subdomains[:500]])
    return results


def _detect_wildcard(
    resolved: Dict[str, List[str]], root_domain: str
) -> Optional[str]:
    if not resolved:
        return None
    from collections import Counter

    all_ips: List[str] = []
    for ips in resolved.values():
        all_ips.extend(ips)
    if not all_ips:
        return None
    c = Counter(all_ips)
    total = len(resolved)
    for ip, count in c.most_common(3):
        if total > 10 and count / total > 0.7:
            return ip
    return None


def _find_resolver_file(config: Any) -> str:
    paths = [
        getattr(config, "resolver_file", "") or "",
        os.path.expanduser("~/.config/resolvers.txt"),
        "/usr/share/massdns/lists/resolvers.txt",
        os.path.expanduser("~/resolvers.txt"),
    ]
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# CDN TRIAGE (new in v12)
# ═══════════════════════════════════════════════════════════════════════════════

def _triage_cdn_hosts(
    resolved: Dict[str, List[str]], ctx: Any, _p
) -> Tuple[Dict[str, List[str]], Dict[str, Dict]]:
    """
    Classify every resolved IP via CDN intelligence.
    Returns:
      - filtered_resolved: dict with CDN IPs removed
      - cdn_hosts: dict of quarantined CDN hosts
    """
    if not _HAS_CDN_INTEL:
        _p("  [dim]CDN intel module not available — skipping triage[/dim]")
        return resolved, {}

    triage = CdnTriage()
    cdn_hosts: Dict[str, Dict] = {}
    filtered: Dict[str, List[str]] = {}
    cdn_count = 0

    for fqdn, ips in resolved.items():
        clean_ips = []
        for ip in ips:
            verdict = triage.classify(ip)
            if verdict.is_cdn:
                cdn_count += 1
                cdn_hosts[fqdn] = {
                    "ip": ip,
                    "vendor": verdict.vendor,
                    "confidence": verdict.confidence,
                    "method": verdict.detection_method,
                    "origin_ip": None,
                }
                _p(
                    f"    [yellow]⚠ CDN[/yellow] {fqdn} → {ip} "
                    f"({verdict.vendor}, {verdict.confidence} via {verdict.detection_method})"
                )
            else:
                clean_ips.append(ip)

        if clean_ips:
            filtered[fqdn] = clean_ips

    if cdn_count:
        _p(
            f"\n  [yellow]⚠ CDN Triage:[/yellow] {cdn_count} IP(s) quarantined across "
            f"{len(cdn_hosts)} host(s) — excluded from port scanning"
        )

    return filtered, cdn_hosts


async def _hunt_origins(
    cdn_hosts: Dict[str, Dict], ctx: Any, engine: Any, config: Any, _p
) -> Dict[str, str]:
    """
    For CDN-quarantined hosts, attempt to discover origin IPs via
    Shodan/Censys SSL certificate history.
    """
    if not _HAS_CDN_INTEL:
        return {}

    shodan_key = getattr(config, "shodan_key", "") or os.environ.get("SHODAN_API_KEY", "")
    censys_id = os.environ.get("CENSYS_API_ID", "")
    censys_secret = os.environ.get("CENSYS_API_SECRET", "")

    if not engine or (not shodan_key and not censys_id):
        _p("  [dim]No API keys for origin hunting (SHODAN_API_KEY / CENSYS_API_ID)[/dim]")
        return {}

    _p(f"\n  [bold]Origin Hunting: {len(cdn_hosts)} CDN hosts[/bold]")

    discoverer = OriginDiscoverer(
        engine=engine,
        shodan_key=shodan_key,
        censys_id=censys_id,
        censys_secret=censys_secret,
        target_domain=ctx.domain,
    )

    origins: Dict[str, str] = {}

    # Hunt for the root domain first
    result = await discoverer.hunt(ctx.domain)
    if result and result.ip:
        origins[ctx.domain] = result.ip
        _p(
            f"  [green]✓[/green]  Origin found for {ctx.domain}: {result.ip} "
            f"(method={result.method}, validated={result.validated}, "
            f"confidence={result.confidence})"
        )

        # Update CDN host records
        for fqdn, info in cdn_hosts.items():
            if info.get("origin_ip") is None:
                info["origin_ip"] = result.ip

        # Promote to ctx
        if result.validated:
            ctx.origin_ip = result.ip
            ctx.persist_scan_state()
            ctx.add_finding(
                severity="HIGH",
                category="CDN_BYPASS",
                url=ctx.target,
                title=f"Origin IP discovered: {result.ip}",
                detail=(
                    f"Method: {result.method} | SSL CN: {result.ssl_cn} | "
                    f"Org: {result.org} | Validated: {result.validated}"
                ),
                impact="Direct backend access bypasses WAF — full attack surface exposed",
                exploit=f"curl -sk https://{result.ip}/ -H 'Host: {ctx.domain}'",
                confidence="HIGH" if result.validated else "MEDIUM",
                cwe="CWE-16",
                phase="2",
            )
    else:
        _p("  [dim]No origin IP found via certificate history[/dim]")

    return origins


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None

    def _p(m):
        (console.print if console else lambda x: print(
            __import__("re").sub(r"\[/?[^\]]*\]", "", x)
        ))(m)

    subs = ctx.subdomains
    if not subs:
        _p("  [yellow]No subdomains to process[/yellow]")
        return ctx

    _p(f"  [bold]Processing {len(subs)} subdomains[/bold]")

    ws = getattr(config, "workspace", "") or "."
    resolver_file = _find_resolver_file(config)
    resolved: Dict[str, List[str]] = {}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ghost_subs_"
    ) as tf:
        tf.write("\n".join(subs) + "\n")
        subs_file = tf.name

    try:
        # ─── DNS Resolution Chain ─────────────────────────────────────────
        if _has("massdns") and resolver_file:
            _p(f"  [cyan]→[/cyan]  MassDNS ({len(subs)} domains, resolver: {Path(resolver_file).name})")
            massdns_out = (
                os.path.join(ws, "recon", "massdns_results.json")
                if os.path.isdir(os.path.join(ws, "recon"))
                else tempfile.mktemp(suffix=".json")
            )

            if _RICH and console:
                with Progress(
                    SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(), console=console, transient=True,
                ) as prog:
                    prog.add_task("MassDNS resolving...", total=None)
                    count, err = await _resolve_massdns(subs_file, massdns_out, resolver_file)
            else:
                count, err = await _resolve_massdns(subs_file, massdns_out, resolver_file)

            if err:
                _p(f"  [yellow]⚠[/yellow]  MassDNS: {err}")
            else:
                _p(f"  [green]✓[/green]  MassDNS: {count} records")
                try:
                    with open(massdns_out) as f:
                        for line in f:
                            try:
                                rec = json.loads(line.strip())
                                name = rec.get("query_name", "").rstrip(".").lower()
                                if not name:
                                    continue
                                for ans in rec.get("resp", {}).get("answers", []):
                                    rtype = ans.get("rdtype", "")
                                    rdata = ans.get("rdata", "").rstrip(".")
                                    if rtype == "A" and re.match(r"\d+\.\d+\.\d+\.\d+", rdata):
                                        resolved.setdefault(name, []).append(rdata)
                                    elif rtype == "CNAME":
                                        ctx.add_subdomain(name, cname=rdata)
                            except (json.JSONDecodeError, KeyError):
                                continue
                except Exception:
                    pass

        if not resolved and _has("dnsx"):
            _p(f"  [cyan]→[/cyan]  dnsx fallback ({len(subs)} domains)")
            if _RICH and console:
                with Progress(
                    SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(), console=console, transient=True,
                ) as prog:
                    prog.add_task("dnsx resolving...", total=None)
                    resolved, err = await _resolve_dnsx(subs_file)
            else:
                resolved, err = await _resolve_dnsx(subs_file)
            if err:
                _p(f"  [yellow]⚠[/yellow]  dnsx: {err}")
            else:
                _p(f"  [green]✓[/green]  dnsx: {len(resolved)} resolved")

        if not resolved and _has("dig"):
            _p(f"  [cyan]→[/cyan]  dig fallback ({min(len(subs), 500)} domains)")
            resolved = await _resolve_dig_fallback(subs, batch_size=30)
            _p(f"  [green]✓[/green]  dig: {len(resolved)} resolved")

        if not resolved:
            _p("  [yellow]⚠ No DNS resolution tools available (install massdns/dnsx/dig)[/yellow]")

    finally:
        try:
            os.unlink(subs_file)
        except OSError:
            pass

    # ─── Wildcard Detection ───────────────────────────────────────────────
    wildcard_ip = _detect_wildcard(resolved, ctx.root_domain)
    if wildcard_ip:
        _p(f"  [yellow]⚠ Wildcard DNS detected: {wildcard_ip} — filtering[/yellow]")
        ctx.wildcard_ip = wildcard_ip
        resolved = {k: [ip for ip in v if ip != wildcard_ip] for k, v in resolved.items()}
        resolved = {k: v for k, v in resolved.items() if v}

    # ─── CDN TRIAGE (new in v12) ──────────────────────────────────────────
    _p(f"\n  [bold]CDN Infrastructure Triage[/bold]")
    filtered_resolved, cdn_hosts = _triage_cdn_hosts(resolved, ctx, _p)

    # Store CDN hosts in ctx for Step 9 to reference
    if hasattr(ctx, "cdn_hosts") or True:
        # Store as scan-level state
        try:
            ctx._db.execute(
                "UPDATE scans SET cdn_detected = ? WHERE scan_id = ?",
                (json.dumps(cdn_hosts), ctx.scan_id),
            )
        except Exception:
            pass

    # ─── Origin Hunting (if CDN detected) ─────────────────────────────────
    if cdn_hosts and engine:
        await _hunt_origins(cdn_hosts, ctx, engine, config, _p)

    # ─── Update Database ──────────────────────────────────────────────────
    total_resolved = {**filtered_resolved}
    # Also add CDN hosts with resolved status (they're resolved, just CDN-flagged)
    for fqdn, info in cdn_hosts.items():
        if info.get("ip"):
            total_resolved.setdefault(fqdn, []).append(info["ip"])

    _p(f"\n  [bold]Updating database with {len(total_resolved)} resolved hosts[/bold]")
    for fqdn, ips in total_resolved.items():
        cdn_info = cdn_hosts.get(fqdn, {})
        ctx.add_subdomain(
            fqdn,
            ip_addresses=ips,
            status="resolved",
            cdn=cdn_info.get("vendor", ""),
        )

    unresolved = [s for s in subs if s not in total_resolved]
    for fqdn in unresolved:
        ctx.add_subdomain(fqdn, status="unresolved")

    # ─── Write resolved.txt ───────────────────────────────────────────────
    if total_resolved and hasattr(config, "workspace") and config.workspace:
        try:
            rp = os.path.join(config.workspace, "recon", "resolved.txt")
            with open(rp, "w") as f:
                for fqdn, ips in sorted(total_resolved.items()):
                    cdn_tag = f" [CDN:{cdn_hosts[fqdn]['vendor']}]" if fqdn in cdn_hosts else ""
                    f.write(f"{fqdn} {','.join(ips)}{cdn_tag}\n")
        except Exception:
            pass

    ctx.persist_scan_state()

    # ─── Summary ──────────────────────────────────────────────────────────
    _p(
        f"\n  [bold]Step 2 Summary:[/bold] {len(total_resolved)} resolved, "
        f"{len(unresolved)} unresolved, {len(cdn_hosts)} CDN-quarantined"
        + (f", wildcard={wildcard_ip}" if wildcard_ip else "")
        + (f", origin={ctx.origin_ip}" if ctx.origin_ip else "")
    )

    return ctx
