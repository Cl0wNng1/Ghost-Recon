"""
GHOST RECON v2.0 — STEP 9: Network Discovery + CDN-Aware Triage

Upgrades over the previous internal build:
  1. CDN IP FILTERING: Before port scanning, every IP is checked via
     core.cdn_intel. If CDN edge → ABORT nmap and log warning.
  2. ORIGIN-ONLY SCANNING: If origin IP was discovered in Step 2,
     scan ONLY the origin (bypass CDN entirely).
  3. ASN/PTR lookup integration for classification.
  4. Preserved: nmap → rustscan → bash fallback, Shodan lookup,
     Deep Visual Recon chain, zombie-proof subprocesses.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        MofNCompleteColumn, TimeElapsedColumn,
    )
    _RICH = True
except ImportError:
    _RICH = False

try:
    from core.cdn_intel import is_cdn_ip, CdnTriage
    _HAS_CDN_INTEL = True
except ImportError:
    _HAS_CDN_INTEL = False

STEP_NUM = 9
STEP_NAME = "Network Discovery"
_HEAVY_SEM = asyncio.Semaphore(3)

QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 2082, 2083, 2086, 2087, 3000, 3306, 3389,
    4443, 5000, 5432, 5900, 5985, 6379, 7443, 8000, 8080,
    8443, 8888, 9090, 9200, 9443, 10443, 11211, 27017,
]

HTTP_PORTS = frozenset({
    80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001,
    4443, 5000, 5001, 5601, 7443, 8000, 8008, 8080, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8181, 8443, 8444, 8800,
    8880, 8888, 8899, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200,
    9443, 9500, 9800, 9981, 9999, 10000, 10443, 16080, 18080, 18443,
})
STANDARD_PORTS = frozenset({80, 443})


def _has(b):
    return shutil.which(b) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# CDN IP CLASSIFICATION (v12 — pre-scan triage)
# ═══════════════════════════════════════════════════════════════════════════════

def _is_cdn_edge(ip: str) -> Tuple[bool, str]:
    """Check if an IP is a CDN edge. Returns (is_cdn, vendor)."""
    if _HAS_CDN_INTEL:
        return is_cdn_ip(ip)
    return False, ""


# ═══════════════════════════════════════════════════════════════════════════════
# PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

async def _nmap_scan(ip, ws, timeout=300.0):
    if not _has("nmap"):
        return {}, "nmap not installed"
    extra = ",".join(str(p) for p in QUICK_PORTS)
    args = [
        "nmap", "-sS", "-sV", "--top-ports", "1000", "-p", extra,
        "--open", "-T3", "-Pn", "--max-retries", "1", ip,
    ]
    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                if proc:
                    proc.kill()
                    await proc.wait()
                return {}, f"Timed out ({timeout:.0f}s)"

            output = (stdout or b"").decode("utf-8", errors="ignore")
            try:
                os.makedirs(os.path.join(ws, "recon"), exist_ok=True)
                with open(
                    os.path.join(ws, "recon", f"nmap_{ip.replace('.', '_')}.txt"), "w"
                ) as f:
                    f.write(output)
            except Exception:
                pass

            ports = {}
            for line in output.split("\n"):
                m = re.match(r"(\d+)/(\w+)\s+open\s+(.*)", line.strip())
                if m:
                    ports[int(m.group(1))] = m.group(3).strip()
            return ports, None

        except Exception as e:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {}, str(e)[:80]


async def _rustscan(ip, timeout=90.0):
    if not _has("rustscan"):
        return {}, "Not installed"
    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "rustscan", "-a", ip, "--ulimit", "3000", "-t", "3000",
                "--tries", "1", "-g",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                if proc:
                    proc.kill()
                    await proc.wait()
                return {}, "Timed out"
            ports = {}
            for p in re.findall(
                r"(\d+)", (stdout or b"").decode("utf-8", errors="ignore")
            ):
                ports[int(p)] = "open"
            return ports, None
        except Exception as e:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {}, str(e)[:80]


async def _bash_port_probe(ip):
    ports = {}
    sem = asyncio.Semaphore(30)

    async def _probe(p):
        async with sem:
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    "bash", "-c",
                    f"timeout 3 bash -c 'echo >/dev/tcp/{ip}/{p}' 2>/dev/null; echo $?",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=6.0)
                except asyncio.TimeoutError:
                    if proc:
                        proc.kill()
                        await proc.wait()
                    return
                if (stdout or b"").decode("utf-8", errors="ignore").strip() == "0":
                    ports[p] = "open"
            except Exception:
                pass

    await asyncio.gather(*[_probe(p) for p in QUICK_PORTS])
    return ports


async def _shodan_lookup(ip, api_key, engine):
    if not api_key or not engine:
        return None, "No Shodan key/engine"
    try:
        resp = await engine.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=12.0, scope="shodan",
        )
        if resp.code == 200 and resp.body:
            d = json.loads(resp.body)
            return {
                "org": d.get("org", ""),
                "isp": d.get("isp", ""),
                "ports": d.get("ports", []),
                "vulns": d.get("vulns", []),
                "os": d.get("os", ""),
                "asn": d.get("asn", ""),
            }, None
        return None, f"HTTP {resp.code}"
    except Exception as e:
        return None, str(e)[:80]


# ═══════════════════════════════════════════════════════════════════════════════
# DEEP VISUAL RECON (preserved from v11)
# ═══════════════════════════════════════════════════════════════════════════════

async def _alive_check_urls(urls, engine, batch=15):
    alive = []
    sem = asyncio.Semaphore(batch)

    async def _check(url):
        async with sem:
            try:
                if engine:
                    resp = await engine.request(
                        url, method="HEAD", timeout=6.0, scope="portscan"
                    )
                    if resp.code > 0:
                        alive.append(url)
                else:
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-skI", "-m", "5", "-o", "/dev/null",
                        "-w", "%{http_code}", url,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=8.0
                        )
                    except asyncio.TimeoutError:
                        if proc:
                            proc.kill()
                            await proc.wait()
                        return
                    code = (stdout or b"").decode("utf-8", errors="ignore").strip()
                    if code.isdigit() and int(code) > 0:
                        alive.append(url)
            except Exception:
                pass

    await asyncio.gather(*[_check(u) for u in urls])
    return alive


async def _gowitness_ext(urls_file, out_dir, timeout=300.0):
    if not _has("gowitness"):
        return 0, "Not installed"
    args = [
        "gowitness", "file", "-f", urls_file, "-P", out_dir,
        "--disable-logging", "--timeout", "15",
    ]
    chrome = (
        shutil.which("google-chrome")
        or shutil.which("chromium-browser")
        or shutil.which("chromium")
    )
    if chrome:
        args.extend(["--chrome-path", chrome])
    env = dict(os.environ)
    env["DISPLAY"] = ""
    env["CHROME_FLAGS"] = (
        "--no-sandbox --disable-dev-shm-usage --headless=new "
        "--window-size=1920,1080 --disable-gpu --disable-software-rasterizer"
    )

    async with _HEAVY_SEM:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                if proc:
                    proc.kill()
                    await proc.wait()
                return 0, f"Timed out ({timeout:.0f}s)"

            count = (
                len(list(Path(out_dir).glob("*.png")))
                if os.path.isdir(out_dir)
                else 0
            )
            return count, None

        except Exception as e:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return 0, str(e)[:80]


async def _aquatone_ext(alive_urls, out_dir, timeout=300.0):
    if not _has("aquatone"):
        return 0, "Not installed"
    hosts_str = "\n".join(alive_urls)
    async with _HEAVY_SEM:
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
                    proc.communicate(input=hosts_str.encode("utf-8")),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                if proc:
                    proc.kill()
                    await proc.wait()
                return 0, "Timed out"
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


async def _deep_visual_recon(all_port_data, ctx, engine, config, _p):
    ws = getattr(config, "workspace", ".") or "."
    candidate_urls = []
    host_header = ctx.host_header or ctx.domain
    for ip, ports in all_port_data.items():
        for port, service in ports.items():
            if port in STANDARD_PORTS:
                continue
            if port in HTTP_PORTS or any(
                k in (service or "").lower()
                for k in ["http", "https", "web", "ssl", "tls"]
            ):
                if port in (443, 4443, 7443, 8443, 9443, 10443, 18443):
                    candidate_urls.append(f"https://{ip}:{port}")
                    candidate_urls.append(f"https://{host_header}:{port}")
                elif port in (80, 8080, 8000, 8888, 9090):
                    candidate_urls.append(f"http://{ip}:{port}")
                    candidate_urls.append(f"http://{host_header}:{port}")
                else:
                    candidate_urls.append(f"https://{ip}:{port}")
                    candidate_urls.append(f"http://{ip}:{port}")

    candidate_urls = sorted(set(candidate_urls))
    if not candidate_urls:
        _p(f"  [dim]No non-standard HTTP ports to screenshot[/dim]")
        return 0

    _p(f"\n  [bold]Deep Visual Recon: {len(candidate_urls)} extended port targets[/bold]")

    _p(f"  [cyan]→[/cyan]  Alive-checking {len(candidate_urls)} targets")
    if _RICH:
        c = Console()
        with Progress(
            SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
            TimeElapsedColumn(), console=c, transient=True,
        ) as prog:
            prog.add_task("HEAD probing extended ports...", total=None)
            alive = await _alive_check_urls(candidate_urls, engine)
    else:
        alive = await _alive_check_urls(candidate_urls, engine)

    if not alive:
        _p(f"  [dim]No extended ports responding HTTP[/dim]")
        return 0

    _p(f"  [green]✓[/green]  {len(alive)} ports confirmed HTTP-alive")
    for u in alive[:8]:
        _p(f"    [dim]{u}[/dim]")
    if len(alive) > 8:
        _p(f"    [dim]... +{len(alive) - 8} more[/dim]")

    for url in alive:
        ctx.add_live_host(url, http_code=200, title="Extended port service")
        ctx.add_finding(
            severity="MEDIUM", category="OPEN_PORTS", url=url,
            title=f"HTTP on non-standard port: {url}",
            detail="Confirmed HTTP response",
            impact="Hidden services, admin panels, debug interfaces",
            exploit=f"curl -sk '{url}'",
            confidence="CONFIRMED", cwe="CWE-200", phase="9",
        )

    ss_dir = os.path.join(ws, "screenshots", "extended_ports")
    os.makedirs(ss_dir, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ghost_extports_"
    ) as tf:
        tf.write("\n".join(alive) + "\n")
        targets_file = tf.name

    total_ss = 0
    try:
        try:
            with open(os.path.join(ss_dir, "targets.txt"), "w") as f:
                f.write("\n".join(alive) + "\n")
        except Exception:
            pass

        if _has("gowitness"):
            _p(f"  [cyan]→[/cyan]  gowitness ({len(alive)} extended port targets)")
            if _RICH:
                c = Console()
                with Progress(
                    SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(), console=c, transient=True,
                ) as prog:
                    prog.add_task("gowitness extended...", total=None)
                    sc, se = await _gowitness_ext(targets_file, ss_dir)
            else:
                sc, se = await _gowitness_ext(targets_file, ss_dir)
            if se:
                _p(f"  [yellow]⚠[/yellow]  gowitness: {se}")
            elif sc == 0:
                _p(f"  [yellow]⚠[/yellow]  gowitness: 0 screenshots captured")
            else:
                _p(f"  [green]✓[/green]  gowitness: {sc} screenshots → screenshots/extended_ports/")
                total_ss = sc

        if total_ss == 0 and _has("aquatone"):
            _p(f"  [cyan]→[/cyan]  Aquatone fallback (stdin pipe)")
            aq_dir = os.path.join(ss_dir, "aquatone_out")
            os.makedirs(aq_dir, exist_ok=True)
            if _RICH:
                c = Console()
                with Progress(
                    SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(), console=c, transient=True,
                ) as prog:
                    prog.add_task("Aquatone extended...", total=None)
                    sc2, se2 = await _aquatone_ext(alive, aq_dir)
            else:
                sc2, se2 = await _aquatone_ext(alive, aq_dir)
            if se2:
                _p(f"  [yellow]⚠[/yellow]  Aquatone: {se2}")
            else:
                _p(f"  [green]✓[/green]  Aquatone: {sc2} screenshots")
                total_ss = sc2

        if total_ss == 0 and not _has("gowitness") and not _has("aquatone"):
            _p(f"  [yellow]⚠[/yellow]  No screenshot tools (install gowitness or aquatone)")
    finally:
        try:
            os.unlink(targets_file)
        except Exception:
            pass

    return total_ss


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def execute(ctx, engine, config):
    console = Console() if _RICH else None

    def _p(m):
        (console.print if console else lambda x: print(
            __import__("re").sub(r"\[/?[^\]]*\]", "", x)
        ))(m)

    ws = getattr(config, "workspace", ".") or "."
    shodan_key = getattr(config, "shodan_key", "") or os.environ.get("SHODAN_API_KEY", "")

    # ─── Collect IPs ──────────────────────────────────────────────────────
    scan_ips: Set[str] = set()
    if ctx.origin_ip:
        scan_ips.add(ctx.origin_ip)

    rows = ctx.db.fetch_all(
        "SELECT ip_addresses FROM subdomains WHERE scan_id = ? AND ip_addresses != '[]'",
        (ctx.scan_id,),
    )
    for row in rows:
        try:
            for ip in json.loads(row["ip_addresses"]):
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and not ip.startswith(
                    ("10.", "192.168.", "172.")
                ):
                    scan_ips.add(ip)
        except Exception:
            continue

    if not scan_ips:
        _p("  [yellow]No IPs to scan[/yellow]")
        return ctx

    # ─── CDN TRIAGE (v12): Filter out CDN edges BEFORE scanning ───────────
    origin_ips: List[str] = []
    cdn_skipped: List[str] = []

    for ip in sorted(scan_ips):
        is_cdn, vendor = _is_cdn_edge(ip)
        if is_cdn and ip != ctx.origin_ip:
            cdn_skipped.append(f"{ip} ({vendor})")
            _p(f"  [yellow]⚠ ABORT[/yellow] scan on {ip} — CDN edge ({vendor})")
        else:
            origin_ips.append(ip)

    if cdn_skipped:
        _p(
            f"\n  [yellow]CDN Triage:[/yellow] {len(cdn_skipped)} IP(s) skipped "
            f"(CDN edges — scanning would only hit edge nodes)"
        )

    if not origin_ips:
        _p("  [yellow]All IPs are CDN edges — no origin IPs to scan[/yellow]")
        if ctx.origin_ip:
            _p(f"  [dim]Origin IP {ctx.origin_ip} would be scanned if available[/dim]")
        return ctx

    scan_list = origin_ips[:20]
    _p(f"  [bold]Scanning {len(scan_list)} non-CDN IP(s)[/bold]")

    all_port_data: Dict[str, Dict] = {}

    for ip in scan_list:
        is_origin = ip == ctx.origin_ip
        _p(
            f"\n  [cyan]→[/cyan]  {ip}"
            + (" [bold](ORIGIN — direct backend)[/bold]" if is_origin else "")
        )

        ports: Dict[int, str] = {}

        # Shodan lookup
        if shodan_key and engine:
            intel, err = await _shodan_lookup(ip, shodan_key, engine)
            if intel:
                _p(
                    f"    Shodan: org={intel['org']}, "
                    f"ports={intel['ports'][:10]}, "
                    f"vulns={len(intel.get('vulns', []))}"
                )
                for p in intel.get("ports", []):
                    ports[p] = "shodan"
                if intel.get("vulns"):
                    ctx.add_finding(
                        severity="HIGH",
                        category="SHODAN_VULNS",
                        url=ip,
                        title=f"Shodan: {len(intel['vulns'])} CVEs on {ip}",
                        detail=f"CVEs: {', '.join(intel['vulns'][:10])}",
                        impact="Known vulnerabilities",
                        exploit=f"shodan host {ip}",
                        confidence="MEDIUM",
                        cwe="CWE-1035",
                        phase="9",
                    )
            elif err:
                _p(f"    [dim]Shodan: {err}[/dim]")

        # Port scanning
        if _has("nmap"):
            _p(f"    nmap scanning...")
            if _RICH and console:
                with Progress(
                    SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(), console=console, transient=True,
                ) as prog:
                    prog.add_task(f"nmap {ip}", total=None)
                    np, ne = await _nmap_scan(ip, ws)
            else:
                np, ne = await _nmap_scan(ip, ws)
            if ne:
                _p(f"    [yellow]⚠ nmap: {ne}[/yellow]")
            else:
                ports.update(np)
                _p(f"    [green]✓[/green] nmap: {len(np)} open ports")
        elif _has("rustscan"):
            rp, re_ = await _rustscan(ip)
            if not re_:
                ports.update(rp)
                _p(f"    [green]✓[/green] rustscan: {len(rp)} ports")
        elif not ports:
            _p(f"    Bash probe...")
            bp = await _bash_port_probe(ip)
            ports.update(bp)
            _p(f"    [green]✓[/green] probe: {len(bp)} ports")

        all_port_data[ip] = ports
        for port, service in ports.items():
            ctx.add_port(
                ip, port,
                service=service,
                source="shodan" if service == "shodan" else "nmap",
            )

        interesting = {p: s for p, s in ports.items() if p not in STANDARD_PORTS}
        if interesting:
            db_p = [
                p for p in interesting
                if p in (3306, 5432, 1433, 1521, 6379, 27017, 9200, 11211)
            ]
            admin_p = [
                p for p in interesting
                if p in (2082, 2083, 2086, 2087, 9090, 8443)
            ]
            if db_p:
                ctx.add_finding(
                    severity="HIGH",
                    category="OPEN_PORTS",
                    url=ip,
                    title=f"Database ports: {db_p}",
                    detail=f"Ports: {db_p}",
                    impact="Direct DB access",
                    exploit=f"nmap -sV -p {','.join(str(p) for p in db_p)} {ip}",
                    confidence="CONFIRMED",
                    cwe="CWE-200",
                    phase="9",
                )
            if admin_p:
                ctx.add_finding(
                    severity="MEDIUM",
                    category="OPEN_PORTS",
                    url=ip,
                    title=f"Admin ports: {admin_p}",
                    detail=f"Ports: {admin_p}",
                    impact="Admin exposure",
                    confidence="CONFIRMED",
                    cwe="CWE-200",
                    phase="9",
                )

    # ─── Deep Visual Recon ────────────────────────────────────────────────
    total_ss = await _deep_visual_recon(all_port_data, ctx, engine, config, _p)

    total_ports = (
        ctx.db.fetch_scalar(
            "SELECT COUNT(*) FROM ports WHERE scan_id = ?", (ctx.scan_id,)
        )
        or 0
    )
    ns = sum(
        1 for ports in all_port_data.values() for p in ports if p not in STANDARD_PORTS
    )

    _p(
        f"\n  [bold]Step 9:[/bold] {total_ports} ports, {ns} non-standard, "
        f"{total_ss} screenshots, {len(cdn_skipped)} CDN IPs skipped"
    )
    return ctx
