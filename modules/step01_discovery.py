"""
GHOST RECON v2.0 — STEP 1: Phase 1 Passive Reconnaissance
4-Phase Architecture: Collect data silently and comprehensively.

v14 upgrades:
  - Multi-tool orchestration: subfinder -all → assetfinder → amass enum -passive
  - Permutation engine: gotator/altdns on discovered subs for hidden dev/staging
  - OSINT API integration: ctx.osint.get_securitytrails_subs(), github_dorks(),
    get_virustotal_subs() — all async, all with circuit breakers
  - Certificate Transparency: crt.sh + hackertarget + alienvault
  - ASN discovery + BGP prefix enumeration
  - Dynamic wordlist: fetch Assetnote best-dns if missing locally
"""
from __future__ import annotations
import asyncio, json, os, re, shutil, tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    _RICH = True
except ImportError:
    _RICH = False

STEP_NUM = 1
STEP_NAME = "Attack Surface Discovery"
_HEAVY_SEM = asyncio.Semaphore(3)

ORIGIN_PREFIXES = [
    "origin", "direct", "backend", "real", "old", "legacy", "raw",
    "origin-www", "direct-connect", "origin-pool", "staging-origin",
    "dev", "stage", "staging", "test", "uat", "qa", "preprod",
    "internal", "admin", "vpn", "mail", "webmail", "ftp", "sftp",
    "ns1", "ns2", "dns", "dns1", "dns2", "mx", "smtp", "pop", "imap",
    "api", "api-dev", "api-staging", "api-internal", "api-v2",
    "portal", "dashboard", "console", "monitoring", "grafana", "kibana",
    "jenkins", "gitlab", "jira", "confluence", "sonar", "nexus",
    "db", "database", "redis", "elastic", "mongo", "mysql", "postgres",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "ws", "websocket", "socket", "grpc", "graphql",
]


def _has(b: str) -> bool:
    return shutil.which(b) is not None


def _clean_subs(raw: str, rd: str) -> Set[str]:
    results: Set[str] = set()
    for token in re.findall(
        r'[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+',
        raw.lower(),
    ):
        fqdn = token.lstrip("*.").rstrip(".")
        if fqdn and rd in fqdn and "." in fqdn and len(fqdn) < 255:
            results.add(fqdn)
    return results


async def _run_tool(
    name: str, args: List[str], rd: str, timeout: float = 300.0
) -> Tuple[str, Set[str], Optional[str]]:
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
                if proc:
                    proc.kill()
                    await proc.wait()
                return (name, set(), f"Timed out after {timeout:.0f}s")
            raw = (stdout or b"").decode("utf-8", errors="ignore")
            if proc.returncode != 0 and not raw.strip():
                return (
                    name,
                    set(),
                    (stderr or b"").decode("utf-8", errors="ignore")[:120],
                )
            return (name, _clean_subs(raw, rd), None)
        except FileNotFoundError:
            return (name, set(), f"Binary '{args[0]}' not found")
        except Exception as e:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return (name, set(), str(e)[:120])


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL WRAPPERS (master-level CLI flags)
# ═══════════════════════════════════════════════════════════════════════════════

async def _subfinder(rd: str) -> Tuple[str, Set[str], Optional[str]]:
    if not _has("subfinder"):
        return ("subfinder", set(), "Not installed")
    return await _run_tool(
        "subfinder",
        [
            "subfinder", "-d", rd, "-silent", "-all", "-nW",
            "-timeout", "30", "-max-time", "5",
        ],
        rd, 300,
    )


async def _assetfinder(rd: str) -> Tuple[str, Set[str], Optional[str]]:
    if not _has("assetfinder"):
        return ("assetfinder", set(), "Not installed")
    return await _run_tool(
        "assetfinder", ["assetfinder", "--subs-only", rd], rd, 180
    )


async def _amass_passive(rd: str) -> Tuple[str, Set[str], Optional[str]]:
    if not _has("amass"):
        return ("amass", set(), "Not installed")
    return await _run_tool(
        "amass",
        ["amass", "enum", "-passive", "-d", rd, "-nocolor", "-timeout", "10"],
        rd, 600,
    )


async def _crtsh(rd: str, engine: Any) -> Tuple[str, Set[str], Optional[str]]:
    subs: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{rd}&output=json"
    try:
        if engine:
            resp = await engine.get(url, timeout=20.0, scope="crtsh")
            code, body = resp.code, resp.body
        else:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sm", "20", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=25.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ("crt.sh", subs, "Timed out")
            body = (stdout or b"").decode("utf-8", errors="ignore")
            code = 200 if body.strip().startswith("[") else 0

        if code == 200 and body:
            for e in json.loads(body):
                for n in e.get("name_value", "").split("\n"):
                    f = n.strip().lower().lstrip("*.")
                    if f and rd in f:
                        subs.add(f)
    except Exception as e:
        return ("crt.sh", subs, str(e)[:80])
    return ("crt.sh", subs, None)


async def _hackertarget(
    rd: str, engine: Any
) -> Tuple[str, Set[str], Optional[str]]:
    subs: Set[str] = set()
    if not engine:
        return ("hackertarget", subs, "No engine")
    try:
        resp = await engine.get(
            f"https://api.hackertarget.com/hostsearch/?q={rd}",
            timeout=15.0, scope="hackertarget",
        )
        if resp.code == 200 and resp.body and "error" not in resp.body.lower():
            for l in resp.body.split("\n"):
                p = l.strip().split(",")
                if p and rd in p[0].lower():
                    subs.add(p[0].strip().lower())
    except Exception as e:
        return ("hackertarget", subs, str(e)[:80])
    return ("hackertarget", subs, None)


async def _alienvault(
    rd: str, engine: Any
) -> Tuple[str, Set[str], Optional[str]]:
    subs: Set[str] = set()
    if not engine:
        return ("alienvault", subs, "No engine")
    try:
        resp = await engine.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{rd}/passive_dns",
            timeout=15.0, scope="alienvault",
        )
        if resp.code == 200 and resp.body:
            for e in json.loads(resp.body).get("passive_dns", []):
                h = e.get("hostname", "").strip().lower()
                if h and rd in h:
                    subs.add(h)
    except Exception as e:
        return ("alienvault", subs, str(e)[:80])
    return ("alienvault", subs, None)


# ═══════════════════════════════════════════════════════════════════════════════
# OSINT API INTEGRATION (v14 — uses ctx.osint)
# ═══════════════════════════════════════════════════════════════════════════════

async def _osint_securitytrails(
    rd: str, ctx: Any, _p
) -> Tuple[str, Set[str], Optional[str]]:
    """SecurityTrails subdomain enumeration via ctx.osint."""
    subs: Set[str] = set()
    osint = getattr(ctx, "osint", None)
    if not osint or not osint.is_available("securitytrails"):
        return ("securitytrails", subs, "No key or disabled")
    try:
        result = await osint.get_securitytrails_subs(rd)
        for fqdn in result:
            if rd in fqdn.lower():
                subs.add(fqdn.lower())
        return ("securitytrails", subs, None)
    except Exception as e:
        return ("securitytrails", subs, str(e)[:80])


async def _osint_virustotal(
    rd: str, ctx: Any, _p
) -> Tuple[str, Set[str], Optional[str]]:
    """VirusTotal subdomain enumeration via ctx.osint."""
    subs: Set[str] = set()
    osint = getattr(ctx, "osint", None)
    if not osint or not osint.is_available("virustotal"):
        return ("virustotal", subs, "No key or disabled")
    try:
        result = await osint.get_virustotal_subs(rd)
        for fqdn in result:
            if rd in fqdn.lower():
                subs.add(fqdn.lower())
        return ("virustotal", subs, None)
    except Exception as e:
        return ("virustotal", subs, str(e)[:80])


async def _osint_github_dorks(
    rd: str, ctx: Any, ws: str, _p
) -> int:
    """GitHub secret dorking via ctx.osint. Returns finding count."""
    osint = getattr(ctx, "osint", None)
    if not osint or not osint.is_available("github"):
        return 0
    try:
        _p(f"  [cyan]→[/cyan]  GitHub dorking (API)...")
        hits = await osint.search_github_dorks(rd)
        count = 0
        for hit in hits:
            dork = hit.get("dork", "")
            total = hit.get("total_count", 0)
            items = hit.get("items", [])
            if total > 0:
                _p(f"    [red]✓ GitHub: '{dork}' → {total} results[/red]")
                for item in items[:3]:
                    _p(f"      {item.get('html_url', '')[:80]}")
                ctx.add_finding(
                    severity="HIGH",
                    category="GITHUB_LEAK",
                    url=items[0].get("html_url", "") if items else f"github.com/search?q={rd}+{dork}",
                    title=f"GitHub code leak: '{dork}' → {total} results",
                    detail=f"Repos: {', '.join(i.get('repo','') for i in items[:3])}",
                    impact="Credentials or secrets in public GitHub repos",
                    exploit=f"https://github.com/search?q={rd}+{dork}&type=code",
                    confidence="HIGH",
                    cwe="CWE-200",
                    phase="1",
                )
                count += 1
            # Write dork URLs to file
            try:
                os.makedirs(os.path.join(ws, "osint"), exist_ok=True)
                with open(os.path.join(ws, "osint", "github_dorks.txt"), "a") as f:
                    for item in items:
                        f.write(
                            f"{dork}|{item.get('repo','')}|{item.get('html_url','')}\n"
                        )
            except Exception:
                pass
        return count
    except Exception as e:
        _p(f"    [dim]GitHub dorks error: {e}[/dim]")
        return 0


# ═══════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN PERMUTATION ENGINE (v14)
# ═══════════════════════════════════════════════════════════════════════════════

async def _permutate_subs(
    subs: Set[str], rd: str, ws: str, _p
) -> Set[str]:
    """Generate permutations of discovered subdomains using gotator or altdns."""
    new_subs: Set[str] = set()

    if not _has("gotator") and not _has("altdns"):
        _p("  [dim]No permutation tool (gotator/altdns) — skipping[/dim]")
        return new_subs

    # Write subs to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ghost_perm_"
    ) as tf:
        tf.write("\n".join(sorted(subs)) + "\n")
        subs_file = tf.name

    # Write permutation words
    perm_words = [
        "dev", "staging", "stage", "test", "uat", "qa", "preprod", "pre",
        "prod", "production", "api", "internal", "private", "admin",
        "backend", "old", "new", "v2", "v3", "beta", "alpha", "demo",
        "sandbox", "origin", "direct", "legacy", "backup", "dr",
    ]
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ghost_words_"
    ) as wf:
        wf.write("\n".join(perm_words) + "\n")
        words_file = wf.name

    try:
        if _has("gotator"):
            _p(f"  [cyan]→[/cyan]  gotator permutation ({len(subs)} seeds)")
            name, results, err = await _run_tool(
                "gotator",
                [
                    "gotator", "-sub", subs_file, "-perm", words_file,
                    "-depth", "1", "-mindup", "-adv",
                ],
                rd, 120,
            )
            if not err:
                new_subs.update(results - subs)
                _p(f"  [green]✓[/green]  gotator: {len(new_subs)} new permutations")
            elif err:
                _p(f"  [dim]gotator: {err}[/dim]")

        elif _has("altdns"):
            _p(f"  [cyan]→[/cyan]  altdns permutation ({len(subs)} seeds)")
            out_file = os.path.join(ws, "recon", "altdns_out.txt")
            os.makedirs(os.path.dirname(out_file), exist_ok=True)
            name, results, err = await _run_tool(
                "altdns",
                [
                    "altdns", "-i", subs_file, "-w", words_file,
                    "-o", out_file,
                ],
                rd, 180,
            )
            if os.path.exists(out_file):
                raw = Path(out_file).read_text(errors="ignore")
                new_subs.update(_clean_subs(raw, rd) - subs)
                _p(f"  [green]✓[/green]  altdns: {len(new_subs)} new permutations")
    finally:
        try:
            os.unlink(subs_file)
        except OSError:
            pass
        try:
            os.unlink(words_file)
        except OSError:
            pass

    return new_subs


# ═══════════════════════════════════════════════════════════════════════════════
# ASN DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

async def _discover_asn(
    rd: str, engine: Any, _p=None
) -> Tuple[Optional[str], List[str]]:
    _log = _p or (lambda m: None)
    asn: Optional[str] = None
    cidrs: List[str] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "A", rd, "@8.8.8.8",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return asn, cidrs
        ips = [
            ip.strip()
            for ip in (stdout or b"").decode("utf-8", errors="ignore").split("\n")
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip.strip())
        ]
        if ips:
            proc2 = await asyncio.create_subprocess_exec(
                "dig", "+short", f"{ips[0]}.origin.asn.cymru.com", "TXT", "@8.8.8.8",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10.0)
            except asyncio.TimeoutError:
                proc2.kill()
                await proc2.wait()
                return asn, cidrs
            m = re.search(
                r'"(\d+)', (stdout2 or b"").decode("utf-8", errors="ignore")
            )
            if m:
                asn = m.group(1)
                _log(f"  [green]✓[/green]  ASN: AS{asn}")
    except (FileNotFoundError, Exception):
        pass

    if asn and engine:
        try:
            resp = await engine.get(
                f"https://api.bgpview.io/asn/{asn}/prefixes",
                timeout=15.0, scope="bgpview",
            )
            if resp.code == 200 and resp.body:
                for pf in json.loads(resp.body).get("data", {}).get(
                    "ipv4_prefixes", []
                )[:20]:
                    c = pf.get("prefix", "")
                    if c:
                        cidrs.append(c)
        except Exception:
            pass

    return asn, cidrs


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    console = Console() if _RICH else None

    def _p(m):
        (console.print if console else lambda x: print(
            __import__("re").sub(r"\[/?[^\]]*\]", "", x)
        ))(m)

    rd = ctx.root_domain
    domain = ctx.domain
    ws = getattr(config, "workspace", ".") or "."

    if getattr(config, "skip_subs", False):
        _p("  [yellow]⊘ Subdomain enum skipped[/yellow]")
        ctx.add_subdomain(domain)
        return ctx

    _p(f"\n  [bold]Phase 1: Passive Reconnaissance — {rd}[/bold]")

    # ─── Stage 1: Multi-tool subdomain enumeration ────────────────────────
    _p(f"\n  [bold]Stage 1: Concurrent subdomain discovery[/bold]")
    tasks: Dict[str, Any] = {
        "subfinder": _subfinder(rd),
        "crt.sh": _crtsh(rd, engine),
        "hackertarget": _hackertarget(rd, engine),
        "alienvault": _alienvault(rd, engine),
    }
    if _has("assetfinder"):
        tasks["assetfinder"] = _assetfinder(rd)
    if _has("amass") and ctx.scope == "wildcard":
        tasks["amass"] = _amass_passive(rd)

    # OSINT API sources (v14)
    tasks["securitytrails"] = _osint_securitytrails(rd, ctx, _p)
    tasks["virustotal"] = _osint_virustotal(rd, ctx, _p)

    names = list(tasks.keys())
    coros = list(tasks.values())

    if _RICH and console:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            TimeElapsedColumn(),
            console=console, transient=True,
        ) as prog:
            prog.add_task(f"Running {len(tasks)} sources...", total=None)
            results = await asyncio.gather(*coros, return_exceptions=True)
    else:
        results = await asyncio.gather(*coros, return_exceptions=True)

    all_subs: Set[str] = set()
    for name, result in zip(names, results):
        if isinstance(result, Exception):
            _p(f"  [red]✗[/red]  {name}: {result}")
            continue
        tn, subs, err = result
        new = len(subs - all_subs)
        _p(
            f"  [{'yellow' if err else 'green'}]"
            f"{'⚠' if err else '✓'}[/]  {tn}: {len(subs)} ({new} new)"
            + (f" — {err}" if err else "")
        )
        all_subs.update(subs)

    all_subs.add(domain)
    all_subs.add(rd)

    # ─── Stage 2: Subdomain permutation (v14) ────────────────────────────
    if ctx.scope == "wildcard" and len(all_subs) > 3:
        _p(f"\n  [bold]Stage 2: Subdomain permutation[/bold]")
        perm_subs = await _permutate_subs(all_subs, rd, ws, _p)
        if perm_subs:
            all_subs.update(perm_subs)
            _p(f"  [green]✓[/green]  Total after permutation: {len(all_subs)}")

    # ─── Stage 3: GitHub dorking (v14) ────────────────────────────────────
    _p(f"\n  [bold]Stage 3: OSINT enrichment[/bold]")
    gh_count = await _osint_github_dorks(rd, ctx, ws, _p)
    if gh_count:
        _p(f"  [green]✓[/green]  GitHub: {gh_count} dork hit(s)")

    # ─── Stage 4: ASN discovery ───────────────────────────────────────────
    asn, cidrs = await _discover_asn(rd, engine, _p)
    if cidrs:
        try:
            os.makedirs(os.path.join(ws, "recon"), exist_ok=True)
            with open(os.path.join(ws, "recon", "asn_ranges.txt"), "w") as f:
                f.write("\n".join(cidrs) + "\n")
        except Exception:
            pass

    # ─── Persist ──────────────────────────────────────────────────────────
    ctx.add_subdomains_bulk(sorted(all_subs), source="step01")
    try:
        os.makedirs(os.path.join(ws, "recon"), exist_ok=True)
        with open(os.path.join(ws, "recon", "subdomains_raw.txt"), "w") as f:
            f.write("\n".join(sorted(all_subs)) + "\n")
    except Exception:
        pass

    kept = len(ctx.subdomains)
    dropped = len(all_subs) - kept
    _p(f"\n  [bold]Phase 1 Complete:[/bold] {kept} in-scope subdomains"
       + (f" [dim]({dropped} out of scope — recorded, never probed; "
          f"use --wildcard or --scope-file to widen)[/dim]" if dropped > 0 else ""))
    return ctx
