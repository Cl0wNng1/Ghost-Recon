"""
GHOST RECON v2.0 — modules/step00_deps.py
STEP 0: Dependency & Environment Validation

Validates that the host environment is ready for a full recon pipeline.
Checks required/optional binaries, Python packages, API keys, and
resolver file availability. Logs clear warnings for degraded capabilities.

Entry point: async def execute(ctx, engine, config) -> Ctx
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

# ═══════════════════════════════════════════════════════════════════════════════
# STEP METADATA
# ═══════════════════════════════════════════════════════════════════════════════

STEP_NUM = 0
STEP_NAME = "Dependency & Environment Validation"

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ToolDef:
    """Definition of an external tool dependency."""
    name: str
    binary: str                     # Binary name in $PATH
    required: bool = False          # True = core capability, False = optional
    category: str = "recon"         # recon|enum|fuzz|vuln|util
    used_in_steps: str = ""         # Which steps use this tool
    install_hint: str = ""          # How to install
    found: bool = False             # Set at runtime
    version: str = ""               # Detected version (best-effort)


# ─── Required tools (core pipeline will be severely degraded without these) ───
REQUIRED_TOOLS: List[ToolDef] = [
    ToolDef("subfinder",    "subfinder",    required=True, category="enum",
            used_in_steps="1",
            install_hint="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolDef("httpx",        "httpx",        required=True, category="enum",
            used_in_steps="2,3",
            install_hint="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolDef("ffuf",         "ffuf",         required=True, category="fuzz",
            used_in_steps="12,13",
            install_hint="go install -v github.com/ffuf/ffuf/v2@latest"),
    ToolDef("nuclei",       "nuclei",       required=True, category="vuln",
            used_in_steps="8",
            install_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
]

# ─── Optional tools (enhance specific capabilities) ──────────────────────────
OPTIONAL_TOOLS: List[ToolDef] = [
    # Subdomain enum
    ToolDef("amass",        "amass",        category="enum",
            used_in_steps="1",
            install_hint="go install -v github.com/owasp-amass/amass/v4/...@latest"),
    ToolDef("assetfinder",  "assetfinder",  category="enum",
            used_in_steps="1",
            install_hint="go install -v github.com/tomnomnom/assetfinder@latest"),
    ToolDef("massdns",      "massdns",      category="enum",
            used_in_steps="2",
            install_hint="git clone https://github.com/blechschmidt/massdns && cd massdns && make"),
    ToolDef("dnsx",         "dnsx",         category="enum",
            used_in_steps="2",
            install_hint="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),

    # URL / crawl
    ToolDef("waybackurls",  "waybackurls",  category="recon",
            used_in_steps="4",
            install_hint="go install -v github.com/tomnomnom/waybackurls@latest"),
    ToolDef("gau",          "gau",          category="recon",
            used_in_steps="4",
            install_hint="go install -v github.com/lc/gau/v2/cmd/gau@latest"),
    ToolDef("katana",       "katana",       category="recon",
            used_in_steps="4",
            install_hint="go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),

    # Params / patterns
    ToolDef("arjun",        "arjun",        category="enum",
            used_in_steps="7",
            install_hint="pip install arjun --break-system-packages"),
    ToolDef("paramspider",  "paramspider",  category="enum",
            used_in_steps="7",
            install_hint="pip install paramspider --break-system-packages"),
    ToolDef("gf",           "gf",           category="enum",
            used_in_steps="7",
            install_hint="go install -v github.com/tomnomnom/gf@latest"),

    # Vuln-specific
    ToolDef("dalfox",       "dalfox",       category="vuln",
            used_in_steps="8",
            install_hint="go install -v github.com/hahwul/dalfox/v2@latest"),
    ToolDef("ghauri",       "ghauri",       category="vuln",
            used_in_steps="8",
            install_hint="pip install ghauri --break-system-packages"),
    ToolDef("crlfuzz",      "crlfuzz",      category="vuln",
            used_in_steps="8",
            install_hint="go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
    ToolDef("corsy",        "corsy",        category="vuln",
            used_in_steps="8",
            install_hint="pip install corsy --break-system-packages"),

    # Visual recon
    ToolDef("gowitness",    "gowitness",    category="recon",
            used_in_steps="3",
            install_hint="go install -v github.com/sensepost/gowitness@latest"),

    # Port scanning
    ToolDef("nmap",         "nmap",         category="recon",
            used_in_steps="9",
            install_hint="apt install nmap"),
    ToolDef("rustscan",     "rustscan",     category="recon",
            used_in_steps="9",
            install_hint="cargo install rustscan"),

    # Wordlist gen
    ToolDef("cewl",         "cewl",         category="util",
            used_in_steps="11,12",
            install_hint="apt install cewl"),
    ToolDef("crunch",       "crunch",       category="util",
            used_in_steps="11,12",
            install_hint="apt install crunch"),

    # CMS
    ToolDef("whatweb",      "whatweb",      category="recon",
            used_in_steps="3",
            install_hint="apt install whatweb"),
    ToolDef("wpscan",       "wpscan",       category="vuln",
            used_in_steps="8",
            install_hint="gem install wpscan"),

    # Origin IP
    ToolDef("hakoriginfinder", "hakoriginfinder", category="recon",
            used_in_steps="1,9",
            install_hint="go install -v github.com/hakluke/hakoriginfinder@latest"),
    ToolDef("prips",        "prips",        category="util",
            used_in_steps="9",
            install_hint="apt install prips"),

    # Notify
    ToolDef("notify",       "notify",       category="util",
            used_in_steps="*",
            install_hint="go install -v github.com/projectdiscovery/notify/cmd/notify@latest"),

    # Dirsearch fallback
    ToolDef("dirsearch",    "dirsearch",    category="fuzz",
            used_in_steps="12",
            install_hint="pip install dirsearch --break-system-packages"),
]

# ─── API keys to check ───────────────────────────────────────────────────────
API_KEY_CHECKS: List[Tuple[str, str, str]] = [
    # (env_var, description, used_in_steps)
    ("SHODAN_API_KEY",       "Shodan (IP intel, port data)",       "1,9"),
    ("GITHUB_TOKEN",         "GitHub (secret dorking)",            "6,10"),
    ("SECURITYTRAILS_KEY",   "SecurityTrails (DNS history)",       "1"),
    ("DISCORD_WEBHOOK",      "Discord (notifications)",            "*"),
    ("SLACK_WEBHOOK",        "Slack (notifications)",              "*"),
    ("TELEGRAM_BOT",         "Telegram (notifications)",           "*"),
    ("VIRUSTOTAL_API_KEY",   "VirusTotal (subdomain enum)",        "1"),
    ("CENSYS_API_ID",        "Censys (host search)",               "9"),
]

# ─── Python packages ─────────────────────────────────────────────────────────
PYTHON_CHECKS: List[Tuple[str, str, bool]] = [
    # (import_name, description, required)
    ("httpx",  "Async HTTP engine (ghost_core)",  True),
    ("rich",   "Terminal UI/UX",                   False),
]


# ═══════════════════════════════════════════════════════════════════════════════
# VERSION DETECTION (best-effort, non-blocking)
# ═══════════════════════════════════════════════════════════════════════════════

async def _get_version(binary: str) -> str:
    """Try to get tool version via --version or -version. Returns '' on failure."""
    for flag in ("--version", "-version", "-v", "version"):
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            output = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(errors="replace")
            # Extract first line with a version-like pattern
            import re
            for line in output.strip().split("\n")[:3]:
                m = re.search(r'v?(\d+\.\d+(?:\.\d+)?)', line)
                if m:
                    return m.group(1)
        except (asyncio.TimeoutError, FileNotFoundError, OSError, Exception):
            continue
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTE
# ═══════════════════════════════════════════════════════════════════════════════

async def execute(ctx: Any, engine: Any, config: Any) -> Any:
    """STEP 0: Validate environment — binaries, Python packages, API keys.

    Never crashes. Logs warnings for missing optional deps. Returns ctx unmodified.
    """
    console = Console() if _RICH else None

    def _print(msg: str) -> None:
        if console:
            console.print(msg)
        else:
            import re
            print(re.sub(r'\[/?[^\]]*\]', '', msg))

    _print(f"  [bold]Scanning environment...[/bold]")

    # ─── 1. Binary checks ─────────────────────────────────────────────────────
    all_tools = REQUIRED_TOOLS + OPTIONAL_TOOLS
    found_count = 0
    missing_required: List[ToolDef] = []
    missing_optional: List[ToolDef] = []
    available_tools: Dict[str, str] = {}  # name → version

    # Check all binaries in parallel (just shutil.which, very fast)
    for tool in all_tools:
        path = shutil.which(tool.binary)
        if tool.binary == "httpx":
            # v2.0: don't mistake the Python httpx CLI for ProjectDiscovery httpx.
            from core.tools import resolve_pd_httpx
            path = resolve_pd_httpx()
        tool.found = path is not None
        if tool.found:
            found_count += 1
            available_tools[tool.name] = path or ""
        elif tool.required:
            missing_required.append(tool)
        else:
            missing_optional.append(tool)

    # Get versions for found tools (concurrent, with timeout)
    if available_tools:
        version_tasks = {
            name: _get_version(name) for name in list(available_tools.keys())[:15]
        }
        try:
            results = await asyncio.gather(
                *version_tasks.values(), return_exceptions=True
            )
            for (name, _), result in zip(version_tasks.items(), results):
                if isinstance(result, str) and result:
                    # Find the tool and set its version
                    for t in all_tools:
                        if t.name == name:
                            t.version = result
                            break
        except Exception:
            pass

    # ─── Display results ──────────────────────────────────────────────────────
    if _RICH and console:
        table = Table(
            title="Tool Availability",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("Tool", style="white", width=18)
        table.add_column("Status", width=10)
        table.add_column("Version", width=10, style="dim")
        table.add_column("Category", width=8, style="dim")
        table.add_column("Steps", width=8, style="dim")

        # Required first
        for tool in REQUIRED_TOOLS:
            status = "[bold green]✓ Found[/bold green]" if tool.found else "[bold red]✗ MISSING[/bold red]"
            table.add_row(
                f"[bold]{tool.name}[/bold]" + (" [red]*[/red]" if tool.required else ""),
                status,
                tool.version or "—",
                tool.category,
                tool.used_in_steps,
            )

        # Optional (only show missing ones to keep it concise, plus found ones)
        found_optional = [t for t in OPTIONAL_TOOLS if t.found]
        for tool in found_optional:
            table.add_row(tool.name, "[green]✓ Found[/green]", tool.version or "—",
                          tool.category, tool.used_in_steps)

        if missing_optional:
            table.add_row("", "", "", "", "", style="dim")
            for tool in missing_optional[:10]:
                table.add_row(
                    f"[dim]{tool.name}[/dim]", "[yellow]○ Missing[/yellow]",
                    "—", tool.category, tool.used_in_steps,
                )
            if len(missing_optional) > 10:
                table.add_row(
                    f"[dim]... +{len(missing_optional)-10} more[/dim]",
                    "", "", "", "",
                )

        console.print(table)
    else:
        _print(f"  Tools found: {found_count}/{len(all_tools)}")
        for t in missing_required:
            _print(f"  [red]✗ REQUIRED MISSING: {t.name}[/red] → {t.install_hint}")

    # ─── Required tool warnings ───────────────────────────────────────────────
    if missing_required:
        _print("")
        _print(f"  [bold red]⚠  {len(missing_required)} REQUIRED tool(s) missing:[/bold red]")
        for tool in missing_required:
            _print(f"    [red]✗ {tool.name}[/red] (Steps {tool.used_in_steps})")
            _print(f"      Install: [cyan]{tool.install_hint}[/cyan]")
        _print("")
        _print(
            f"  [yellow]Pipeline will continue but Steps "
            f"{', '.join(t.used_in_steps for t in missing_required)} "
            f"will have degraded capabilities.[/yellow]"
        )

    if missing_optional and not missing_required:
        _print(
            f"\n  [dim]{len(missing_optional)} optional tool(s) missing — "
            f"some advanced capabilities degraded[/dim]"
        )

    # ─── 2. Python package checks ─────────────────────────────────────────────
    _print("")
    py_missing: List[Tuple[str, str]] = []
    for pkg_name, desc, required in PYTHON_CHECKS:
        try:
            __import__(pkg_name)
            _print(f"  [green]✓[/green]  Python: {pkg_name} ({desc})")
        except ImportError:
            marker = "[red]REQUIRED[/red]" if required else "[yellow]optional[/yellow]"
            _print(f"  [red]✗[/red]  Python: {pkg_name} ({desc}) — {marker}")
            py_missing.append((pkg_name, desc))

    if py_missing:
        pkgs = " ".join(p for p, _ in py_missing)
        _print(f"  [dim]Install: pip install {pkgs} --break-system-packages[/dim]")

    # ─── 3. API key checks ────────────────────────────────────────────────────
    _print("")
    keys_found = 0
    keys_missing: List[Tuple[str, str, str]] = []

    for env_var, desc, steps in API_KEY_CHECKS:
        val = os.environ.get(env_var, "") or getattr(config, env_var.lower(), "")
        if val:
            masked = val[:6] + "***" if len(val) > 6 else "***"
            _print(f"  [green]✓[/green]  {env_var}: {masked} ({desc})")
            keys_found += 1
        else:
            keys_missing.append((env_var, desc, steps))

    if keys_missing:
        _print(f"\n  [dim]{len(keys_missing)} API key(s) not configured:[/dim]")
        for env_var, desc, steps in keys_missing:
            _print(f"    [dim]○ {env_var} — {desc} (Steps {steps})[/dim]")
        _print(f"  [dim]Set via environment variables or CLI flags for enhanced results.[/dim]")

    # ─── 4. Resolver file check ───────────────────────────────────────────────
    _print("")
    resolver_paths = [
        config.resolver_file if hasattr(config, 'resolver_file') and config.resolver_file else "",
        os.path.expanduser("~/.config/resolvers.txt"),
        "/usr/share/massdns/lists/resolvers.txt",
        os.path.expanduser("~/resolvers.txt"),
    ]
    resolver_found = False
    for rp in resolver_paths:
        if rp and os.path.isfile(rp):
            try:
                line_count = sum(1 for _ in open(rp))
            except Exception:
                line_count = 0
            _print(f"  [green]✓[/green]  Resolver file: {rp} ({line_count} resolvers)")
            resolver_found = True
            break
    if not resolver_found:
        _print(
            f"  [yellow]○[/yellow]  No resolver file found — MassDNS/dnsx will use defaults"
        )
        _print(
            f"    [dim]Recommended: Download from "
            f"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt[/dim]"
        )

    # ─── 5. Summary ───────────────────────────────────────────────────────────
    _print("")
    total_tools = len(all_tools)
    _print(
        f"  [bold]Summary:[/bold] {found_count}/{total_tools} tools | "
        f"{keys_found}/{len(API_KEY_CHECKS)} API keys | "
        f"{'resolver ✓' if resolver_found else 'no resolver'}"
    )

    if not missing_required:
        _print(f"  [bold green]✓ Environment ready for full pipeline execution[/bold green]")
    else:
        _print(
            f"  [bold yellow]⚠ Environment partially ready — "
            f"install required tools for full coverage[/bold yellow]"
        )

    return ctx
