#!/usr/bin/env python3
"""
GHOST RECON v2.0 — scope-aware automated recon & AppSec pipeline.

USAGE:
  python3 ghost.py -u https://target.com
  python3 ghost.py -u '*.target.com' --stealth high --exclude legacy.target.com
  python3 ghost.py -u target.com --steps 0-4 --format json,md
  python3 ghost.py --config engagement.yml --fail-on high
  python3 ghost.py --list-steps
  python3 ghost.py --resume ./hunt_target_com_20261011_120000/

Only scan assets you are explicitly authorised to test.
"""

from __future__ import annotations

import importlib
import json
import os
import signal
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol

# ═══════════════════════════════════════════════════════════════════════════════
# ENSURE RICH IS AVAILABLE
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _HAS_RICH = True
except ImportError:
    # ─── Minimal Rich Fallback (production: pip install rich) ─────────────────
    _HAS_RICH = False

    class _FakeBox:
        SIMPLE_HEAVY = None
        ROUNDED = None
    box = _FakeBox()

    class Console:
        def print(self, *a, **kw):
            import re
            text = str(a[0]) if a else ""
            clean = re.sub(r'\[/?[^\]]*\]', '', text)
            print(clean)
        def rule(self, title="", **kw):
            clean_title = __import__('re').sub(r'\[/?[^\]]*\]', '', str(title))
            print(f"{'━' * 20} {clean_title} {'━' * 20}")

    class Panel:
        def __init__(self, content, **kw):
            self._content = content
            self._title = kw.get("title", "")
        def __str__(self):
            return f"── {self._title} ──\n{self._content}\n{'─' * 40}"
        def __rich_console__(self, *a, **kw):
            yield str(self)

    class Table:
        def __init__(self, **kw):
            self._title = kw.get("title", "")
            self._cols = []
            self._rows = []
        def add_column(self, name, **kw):
            self._cols.append(name)
        def add_row(self, *vals, **kw):
            self._rows.append(vals)
        def __str__(self):
            lines = [self._title] if self._title else []
            for row in self._rows:
                lines.append("  " + " | ".join(str(v) for v in row))
            return "\n".join(lines)
        def __rich_console__(self, *a, **kw):
            yield str(self)

    class Text:
        pass

    # Monkey-patch Console.print to handle Table/Panel objects
    _orig_console_print = Console.print
    def _patched_print(self, *a, **kw):
        if a and hasattr(a[0], '__rich_console__'):
            print(str(a[0]))
        else:
            _orig_console_print(self, *a, **kw)
    Console.print = _patched_print

# ═══════════════════════════════════════════════════════════════════════════════
# CORE IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

from core.config import Config, build_config, VERSION, TOTAL_STEPS, STEALTH_PROFILES, SECRET_FIELDS
from core.db import GhostDB, find_scan_db, get_resume_info
from core.context import Ctx
from core.pipeline import STEP_DEFINITIONS, PipelineLoop, completed_from_snapshot

# ═══════════════════════════════════════════════════════════════════════════════
# v13: OSINT CLIENTS + SECRET VALIDATOR (fixes Token Amnesia)
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from core.api_clients import OSINTClients
    _HAS_OSINT = True
except ImportError:
    _HAS_OSINT = False

try:
    from core.secret_validator import SecretValidator
    _HAS_VALIDATOR = True
except ImportError:
    _HAS_VALIDATOR = False

# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD REGISTRY LOADER (v12 — recursive flattening)
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from core.payload_loader import load_payload_registry
except ImportError:
    def load_payload_registry(payloads_dir: str, console: Console) -> Dict[str, Any]:
        """Fallback payload loader if core.payload_loader is missing."""
        registry: Dict[str, Any] = {}
        pdir = Path(payloads_dir)
        if not pdir.is_dir():
            console.print(f"  [dim]Payloads directory not found: {payloads_dir}[/dim]")
            return registry
        try:
            import yaml as _yaml
        except ImportError:
            console.print(f"  [dim]PyYAML not installed — payload registry empty[/dim]")
            return registry
        for yml_file in sorted(pdir.glob("*.yml")):
            try:
                data = _yaml.safe_load(yml_file.read_text())
                if data:
                    registry[yml_file.stem] = data
            except Exception as e:
                console.print(f"  [yellow]⚠[/yellow]  Failed to load {yml_file.name}: {e}")
        if registry:
            console.print(f"  [green]✓[/green]  Payload registry: {len(registry)} files ({', '.join(registry.keys())})")
        return registry

# ═══════════════════════════════════════════════════════════════════════════════
# GHOST_CORE ENGINE (existing async HTTP engine)
# ═══════════════════════════════════════════════════════════════════════════════

_HAS_CORE = False
_engine = None

try:
    import ghost_core
    _HAS_CORE = True
except ImportError:
    pass  # Handled gracefully below


# ═══════════════════════════════════════════════════════════════════════════════
# STEP MODULE PROTOCOL
# ═══════════════════════════════════════════════════════════════════════════════

class StepModule(Protocol):
    """Protocol that all step modules must satisfy."""
    STEP_NUM: int
    STEP_NAME: str
    async def execute(self, ctx: Ctx, engine: Any, config: Config) -> Ctx: ...


# Step registry lives in core/pipeline.py (STEP_DEFINITIONS) so the CLI,
# tests and resume logic all share one definition.


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC MODULE LOADER
# ═══════════════════════════════════════════════════════════════════════════════

def load_step_module(module_path: str, console: Console) -> Optional[Any]:
    """Dynamically import a step module. Returns None if not found."""
    try:
        mod = importlib.import_module(module_path)
        # Validate the module has the required interface
        if not hasattr(mod, "execute"):
            console.print(
                f"  [yellow]⚠[/yellow]  Module [bold]{module_path}[/bold] has no "
                f"execute() function — skipping"
            )
            return None
        return mod
    except ModuleNotFoundError:
        return None
    except Exception as e:
        console.print(
            f"  [red]✗[/red]  Error loading [bold]{module_path}[/bold]: {e}"
        )
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = """[bold red]
   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓    ██▀███  ▓█████  ▄████▄
  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒▓  ██▒ ▓▒   ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█
 ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄ ▒ ▓██░ ▒░   ▓██ ░▄█ ▒▒███   ▒▓█    ▄
 ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░   ▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒
 ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░   ░██▓ ▒██▒░▒████▒▒ ▓███▀ ░[/bold red]"""

SUB_BANNER = f"""[red]  ╔═══════════════════════════════════════════════════════════════╗
  ║  GHOST RECON v{VERSION:<8} — scope-aware recon & AppSec pipeline  ║
  ║  CDN-aware • OSINT • Secret validation • Authz diffing        ║
  ║  JSON / Markdown / SARIF / HTML reports • CI exit codes       ║
  ╚═══════════════════════════════════════════════════════════════╝[/red]"""


# ═══════════════════════════════════════════════════════════════════════════════
# WORKSPACE SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def setup_workspace(config: Config) -> Path:
    """Create the output workspace directory structure."""
    if config.output_dir:
        ws = Path(config.output_dir)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = config.domain.replace(".", "_")
        ws = Path(f"./hunt_{safe_domain}_{ts}")

    # Create subdirectories
    for subdir in ["recon", "enum", "fuzz", "vulns", "secrets", "nuclei", "osint", "reports"]:
        (ws / subdir).mkdir(parents=True, exist_ok=True)

    config.workspace = str(ws.resolve())
    return ws


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def init_engine(config: Config, console: Console) -> Optional[Any]:
    """Initialize the ghost_core async HTTP engine."""
    if not _HAS_CORE:
        console.print(
            "  [yellow]⚠[/yellow]  ghost_core.py not found — HTTP engine will use "
            "subprocess fallback"
        )
        return None

    engine = ghost_core.init_engine(
        rate=config.rate,
        max_concurrency=config.concurrency,
        proxy=config.proxy,
    )
    console.print(
        f"  [green]✓[/green]  Async engine: httpx, rate={config.rate}/s, "
        f"concurrency={config.concurrency}"
    )
    console.print(
        f"  [green]✓[/green]  Validator: 3-layer pipeline (baseline → cluster → semantic)"
    )
    return engine


def shutdown_engine(console: Console) -> None:
    """Gracefully shut down the async HTTP engine."""
    if _HAS_CORE:
        try:
            ghost_core.shutdown_engine()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# STEP EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

def run_step(
    step_def: Dict[str, Any],
    ctx: Ctx,
    engine: Any,
    config: Config,
    console: Console,
    runner: PipelineLoop,
) -> Ctx:
    """Execute one step on the persistent loop; checkpoint only on success."""
    step_num: int = step_def["num"]
    step_name: str = step_def["name"]
    module_path: str = step_def["module"]

    console.print()
    console.rule(f"[bold blue]  STEP {step_num}  [/bold blue] {step_name}", style="blue")

    if not config.should_run_step(step_num):
        console.print("  [dim]⊘  Skipped (--steps / --skip-steps)[/dim]")
        return ctx

    mod = load_step_module(module_path, console)
    if mod is None:
        console.print(f"  [yellow]⊘[/yellow]  Module [bold]{module_path}[/bold] not found — skipping")
        return ctx

    t0 = time.monotonic()
    try:
        result = runner.run(mod.execute(ctx, engine, config))
        if result is not None:
            ctx = result
        console.print(f"  [green]✓[/green]  Completed in {time.monotonic() - t0:.1f}s")
    except KeyboardInterrupt:
        raise
    except Exception as e:
        console.print(f"  [red]✗[/red]  FAILED after {time.monotonic() - t0:.1f}s: {e}")
        console.print(f"  [dim]{traceback.format_exc()}[/dim]")
        # Not marked complete, so --resume will retry this step.
        return ctx

    ctx.completed_steps.add(step_num)
    try:
        ctx.save_checkpoint(step_num + 1)
        console.print(f"  [dim]💾 Checkpoint saved ({len(ctx.completed_steps)} steps complete)[/dim]")
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow]  Checkpoint save failed: {e}")
    return ctx


def print_steps(console: Console, config: Optional[Config] = None) -> None:
    """--list-steps / --dry-run pipeline table."""
    t = Table(title="Pipeline (execution order)", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    t.add_column("#", justify="right", style="dim")
    t.add_column("ID", justify="right", style="bold")
    t.add_column("Step")
    t.add_column("Touches target", justify="center")
    t.add_column("Run", justify="center")
    for i, sd in enumerate(STEP_DEFINITIONS, 1):
        run = "✓" if config is None or config.should_run_step(sd["num"]) else "—"
        t.add_row(str(i), str(sd["num"]), sd["name"], "yes" if sd.get("active") else "passive", run)
    console.print(t)
    console.print("  [dim]Use the ID with --steps / --skip-steps, e.g. --steps 0-4,15[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

def display_summary(ctx: Ctx, config: Config, console: Console, elapsed: float) -> None:
    """Display the final scan summary using Rich."""
    stats = ctx.stats()
    severity_counts = ctx.findings_by_severity()

    # ─── Stats table ──────────────────────────────────────────────────────────
    stats_table = Table(
        title="Scan Statistics",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
    )
    stats_table.add_column("Metric", style="white")
    stats_table.add_column("Count", style="bold green", justify="right")

    stats_table.add_row("Subdomains", str(stats.get("subdomains", 0)))
    stats_table.add_row("Live Hosts", str(stats.get("live_hosts", 0)))
    stats_table.add_row("URLs", str(stats.get("urls", 0)))
    stats_table.add_row("JS Files", str(stats.get("js_files", 0)))
    stats_table.add_row("Parameters", str(stats.get("params", 0)))
    stats_table.add_row("API Endpoints", str(stats.get("api_endpoints", 0)))
    stats_table.add_row("Ports", str(stats.get("ports", 0)))
    stats_table.add_row("Secrets", str(stats.get("secrets", 0)))
    stats_table.add_row("Paths (200)", str(stats.get("paths_200", 0)))
    stats_table.add_row("Paths (403)", str(stats.get("paths_403", 0)))
    oos = len(getattr(ctx, "out_of_scope_hosts", ()))
    if oos:
        stats_table.add_row("Out of scope (dropped)", str(oos))

    console.print()
    console.print(stats_table)

    # ─── Findings table ───────────────────────────────────────────────────────
    total_findings = ctx.finding_count()
    sev_icons = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
    }
    sev_styles = {
        "CRITICAL": "bold red", "HIGH": "bold yellow", "MEDIUM": "yellow",
        "LOW": "blue", "INFO": "dim",
    }

    if total_findings > 0:
        findings_table = Table(
            title=f"🎯 {total_findings} Findings",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold red",
        )
        findings_table.add_column("#", style="dim", width=4)
        findings_table.add_column("Sev", width=10)
        findings_table.add_column("CVSS", width=5, justify="right")
        findings_table.add_column("Category", width=20)
        findings_table.add_column("Title", max_width=50)
        findings_table.add_column("Confidence", width=12)

        for i, f in enumerate(ctx.findings[:30], 1):
            sev = f.get("severity", "INFO")
            style = sev_styles.get(sev, "")
            findings_table.add_row(
                str(i),
                f"{sev_icons.get(sev, '⚪')} {sev}",
                f"{f.get('cvss_score', 0):.1f}",
                f.get("category", ""),
                f.get("title", "")[:50],
                f.get("confidence", ""),
                style=style,
            )

        if total_findings > 30:
            findings_table.add_row(
                "...", "", "", "", f"... and {total_findings - 30} more", "",
                style="dim",
            )

        console.print()
        console.print(findings_table)

        # Severity breakdown
        sev_parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = severity_counts.get(sev, 0)
            if count > 0:
                sev_parts.append(f"{sev_icons[sev]} {sev}: {count}")
        if sev_parts:
            console.print(f"  {' │ '.join(sev_parts)}")
    else:
        console.print("\n  [green]✓ Clean — no findings. Manual testing recommended.[/green]")

    # ─── Diff (if previous scan exists) ───────────────────────────────────────
    diff = ctx.diff_previous()
    if diff:
        new_count = len(diff.get("new_findings", []))
        resolved_count = len(diff.get("resolved_findings", []))
        new_subs = len(diff.get("new_subdomains", []))
        removed_subs = len(diff.get("removed_subdomains", []))
        if new_count or resolved_count or new_subs or removed_subs:
            console.print()
            console.print(Panel(
                f"[bold]Diff vs. Previous Scan[/bold]\n"
                f"  New findings: [red]{new_count}[/red] | "
                f"Resolved: [green]{resolved_count}[/green]\n"
                f"  New subdomains: [cyan]{new_subs}[/cyan] | "
                f"Removed: [dim]{removed_subs}[/dim]",
                title="📊 Delta",
                border_style="cyan",
            ))

    # ─── Footer ───────────────────────────────────────────────────────────────
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    console.print()
    console.rule(style="green")
    console.print(
        f"  [cyan]Workspace[/cyan] : {config.workspace}",
    )
    console.print(
        f"  [cyan]Database [/cyan] : {config.workspace}/ghost.db",
    )
    console.print(
        f"  [cyan]Duration [/cyan] : {minutes}m {seconds}s",
    )
    console.rule(style="green")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def _restore_config_from_db(config: Config, db: GhostDB, scan_id: str) -> None:
    """Re-apply the original scan's (non-secret) settings on --resume."""
    row = db.get_scan(scan_id)
    try:
        saved = json.loads((row or {})["config_json"] or "{}")
    except Exception:
        saved = {}
    skip = set(SECRET_FIELDS) | {"resume", "resume_dir", "workspace", "dry_run", "list_steps", "no_banner"}
    for k, v in saved.items():
        if k in skip or not hasattr(config, k):
            continue
        setattr(config, k, v)
    for k, v in getattr(config, "_resume_overrides", {}).items():
        setattr(config, k, v)


def _dry_run(config: Config, console: Console) -> int:
    from core.scope import build_scope_guard
    guard = build_scope_guard(config, None, enforce=config.scope_enforce)
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("Key", style="cyan", width=14)
    t.add_column("Value", style="white")
    t.add_row("Target", config.target_url)
    t.add_row("Domain", f"{config.domain} (registrable: {config.root_domain})")
    t.add_row("Scope", f"{config.scope.upper()}  —  {guard.describe()}")
    t.add_row("Strict scope", str(config.scope_enforce))
    t.add_row("Throughput", f"{config.stealth}: {config.rate}/s, concurrency {config.concurrency}")
    t.add_row("Auth", config.auth_mode)
    t.add_row("Authz roles", ", ".join(config.authz_roles) or "—")
    t.add_row("Reports", ", ".join(config.formats))
    t.add_row("Fail on", config.fail_on or "—")
    console.print(Panel(t, title="Dry run — no traffic sent, no workspace created", border_style="cyan"))
    print_steps(console, config)
    return 0


def _close_async(runner: PipelineLoop, obj: Any) -> None:
    if obj is None or not hasattr(obj, "close"):
        return
    try:
        runner.run(obj.close())
    except Exception:
        pass


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point. Returns exit code (0 ok, 1 error, 2 --fail-on hit, 130 interrupted)."""
    start_time = time.monotonic()
    console = Console()

    try:
        config = build_config(argv)
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 1

    if not config.no_banner:
        console.print(BANNER)
        console.print(SUB_BANNER)
        console.print()

    if config.list_steps:
        print_steps(console)
        return 0
    if config.dry_run and not config.resume:
        return _dry_run(config, console)

    # ─── Resume or new scan ───────────────────────────────────────────────────
    if config.resume:
        console.print(f"  [cyan]⟳ Resume mode[/cyan] : {config.resume_dir}")
        db_path = find_scan_db(config.resume_dir)
        if not db_path:
            console.print(f"  [red]✗[/red]  No ghost.db found in {config.resume_dir}")
            return 1
        resume_info = get_resume_info(db_path)
        if not resume_info:
            console.print("  [red]✗[/red]  No incomplete scan found in database")
            return 1
        db = GhostDB(db_path)
        scan_id = resume_info["scan_id"]
        config.workspace = str(Path(db_path).parent.resolve())
        ctx = Ctx.resume(db, scan_id)
        snapshot = resume_info.get("ctx_snapshot", {}) or {}
        ctx.restore_from_snapshot(snapshot)
        ctx.completed_steps = completed_from_snapshot(snapshot, resume_info.get("step") or 0)

        _restore_config_from_db(config, db, scan_id)
        config.target_url, config.domain = ctx.target, ctx.domain
        config.root_domain, config.scope, config.stealth = ctx.root_domain, ctx.scope, ctx.stealth
        console.print(f"  [green]✓[/green]  Found scan: {resume_info.get('target', '?')}")
        console.print(f"  [green]✓[/green]  Already complete: "
                      f"{sorted(ctx.completed_steps) or 'none'}")
        if config.dry_run:
            print_steps(console, config)
            db.close()
            return 0
    else:
        ws = setup_workspace(config)
        db = GhostDB(ws / "ghost.db")
        ctx = Ctx.new(
            db=db, target=config.target_url, domain=config.domain,
            root_domain=config.root_domain, scope=config.scope,
            stealth=config.stealth, config_json=config.to_json(),
        )
        if config.origin_ip:
            ctx.origin_ip = config.origin_ip
            ctx.persist_scan_state()

    # ─── Configuration panel ──────────────────────────────────────────────────
    console.print()
    info = Table(box=None, show_header=False, padding=(0, 2))
    info.add_column("Key", style="cyan", width=12)
    info.add_column("Value", style="white")
    info.add_row("Target", ctx.target)
    info.add_row("Domain", f"{ctx.domain} (registrable: {ctx.root_domain})")
    info.add_row("Stealth", f"{config.stealth} (rate={config.rate}/s, concurrency={config.concurrency})")
    info.add_row("Steps", (str(config.steps) if config.steps else "ALL")
                 + (f" minus {config.skip_steps}" if config.skip_steps else ""))
    flags = [n.upper().replace("_", "-") for n in
             ("osint", "logic", "notify", "aggressive", "skip_nuclei", "skip_subs") if getattr(config, n)]
    if config.scope_enforce:
        flags.append("STRICT-SCOPE")
    info.add_row("Flags", " ".join(flags) or "—")
    info.add_row("Auth", config.auth_mode + (f" | roles: {', '.join(config.authz_roles)}" if config.authz_roles else ""))
    if ctx.origin_ip:
        info.add_row("Origin IP", ctx.origin_ip)
    info.add_row("Workspace", config.workspace)
    info.add_row("Scan ID", ctx.scan_id[:12] + "…")
    console.print(Panel(info, title="Configuration", border_style="cyan"))

    # ─── One event loop for the whole scan ────────────────────────────────────
    runner = PipelineLoop()
    if _HAS_CORE and hasattr(ghost_core, "bind_loop"):
        ghost_core.bind_loop(runner.loop)

    engine = init_engine(config, console)
    ctx.engine = engine

    payloads_dir = str(Path(os.path.dirname(os.path.abspath(__file__))) / "payloads")
    ctx.payload_registry = load_payload_registry(payloads_dir, console)

    if _HAS_OSINT:
        ctx.osint = OSINTClients(
            shodan_key=config.shodan_key,
            github_token=config.github_token,
            securitytrails_key=config.securitytrails_key,
            virustotal_key=os.environ.get("VIRUSTOTAL_API_KEY", ""),
            censys_id=os.environ.get("CENSYS_API_ID", ""),
            censys_secret=os.environ.get("CENSYS_API_SECRET", ""),
        )
        active = ctx.osint.available_providers()
        console.print(f"  [green]✓[/green]  OSINT clients: {', '.join(active)}" if active
                      else "  [yellow]⚠[/yellow]  No OSINT API keys configured")
    else:
        ctx.osint = None

    if _HAS_VALIDATOR:
        ctx.secret_validator = SecretValidator(max_concurrency=3)
        console.print("  [green]✓[/green]  Secret validator: active")
    else:
        ctx.secret_validator = None

    # ─── Scope guard (data layer + engine + shared client) & auth session ─────
    from core.scope import build_scope_guard
    from core.http import build_http_client, AuthSession, auth_engine_headers

    ctx.scope_guard = build_scope_guard(config, ctx, enforce=config.scope_enforce)
    if engine is not None:
        engine.scope_guard = ctx.scope_guard
    auth = AuthSession()
    sess_path = os.path.join(config.workspace, "auth_session.json")
    if os.path.exists(sess_path):
        try:
            with open(sess_path, encoding="utf-8") as fh:
                auth = AuthSession.from_dict(json.load(fh))
            if auth.logged_in and engine is not None:
                engine.auth_headers = auth_engine_headers(auth)
                console.print("  [green]✓[/green]  Restored authenticated session")
        except Exception:
            auth = AuthSession()
    ctx.http = build_http_client(config, ctx.scope_guard, auth=auth)
    ctx.auth = ctx.http.auth
    console.print(f"  [green]✓[/green]  Scope: {ctx.scope_guard.describe()}"
                  + ("  [bold](strict)[/bold]" if config.scope_enforce else ""))

    if not hasattr(ctx, "log"):
        ctx.log = lambda msg, _c=console: _c.print(f"  [dim]{msg}[/dim]")

    # ─── Signal handler ───────────────────────────────────────────────────────
    interrupted = False

    def _sigint_handler(signum, frame):
        nonlocal interrupted
        if interrupted:
            console.print("\n  [red]Force quit.[/red]")
            sys.exit(130)
        interrupted = True
        console.print("\n  [yellow]⚠  Interrupt received — finishing current step, then "
                      "saving state and writing reports (Ctrl-C again to force quit)[/yellow]")

    signal.signal(signal.SIGINT, _sigint_handler)

    # ─── Pipeline ─────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold green] Pipeline Execution ", style="green")
    try:
        for step_def in STEP_DEFINITIONS:
            if interrupted:
                break
            if step_def["num"] in ctx.completed_steps:
                console.print(f"\n  [dim]⊘  STEP {step_def['num']}: {step_def['name']} "
                              f"— already completed (resume)[/dim]")
                continue
            ctx = run_step(step_def, ctx, engine, config, console, runner)
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n  [yellow]⚠  Interrupted — saving final state...[/yellow]")
    except Exception as e:
        console.print(f"\n  [red]✗  Fatal error: {e}[/red]")
        console.print(f"  [dim]{traceback.format_exc()}[/dim]")

    elapsed = time.monotonic() - start_time
    try:
        if interrupted:
            ctx.persist_scan_state()
        else:
            ctx.finalize()
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow]  Finalization error: {e}")

    # Out-of-scope audit trail
    if ctx.out_of_scope_hosts:
        try:
            oos = Path(config.workspace) / "recon" / "out_of_scope.txt"
            oos.parent.mkdir(parents=True, exist_ok=True)
            oos.write_text("\n".join(sorted(ctx.out_of_scope_hosts)) + "\n", encoding="utf-8")
        except Exception:
            pass

    console.print()
    console.rule("[bold green] Scan Complete ", style="green")
    display_summary(ctx, config, console, elapsed)

    # ─── Reports ──────────────────────────────────────────────────────────────
    reports_dir = os.path.join(config.workspace, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    if "html" in config.formats:
        try:
            from reports.html_report import generate_html
            html_path = os.path.join(reports_dir, "report.html")
            generate_html(ctx, config, html_path, elapsed)
            console.print(f"  [green]✓[/green]  HTML     → {html_path}")
        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow]  HTML report failed: {e}")
    try:
        from reports.exporters import export_all
        for fmt, path in export_all(ctx, config, elapsed, config.formats, reports_dir).items():
            console.print(f"  [green]✓[/green]  {fmt.upper():<8} → {path}")
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow]  Export failed: {e}")

    if config.notify:
        try:
            from core.notifications import notify_all
            runner.run(notify_all(ctx, config, elapsed))
            console.print("  [green]✓[/green]  Notifications sent")
        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow]  Notification failed: {e}")

    # ─── Shutdown (same loop the clients were created on) ─────────────────────
    for obj in (engine, getattr(ctx, "osint", None), getattr(ctx, "secret_validator", None),
                getattr(ctx, "http", None)):
        _close_async(runner, obj)
    runner.close()
    sev_counts = ctx.findings_by_severity()
    db.close()

    if interrupted:
        return 130
    if config.fail_threshold_hit(sev_counts):
        console.print(f"  [red]✗  --fail-on {config.fail_on}: threshold reached (exit 2)[/red]")
        return 2
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# MODULES __init__ (empty placeholder so imports work)
# ═══════════════════════════════════════════════════════════════════════════════

# This is handled by the modules/ directory having its own __init__.py


if __name__ == "__main__":
    sys.exit(main())
