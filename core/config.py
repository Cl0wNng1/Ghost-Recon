"""
GHOST RECON v2.0 — core/config.py
CLI argument parsing and configuration management.

Precedence (lowest → highest):
  built-in defaults  →  --config FILE (YAML/JSON)  →  environment (API keys)  →  CLI flags
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field, asdict, fields
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


VERSION = "2.0.0"
TOTAL_STEPS = 17  # step IDs 0-16 (see core/pipeline.py for execution order)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
EXPORT_FORMATS = ("html", "json", "md", "sarif")

# ═══════════════════════════════════════════════════════════════════════════════
# STEALTH PROFILES
# ═══════════════════════════════════════════════════════════════════════════════
# NOTE: "turbo" is the *slowest* profile (kept for backward compatibility; it was
# named for how far under the radar it flies, not for speed).

STEALTH_PROFILES: Dict[str, Dict[str, float | int]] = {
    "low":    {"rate": 30.0, "jitter": 0.1,  "cooldown": 3,  "cooldown_every": 200, "threads": 15, "phase_delay": 1,  "concurrency": 15},
    "medium": {"rate": 10.0, "jitter": 0.3,  "cooldown": 8,  "cooldown_every": 100, "threads": 8,  "phase_delay": 3,  "concurrency": 8},
    "high":   {"rate": 3.0,  "jitter": 0.8,  "cooldown": 15, "cooldown_every": 50,  "threads": 5,  "phase_delay": 8,  "concurrency": 5},
    "turbo":  {"rate": 1.0,  "jitter": 2.0,  "cooldown": 30, "cooldown_every": 25,  "threads": 2,  "phase_delay": 15, "concurrency": 2},
}

# Fields that hold credentials. Redacted whenever config is serialised
# (ghost.db, reports, --dry-run output).
SECRET_FIELDS = (
    "github_token", "shodan_key", "securitytrails_key",
    "discord_webhook", "slack_webhook", "telegram_bot", "telegram_chat",
    "auth_token_a", "auth_token_b",
    "auth_cookie", "auth_bearer", "auth_password", "auth_headers",
    "auth_extra_fields", "authz_roles",
)


def _redact_value(v: Any) -> Any:
    """Mask credentials completely; keep structure (dict keys, list length)."""
    if isinstance(v, bool) or isinstance(v, (int, float)) or v is None:
        return v
    if isinstance(v, str):
        return "***" if v else v
    if isinstance(v, dict):
        return {k: _redact_value(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_redact_value(x) for x in v]
    return "***"


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG DATACLASS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Config:
    """Scan configuration. Created from CLI args / config file, serialised to JSON."""

    # ─── Target ───────────────────────────────────────────────────────────────
    target_url: str = ""
    domain: str = ""
    root_domain: str = ""
    scope: str = "single"          # single | wildcard

    # ─── Stealth / throughput ─────────────────────────────────────────────────
    stealth: str = "medium"
    rate: float = 10.0
    concurrency: int = 8
    threads: int = 8
    user_agent: str = "GhostRecon/2.0"

    # ─── Execution ────────────────────────────────────────────────────────────
    steps: Optional[List[int]] = None       # None = all
    skip_steps: List[int] = field(default_factory=list)
    resume: bool = False
    resume_dir: str = ""
    output_dir: str = ""
    dry_run: bool = False
    list_steps: bool = False
    no_banner: bool = False
    config_file: str = ""

    # ─── Output ───────────────────────────────────────────────────────────────
    formats: List[str] = field(default_factory=lambda: list(EXPORT_FORMATS))
    fail_on: str = ""                       # "" | CRITICAL | HIGH | MEDIUM | LOW | INFO

    # ─── Features ─────────────────────────────────────────────────────────────
    aggressive: bool = False
    wildcard: bool = False
    osint: bool = False
    logic: bool = False
    notify: bool = False
    skip_subs: bool = False
    skip_nuclei: bool = False

    # ─── Network ──────────────────────────────────────────────────────────────
    proxy: str = ""
    proxy_file: str = ""
    resolver_file: str = ""
    origin_ip: str = ""

    # ─── API Keys ─────────────────────────────────────────────────────────────
    github_token: str = ""
    shodan_key: str = ""
    securitytrails_key: str = ""
    discord_webhook: str = ""
    slack_webhook: str = ""
    telegram_bot: str = ""
    telegram_chat: str = ""

    # ─── Legacy two-user BOLA tokens (folded into authz_roles) ────────────────
    auth_token_a: str = ""
    auth_token_b: str = ""

    # ─── Authenticated scanning ───────────────────────────────────────────────
    auth_mode: str = "none"          # none | cookie | bearer | form | raw
    auth_cookie: str = ""
    auth_bearer: str = ""
    auth_headers: dict = field(default_factory=dict)
    auth_login_url: str = ""
    auth_post_url: str = ""
    auth_username: str = ""
    auth_password: str = ""
    auth_user_field: str = "username"
    auth_pass_field: str = "password"
    auth_csrf_field: str = "csrf_token"
    auth_extra_fields: dict = field(default_factory=dict)
    auth_verify_url: str = ""
    auth_success_markers: list = field(default_factory=list)
    auth_failure_markers: list = field(default_factory=list)

    # ─── Scope enforcement ────────────────────────────────────────────────────
    scope_file: str = ""
    scope_enforce: bool = False      # --strict-scope
    scope_block_private: bool = True
    allow_hosts: list = field(default_factory=list)
    deny_hosts: list = field(default_factory=list)
    allow_cidrs: list = field(default_factory=list)
    deny_cidrs: list = field(default_factory=list)

    # ─── Access-control (authz) testing ───────────────────────────────────────
    authz_roles: dict = field(default_factory=dict)
    authz_similarity: float = 0.90
    authz_max_endpoints: int = 300

    # ─── Derived ──────────────────────────────────────────────────────────────
    workspace: str = ""

    # ── serialisation ─────────────────────────────────────────────────────────
    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        d = asdict(self)
        if redact:
            for key in SECRET_FIELDS:
                if d.get(key):
                    d[key] = _redact_value(d[key])
        return d

    def to_json(self) -> str:
        """Serialize config to JSON for DB storage (credentials redacted)."""
        return json.dumps(self.to_dict(redact=True), indent=2)

    @property
    def stealth_profile(self) -> Dict[str, float | int]:
        return STEALTH_PROFILES.get(self.stealth, STEALTH_PROFILES["medium"])

    def should_run_step(self, step_num: int) -> bool:
        if step_num in (self.skip_steps or []):
            return False
        if self.steps is None:
            return True
        return step_num in self.steps

    def fail_threshold_hit(self, severity_counts: Dict[str, int]) -> bool:
        """True if any finding is at or above --fail-on severity."""
        if not self.fail_on:
            return False
        lvl = self.fail_on.upper()
        if lvl not in SEVERITIES:
            return False
        idx = SEVERITIES.index(lvl)
        return any(severity_counts.get(s, 0) > 0 for s in SEVERITIES[: idx + 1])


# ═══════════════════════════════════════════════════════════════════════════════
# CLI PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _csv(raw: Optional[str]) -> List[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghost",
        description=f"GHOST RECON v{VERSION} — scope-aware automated recon & AppSec pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ghost.py -u https://target.com
  python3 ghost.py -u '*.target.com' --stealth high --exclude legacy.target.com
  python3 ghost.py -u target.com --steps 0-4 --format json,md
  python3 ghost.py -u target.com --scope-file scope.txt --strict-scope
  python3 ghost.py -u app.target.com --auth-mode bearer --auth-bearer "$TOKEN"
  python3 ghost.py -u target.com --role userA:bearer:$TA --role userB:bearer:$TB
  python3 ghost.py --config engagement.yml --fail-on high
  python3 ghost.py --list-steps
  python3 ghost.py --resume ./hunt_target_com_20261011_120000/

Only scan assets you are explicitly authorised to test.
        """,
    )
    p.add_argument("-V", "--version", action="version", version=f"ghost {VERSION}")

    g = p.add_argument_group("Target")
    g.add_argument("-u", "--url", help="Target URL or domain (prefix *. for wildcard scope)")
    g.add_argument("--config", dest="config_file", metavar="FILE",
                   help="YAML/JSON file with any Config field (CLI flags override it)")
    g.add_argument("--resume", metavar="WORKSPACE_DIR", help="Resume a previous scan")

    g = p.add_argument_group("Execution")
    g.add_argument("--steps", help="Run only these step IDs (e.g. '0,1,3' or '0-4,15')")
    g.add_argument("--skip-steps", help="Skip these step IDs (same syntax as --steps)")
    g.add_argument("--stealth", choices=list(STEALTH_PROFILES), default=None,
                   help="Stealth profile: low (fast) | medium (default) | high | turbo (slowest)")
    g.add_argument("--rate", type=float, help="Override requests/sec from the stealth profile")
    g.add_argument("--concurrency", type=int, help="Override concurrent requests")
    g.add_argument("--user-agent", help="User-Agent for the shared HTTP client")
    g.add_argument("-o", "--output", help="Output directory (default: ./hunt_<domain>_<ts>)")
    g.add_argument("--list-steps", action="store_true", help="Print the pipeline and exit")
    g.add_argument("--dry-run", action="store_true",
                   help="Show resolved config, scope and planned steps; send no traffic")
    g.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")

    g = p.add_argument_group("Scope")
    g.add_argument("--wildcard", action="store_true", help="Wildcard scope: target host + all subdomains")
    g.add_argument("--scope-file", help="Allow/deny list file (hosts, *.globs, CIDRs; prefix ! to deny)")
    g.add_argument("--include", help="Extra in-scope hosts/CIDRs, comma-separated")
    g.add_argument("--exclude", help="Out-of-scope hosts/CIDRs, comma-separated (deny always wins)")
    g.add_argument("--strict-scope", action="store_true",
                   help="Raise on any out-of-scope request and drop third-party JS")
    g.add_argument("--allow-private", action="store_true",
                   help="Permit RFC1918/loopback targets (lab / internal engagements)")

    g = p.add_argument_group("Output")
    g.add_argument("--format", dest="formats",
                   help=f"Report formats, comma-separated (default: {','.join(EXPORT_FORMATS)})")
    g.add_argument("--fail-on", type=str.upper, choices=list(SEVERITIES),
                   help="Exit with code 2 if any finding is at or above this severity (CI)")

    g = p.add_argument_group("Features")
    g.add_argument("--aggressive", action="store_true", help="Low stealth + OSINT + logic guide")
    g.add_argument("--osint", action="store_true", help="Enable OSINT (GitHub, cloud, WHOIS)")
    g.add_argument("--logic", action="store_true", help="Generate logic-bug testing guide")
    g.add_argument("--notify", action="store_true", help="Send alerts to Slack/Discord/Telegram")
    g.add_argument("--skip-subs", action="store_true", help="Skip subdomain enumeration")
    g.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scanning")

    g = p.add_argument_group("Network")
    g.add_argument("--proxy", help="HTTP/SOCKS proxy for in-process requests (e.g. Burp)")
    g.add_argument("--proxy-file", help="File with proxy list for rotation")
    g.add_argument("--resolver-file", help="File with DNS resolvers")
    g.add_argument("--origin", help="Known origin IP (added to scope automatically)")

    g = p.add_argument_group("Authentication")
    g.add_argument("--auth-mode", choices=["none", "cookie", "bearer", "form", "raw"])
    g.add_argument("--auth-cookie", default=os.environ.get("GHOST_AUTH_COOKIE"),
                   help="'name=val; name2=val2'  (env: GHOST_AUTH_COOKIE)")
    g.add_argument("--auth-bearer", default=os.environ.get("GHOST_AUTH_BEARER"),
                   help="Bearer token (env: GHOST_AUTH_BEARER)")
    g.add_argument("--auth-header", action="append", metavar="'Name: value'",
                   help="Raw header for --auth-mode raw (repeatable)")
    g.add_argument("--login-url", help="Form login page (GET for CSRF/cookies)")
    g.add_argument("--login-post-url", help="Form POST target (default: --login-url)")
    g.add_argument("--username")
    g.add_argument("--password", default=os.environ.get("GHOST_AUTH_PASSWORD"),
                   help="Prefer env GHOST_AUTH_PASSWORD to keep it out of shell history")
    g.add_argument("--user-field", help="Form username field (default: username)")
    g.add_argument("--pass-field", help="Form password field (default: password)")
    g.add_argument("--csrf-field", help="Form CSRF field (default: csrf_token)")
    g.add_argument("--auth-verify-url", help="Protected URL used to confirm the session")
    g.add_argument("--auth-success", action="append", metavar="TEXT", help="Logged-in marker (repeatable)")
    g.add_argument("--auth-failure", action="append", metavar="TEXT", help="Logged-out marker (repeatable)")

    g = p.add_argument_group("Access-control / IDOR testing")
    g.add_argument("--role", action="append", metavar="NAME:TYPE:VALUE",
                   help="Role for authz diffing; TYPE is cookie|bearer|header. "
                        "e.g. userA:bearer:eyJ...  admin:cookie:'sid=abc'  (repeatable; "
                        "an 'anon' role is added automatically)")
    g.add_argument("--authz-max-endpoints", type=int)
    g.add_argument("--auth-a", default=os.environ.get("AUTH_TOKEN_A", ""),
                   help="Legacy: bearer token for user A (becomes role userA)")
    g.add_argument("--auth-b", default=os.environ.get("AUTH_TOKEN_B", ""),
                   help="Legacy: bearer token for user B (becomes role userB)")

    g = p.add_argument_group("API keys (or env vars)")
    g.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    g.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY", ""))
    g.add_argument("--securitytrails-key", default=os.environ.get("SECURITYTRAILS_KEY", ""))
    g.add_argument("--discord-webhook", default=os.environ.get("DISCORD_WEBHOOK", ""))
    g.add_argument("--slack-webhook", default=os.environ.get("SLACK_WEBHOOK", ""))
    g.add_argument("--telegram-bot", default=os.environ.get("TELEGRAM_BOT", ""))
    g.add_argument("--telegram-chat", default=os.environ.get("TELEGRAM_CHAT", ""))

    return p


# ═══════════════════════════════════════════════════════════════════════════════
# TARGET PARSING
# ═══════════════════════════════════════════════════════════════════════════════

# Common multi-label public suffixes, used when `tldextract` is unavailable.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "govt.nz", "co.za", "org.za", "gov.za",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my",
    "com.mx", "com.ar", "com.co", "com.tr", "com.eg", "com.sa", "com.pk", "com.ng",
    "co.kr", "or.kr", "co.il", "org.il", "co.id", "or.id", "co.th", "in.th",
    "com.ua", "com.pl", "com.ru", "com.vn", "com.ph",
    "github.io", "gitlab.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "appspot.com", "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
    "netlify.app", "vercel.app", "s3.amazonaws.com",
}

_TLDX = None


def registrable_domain(host: str) -> str:
    """eTLD+1 for a hostname (``a.b.example.co.uk`` → ``example.co.uk``)."""
    host = (host or "").lower().strip(".")
    if not host:
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    global _TLDX
    try:
        if _TLDX is None:
            import tldextract  # optional; offline snapshot, no network fetch
            _TLDX = tldextract.TLDExtract(suffix_list_urls=())
        ext = _TLDX(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts) >= 4 and ".".join(parts[-3:]) in _MULTI_SUFFIXES:
        return ".".join(parts[-4:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def parse_target(raw: str) -> Tuple[str, str, str, bool]:
    """Parse a raw target into (url, domain, root_domain, is_wildcard).

      https://example.com      → (https://example.com, example.com, example.com, False)
      *.example.com            → (https://example.com, example.com, example.com, True)
      sub.example.co.uk:8443   → (https://sub.example.co.uk:8443, sub.example.co.uk, example.co.uk, False)
    """
    raw = (raw or "").strip()
    is_wildcard = raw.startswith("*.")
    clean = raw[2:] if is_wildcard else raw
    if "://" not in clean:
        clean = f"https://{clean}"
    parsed = urlparse(clean)
    domain = (parsed.hostname or "").lower().rstrip(".")
    if not domain:
        raise ValueError(f"Could not parse a hostname from target: {raw!r}")
    netloc = domain if parsed.port is None else f"{domain}:{parsed.port}"
    if ":" in domain and not domain.startswith("["):  # bare IPv6
        netloc = f"[{domain}]" if parsed.port is None else f"[{domain}]:{parsed.port}"
    url = f"{parsed.scheme}://{netloc}"
    return url, domain, registrable_domain(domain), is_wildcard


def parse_steps(raw: Optional[str]) -> Optional[List[int]]:
    """'0,1,8-12' → [0, 1, 8, 9, 10, 11, 12]. Unknown IDs are ignored."""
    if raw is None:
        return None
    result: Set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                rng = range(int(a), int(b) + 1)
            else:
                rng = range(int(part), int(part) + 1)
        except ValueError:
            continue
        result.update(i for i in rng if 0 <= i < TOTAL_STEPS)
    return sorted(result) if result else None


def parse_role(spec: str) -> Tuple[str, Dict[str, Any]]:
    """'userA:bearer:TOKEN' → ('userA', {'bearer': 'TOKEN'})."""
    try:
        name, kind, value = spec.split(":", 2)
    except ValueError:
        raise ValueError(f"--role must be NAME:TYPE:VALUE, got {spec!r}")
    kind = kind.strip().lower()
    if kind == "cookie":
        return name.strip(), {"cookie": value}
    if kind == "bearer":
        return name.strip(), {"bearer": value}
    if kind == "header":
        k, _, v = value.partition(":")
        return name.strip(), {"headers": {k.strip(): v.strip()}}
    raise ValueError(f"--role TYPE must be cookie|bearer|header, got {kind!r}")


def _parse_header(h: str) -> Tuple[str, str]:
    k, sep, v = h.partition(":")
    if not sep:
        raise ValueError(f"Header must be 'Name: value', got {h!r}")
    return k.strip(), v.strip()


def load_config_file(path: str) -> Dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yml", ".yaml")):
        import yaml
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    known = {f.name for f in fields(Config)}
    unknown = sorted(set(data) - known - {"url", "target"})
    if unknown:
        raise ValueError(f"{path}: unknown keys {unknown}")
    return data


# ═══════════════════════════════════════════════════════════════════════════════
# BUILD CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_stealth(cfg: Config) -> None:
    prof = STEALTH_PROFILES.get(cfg.stealth, STEALTH_PROFILES["medium"])
    cfg.rate = float(prof["rate"])
    cfg.concurrency = int(prof["concurrency"])
    cfg.threads = int(prof["threads"])


def build_config(argv: Optional[List[str]] = None) -> Config:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config()

    # ─── Config file (lowest precedence after defaults) ──────────────────────
    file_data: Dict[str, Any] = {}
    if args.config_file:
        try:
            file_data = load_config_file(args.config_file)
        except Exception as e:
            parser.error(f"--config: {e}")
        for k, v in file_data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        cfg.config_file = args.config_file

    cfg.list_steps = args.list_steps
    cfg.no_banner = args.no_banner
    cfg.dry_run = args.dry_run
    if cfg.list_steps:
        return cfg

    # ─── Resume ──────────────────────────────────────────────────────────────
    if args.resume:
        cfg.resume = True
        cfg.resume_dir = str(Path(args.resume).resolve())
        # Everything else is restored from the original scan; only these
        # output options may be changed on resume.
        overrides: Dict[str, Any] = {}
        if args.fail_on:
            overrides["fail_on"] = args.fail_on
        if args.formats:
            overrides["formats"] = _csv(args.formats)
        cfg._resume_overrides = overrides  # type: ignore[attr-defined]
        return cfg

    # ─── Target ──────────────────────────────────────────────────────────────
    raw_target = args.url or file_data.get("url") or file_data.get("target") or cfg.target_url
    if not raw_target:
        parser.error("one of -u/--url, --config (with 'url'), --resume or --list-steps is required")
    try:
        url, domain, root_domain, auto_wildcard = parse_target(raw_target)
    except ValueError as e:
        parser.error(str(e))
    cfg.target_url, cfg.domain, cfg.root_domain = url, domain, root_domain
    cfg.wildcard = bool(args.wildcard or auto_wildcard or cfg.wildcard or cfg.scope == "wildcard")
    cfg.scope = "wildcard" if cfg.wildcard else "single"

    # ─── Stealth & throughput ────────────────────────────────────────────────
    if args.stealth:
        cfg.stealth = args.stealth
    _apply_stealth(cfg)
    if args.aggressive or cfg.aggressive:
        cfg.aggressive = True
        cfg.stealth = "low"
        cfg.osint = True
        cfg.logic = True
        _apply_stealth(cfg)
    if "rate" in file_data:
        cfg.rate = float(file_data["rate"])
    if "concurrency" in file_data:
        cfg.concurrency = int(file_data["concurrency"])
    if args.rate:
        cfg.rate = max(0.1, float(args.rate))
    if args.concurrency:
        cfg.concurrency = max(1, int(args.concurrency))
    if args.user_agent:
        cfg.user_agent = args.user_agent

    # ─── Execution ───────────────────────────────────────────────────────────
    if args.steps is not None:
        cfg.steps = parse_steps(args.steps)
    elif isinstance(cfg.steps, str):
        cfg.steps = parse_steps(cfg.steps)
    if args.skip_steps is not None:
        cfg.skip_steps = parse_steps(args.skip_steps) or []
    elif isinstance(cfg.skip_steps, str):
        cfg.skip_steps = parse_steps(cfg.skip_steps) or []
    if args.output:
        cfg.output_dir = args.output

    # ─── Output ──────────────────────────────────────────────────────────────
    if args.formats:
        cfg.formats = _csv(args.formats)
    bad = [f for f in cfg.formats if f not in EXPORT_FORMATS]
    if bad:
        parser.error(f"--format: unknown {bad}; choose from {', '.join(EXPORT_FORMATS)}")
    if args.fail_on:
        cfg.fail_on = args.fail_on

    # ─── Features (flags only ever switch things on) ─────────────────────────
    for name in ("osint", "logic", "notify", "skip_subs", "skip_nuclei"):
        if getattr(args, name):
            setattr(cfg, name, True)

    # ─── Network ─────────────────────────────────────────────────────────────
    cfg.proxy = args.proxy or cfg.proxy
    cfg.proxy_file = args.proxy_file or cfg.proxy_file
    cfg.resolver_file = args.resolver_file or cfg.resolver_file
    cfg.origin_ip = args.origin or cfg.origin_ip

    # ─── Scope ───────────────────────────────────────────────────────────────
    from core.scope import load_scope_file, parse_scope_lines
    if args.scope_file:
        cfg.scope_file = args.scope_file
    if cfg.scope_file:
        try:
            ah, dh, ac, dc = load_scope_file(cfg.scope_file)
        except OSError as e:
            parser.error(f"--scope-file: {e}")
        cfg.allow_hosts += ah; cfg.deny_hosts += dh
        cfg.allow_cidrs += ac; cfg.deny_cidrs += dc
    if args.include:
        ah, _, ac, _ = parse_scope_lines(_csv(args.include))
        # --include extends the default scope, so seed the allow-list with it.
        if not cfg.allow_hosts and not cfg.allow_cidrs:
            cfg.allow_hosts.append(cfg.domain)
            if cfg.wildcard:
                cfg.allow_hosts.append("*." + cfg.domain)
            else:
                cfg.allow_hosts.append("www." + cfg.domain)
        cfg.allow_hosts += ah; cfg.allow_cidrs += ac
    if args.exclude:
        _, dh, _, dc = parse_scope_lines("!" + x for x in _csv(args.exclude))
        cfg.deny_hosts += dh; cfg.deny_cidrs += dc
    if args.strict_scope:
        cfg.scope_enforce = True
    if args.allow_private:
        cfg.scope_block_private = False
    # An allow-list that doesn't cover the target itself is almost always a mistake.
    if cfg.allow_hosts or cfg.allow_cidrs:
        from core.scope import ScopeGuard
        probe = ScopeGuard(allow_hosts=cfg.allow_hosts, allow_cidrs=cfg.allow_cidrs,
                           block_private=cfg.scope_block_private)
        if not probe.is_in_scope(cfg.domain):
            parser.error(f"target {cfg.domain} is not covered by the scope allow-list")

    # ─── API keys ────────────────────────────────────────────────────────────
    for name in ("github_token", "shodan_key", "securitytrails_key", "discord_webhook",
                 "slack_webhook", "telegram_bot", "telegram_chat"):
        val = getattr(args, name)
        if val:
            setattr(cfg, name, val)

    # ─── Authentication ──────────────────────────────────────────────────────
    if args.auth_mode:
        cfg.auth_mode = args.auth_mode
    if args.auth_cookie:
        cfg.auth_cookie = args.auth_cookie
    if args.auth_bearer:
        cfg.auth_bearer = args.auth_bearer
    if args.auth_header:
        try:
            cfg.auth_headers.update(dict(_parse_header(h) for h in args.auth_header))
        except ValueError as e:
            parser.error(str(e))
    for arg, attr in (("login_url", "auth_login_url"), ("login_post_url", "auth_post_url"),
                      ("username", "auth_username"), ("password", "auth_password"),
                      ("user_field", "auth_user_field"), ("pass_field", "auth_pass_field"),
                      ("csrf_field", "auth_csrf_field"), ("auth_verify_url", "auth_verify_url")):
        val = getattr(args, arg)
        if val:
            setattr(cfg, attr, val)
    if args.auth_success:
        cfg.auth_success_markers = list(args.auth_success)
    if args.auth_failure:
        cfg.auth_failure_markers = list(args.auth_failure)
    # Infer the mode when credentials were given without --auth-mode.
    if cfg.auth_mode == "none":
        if cfg.auth_login_url and cfg.auth_username:
            cfg.auth_mode = "form"
        elif cfg.auth_bearer:
            cfg.auth_mode = "bearer"
        elif cfg.auth_cookie:
            cfg.auth_mode = "cookie"
        elif cfg.auth_headers:
            cfg.auth_mode = "raw"
    if cfg.auth_mode == "form" and not (cfg.auth_login_url and cfg.auth_username):
        parser.error("--auth-mode form needs --login-url and --username (and a password)")

    # ─── Access-control roles ────────────────────────────────────────────────
    cfg.auth_token_a = args.auth_a or cfg.auth_token_a
    cfg.auth_token_b = args.auth_b or cfg.auth_token_b
    roles: Dict[str, Dict[str, Any]] = dict(cfg.authz_roles or {})
    for spec in args.role or []:
        try:
            name, r = parse_role(spec)
        except ValueError as e:
            parser.error(str(e))
        roles[name] = r
    if cfg.auth_token_a:
        roles.setdefault("userA", {"bearer": cfg.auth_token_a})
    if cfg.auth_token_b:
        roles.setdefault("userB", {"bearer": cfg.auth_token_b})
    if roles:
        roles.setdefault("anon", {})
    cfg.authz_roles = roles
    if args.authz_max_endpoints:
        cfg.authz_max_endpoints = args.authz_max_endpoints

    return cfg
