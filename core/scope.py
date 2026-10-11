"""
GHOST RECON v2.0 — core/scope.py
Central scope enforcement. Every outbound target (URL / host / IP) SHOULD pass
through ScopeGuard.is_in_scope() before a tool is launched against it.

Design goals
------------
* One canonical place to answer "am I allowed to touch this?".
* Safe by default: an explicit deny-list always wins; if allow-list rules exist
  and nothing matches, the target is OUT of scope.
* Works with the existing Config.scope ("single" | "wildcard") and Ctx.root_domain
  without forcing callers to build rule objects.
* Cheap: results are memoised per-host.

This module has NO third-party dependencies so it can be imported anywhere,
including step00 before deps are installed.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

__all__ = ["ScopeGuard", "ScopeError", "build_scope_guard", "load_scope_file", "parse_scope_lines"]


class ScopeError(RuntimeError):
    """Raised when a hard scope violation is attempted and enforce=True."""


def _host_of(target: str) -> str:
    """Extract a bare hostname/IP from a URL, host:port, or bare host."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        # bare host or host:port — give urlparse a scheme so netloc populates
        t = "//" + t
    parsed = urlparse(t, scheme="http")
    host = parsed.hostname or ""
    return host.lower().rstrip(".")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass
class ScopeGuard:
    """Decides whether a target is in scope.

    allow_hosts / deny_hosts accept exact hostnames or wildcard globs
    (``*.example.com``). deny_cidrs / allow_cidrs accept CIDR strings.
    When no allow-list is given, ``root_domain`` is the *scope base*: the exact
    target host (plus its ``www.`` alias) in single scope, or that host and
    everything beneath it in wildcard scope.
    """

    root_domain: str = ""
    wildcard: bool = False
    allow_hosts: List[str] = field(default_factory=list)
    deny_hosts: List[str] = field(default_factory=list)
    allow_cidrs: List[str] = field(default_factory=list)
    deny_cidrs: List[str] = field(default_factory=list)
    # Block RFC1918 / loopback / link-local by default — pentests should not
    # wander onto internal infra unless the operator opts in.
    block_private: bool = True
    enforce: bool = False  # if True, out_of_scope() raises instead of returning

    _allow_res: List[re.Pattern] = field(default_factory=list, init=False, repr=False)
    _deny_res: List[re.Pattern] = field(default_factory=list, init=False, repr=False)
    _allow_nets: list = field(default_factory=list, init=False, repr=False)
    _deny_nets: list = field(default_factory=list, init=False, repr=False)
    _cache: dict = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.root_domain = (self.root_domain or "").lower().lstrip("*.").rstrip(".")
        self._allow_res = [self._glob(h) for h in self.allow_hosts]
        self._deny_res = [self._glob(h) for h in self.deny_hosts]
        self._allow_nets = [ipaddress.ip_network(c, strict=False) for c in self.allow_cidrs]
        self._deny_nets = [ipaddress.ip_network(c, strict=False) for c in self.deny_cidrs]

    # ── rule compilation ────────────────────────────────────────────────────
    @staticmethod
    def _glob(pattern: str) -> re.Pattern:
        p = (pattern or "").strip().lower().rstrip(".")
        # A leading "*." matches any depth (a.b.example.com); any other "*"
        # matches within a single label.
        prefix = ""
        if p.startswith("*."):
            prefix, p = r"(?:[^.]+\.)+", p[2:]
        escaped = re.escape(p).replace(r"\*", r"[^.]+")
        return re.compile(rf"^{prefix}{escaped}$")

    # ── the one method everything calls ─────────────────────────────────────
    def is_in_scope(self, target: str) -> bool:
        host = _host_of(target)
        if not host:
            return False
        cached = self._cache.get(host)
        if cached is not None:
            return cached
        result = self._decide(host)
        if len(self._cache) < 8192:
            self._cache[host] = result
        return result

    def _decide(self, host: str) -> bool:
        # 1. Deny-list always wins.
        if any(r.match(host) for r in self._deny_res):
            return False

        if _is_ip(host):
            ip = ipaddress.ip_address(host)
            if any(ip in net for net in self._deny_nets):
                return False
            if self.block_private and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
                # allow only if an explicit allow_cidr covers it
                if not any(ip in net for net in self._allow_nets):
                    return False
            if self._allow_nets or self._allow_res:
                return any(ip in net for net in self._allow_nets)
            # IP-literal target with no explicit lists: only that IP is in scope.
            if self.root_domain and _is_ip(self.root_domain):
                return ip == ipaddress.ip_address(self.root_domain)
            # Domain target: IPs (e.g. resolved A records) are allowed unless
            # private/denied — they are reached via in-scope hostnames.
            return True

        # 2. Explicit allow-list. If ANY allow rule exists (host or CIDR), a
        #    hostname must match a host rule — a CIDR-only scope never admits
        #    arbitrary names (v15 fell through to "unrestricted" here).
        if self._allow_res or self._allow_nets:
            return any(r.match(host) for r in self._allow_res)

        # 3. Fallback: v14-style root-domain scope.
        if not self.root_domain:
            return True  # no constraints configured at all
        if host == self.root_domain:
            return True
        if self.wildcard and host.endswith("." + self.root_domain):
            return True
        # Single scope: treat the www alias as the same asset (redirects to it
        # are near-universal). Exclude it with --exclude if it is not in scope.
        if not self.wildcard and host == "www." + self.root_domain:
            return True
        return False

    def describe(self) -> str:
        """One-line human summary for the console / dry-run."""
        parts = []
        if self.allow_hosts or self.allow_cidrs:
            parts.append("allow=" + ",".join(self.allow_hosts + self.allow_cidrs))
        elif self.root_domain:
            parts.append(("*." if self.wildcard else "") + self.root_domain)
        if self.deny_hosts or self.deny_cidrs:
            parts.append("deny=" + ",".join(self.deny_hosts + self.deny_cidrs))
        parts.append("private=" + ("blocked" if self.block_private else "allowed"))
        return "  ".join(parts) or "unrestricted"

    def assert_in_scope(self, target: str) -> str:
        """Return the target if in scope; raise ScopeError otherwise."""
        if self.is_in_scope(target):
            return target
        if self.enforce:
            raise ScopeError(f"Out of scope: {target}")
        return target

    def filter(self, targets: Iterable[str]) -> List[str]:
        """Return only the in-scope members of an iterable, order-preserving."""
        seen: Set[str] = set()
        out: List[str] = []
        for t in targets:
            if t in seen:
                continue
            seen.add(t)
            if self.is_in_scope(t):
                out.append(t)
        return out

    def rejected(self, targets: Iterable[str]) -> List[str]:
        """Return the out-of-scope members (useful for audit logging)."""
        return [t for t in targets if not self.is_in_scope(t)]


def parse_scope_lines(lines: Iterable[str]):
    """Parse scope-file lines into (allow_hosts, deny_hosts, allow_cidrs, deny_cidrs).

    Format (one entry per line, ``#`` comments allowed)::

        example.com            # exact host
        *.example.com          # any subdomain (single label glob)
        10.10.0.0/16           # CIDR
        !legacy.example.com    # deny (also accepts a leading '-')
        https://app.example.com/path   # URLs are reduced to their host
    """
    allow_h: List[str] = []; deny_h: List[str] = []
    allow_c: List[str] = []; deny_c: List[str] = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        deny = line[0] in "!-"
        if deny:
            line = line[1:].strip()
        try:
            ipaddress.ip_network(line, strict=False)
            (deny_c if deny else allow_c).append(line)
            continue
        except ValueError:
            pass
        if line.startswith("*."):
            host = "*." + _host_of(line[2:])
        else:
            host = _host_of(line)
        if host and host != "*.":
            (deny_h if deny else allow_h).append(host)
    return allow_h, deny_h, allow_c, deny_c


def load_scope_file(path: str):
    with open(path, encoding="utf-8") as fh:
        return parse_scope_lines(fh)


def build_scope_guard(config, ctx=None, *, enforce: bool = False) -> ScopeGuard:
    """Construct a ScopeGuard from the running Config/Ctx.

    v2.0 fix: the scope base is the *target host* (``ctx.domain``), not the
    registrable root. v15 used ``root_domain``, which put ``-u app.example.com``
    itself out of scope and widened ``*.sub.example.com`` to all of example.com.
    """
    base = ""
    if ctx is not None:
        base = getattr(ctx, "domain", "") or getattr(ctx, "root_domain", "")
    if not base:
        base = getattr(config, "domain", "") or getattr(config, "root_domain", "")

    wildcard = getattr(config, "scope", "single") == "wildcard" or getattr(config, "wildcard", False)

    allow_cidrs = list(getattr(config, "allow_cidrs", []) or [])
    # An origin IP the operator supplied explicitly is in scope by definition.
    origin = (getattr(ctx, "origin_ip", "") if ctx is not None else "") or getattr(config, "origin_ip", "")
    if origin and _is_ip(origin) and origin not in allow_cidrs:
        if allow_cidrs or getattr(config, "allow_hosts", None) or ipaddress.ip_address(origin).is_private:
            allow_cidrs.append(origin)

    return ScopeGuard(
        root_domain=base,
        wildcard=bool(wildcard),
        allow_hosts=list(getattr(config, "allow_hosts", []) or []),
        deny_hosts=list(getattr(config, "deny_hosts", []) or []),
        allow_cidrs=allow_cidrs,
        deny_cidrs=list(getattr(config, "deny_cidrs", []) or []),
        block_private=bool(getattr(config, "scope_block_private", True)),
        enforce=enforce,
    )
