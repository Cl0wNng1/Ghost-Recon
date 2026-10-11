"""
Ghost v2.0 regression tests — every test here is offline (local loopback only)
and pins a bug fixed or a feature added in v2.0.
"""
from __future__ import annotations

import asyncio
import http.server
import json
import os
import socket
import stat
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Never route loopback test traffic through an environment proxy.
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


# ─── Local keep-alive lab server ──────────────────────────────────────────────

class _LabHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: what exposed the event-loop bug

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/redir-out":
            return self._send(302, headers={"Location": "http://evil.invalid/steal"})
        if self.path == "/redir-in":
            return self._send(302, headers={"Location": "/landing"})
        if self.path == "/landing":
            return self._send(200, b"landed")
        if self.path == "/protected":
            ok = "session=good" in (self.headers.get("Cookie") or "")
            return self._send(200, b"Welcome back - Sign out" if ok else b"Please log in")
        if self.path == "/whoami":
            return self._send(200, (self.headers.get("Authorization") or "anon").encode())
        return self._send(200, b"<html><title>lab</title>ok</html>")


@pytest.fixture(scope="module")
def lab():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _lab_guard(**kw):
    from core.scope import ScopeGuard
    return ScopeGuard(allow_cidrs=["127.0.0.1/32"], block_private=False, **kw)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Event loop: engine + shared client survive across steps
# ═══════════════════════════════════════════════════════════════════════════════

def test_engine_survives_across_steps_on_pipeline_loop(lab):
    import ghost_core
    from core.pipeline import PipelineLoop

    runner = PipelineLoop()
    ghost_core.bind_loop(runner.loop)
    eng = ghost_core.init_engine(rate=100, max_concurrency=4)

    async def step():
        return (await eng.get(lab + "/")).code

    try:
        codes = [runner.run(step()) for _ in range(3)]  # three "steps"
    finally:
        runner.run(eng.close())
        runner.close()
    assert codes == [200, 200, 200]


def test_engine_rebinds_if_loop_changes(lab):
    """Defence in depth: even legacy per-step asyncio.run() must not break."""
    import ghost_core
    eng = ghost_core.AsyncHttpEngine(rate=100, max_concurrency=4)

    async def step():
        return (await eng.get(lab + "/")).code

    assert asyncio.run(step()) == 200
    assert asyncio.run(step()) == 200  # v15: code 0, "Event loop is closed"


def test_http_client_rebinds_across_loops(lab):
    from core.http import HttpClient
    c = HttpClient(_lab_guard(), rate=100, concurrency=2, jitter=0)

    async def step():
        r = await c.get(lab + "/")
        return r.status if r is not None else None

    assert asyncio.run(step()) == 200
    assert asyncio.run(step()) == 200


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Scope: redirects, engine enforcement, guard base, data-layer filtering
# ═══════════════════════════════════════════════════════════════════════════════

def test_engine_blocks_out_of_scope_and_offscope_redirects(lab):
    import ghost_core
    eng = ghost_core.AsyncHttpEngine(rate=100, max_concurrency=2)
    eng.scope_guard = _lab_guard()

    async def go():
        blocked = await eng.get("http://evil.invalid/")
        redir_out = await eng.get(lab + "/redir-out")
        redir_in = await eng.get(lab + "/redir-in")
        third_party = await eng.get("https://crt.sh/?q=x", scope="crtsh", timeout=0.01)
        await eng.close()
        return blocked, redir_out, redir_in, third_party

    blocked, redir_out, redir_in, third_party = asyncio.run(go())
    assert blocked.error == "out-of-scope"
    assert redir_out.code == 302            # handed back, not followed
    assert redir_in.code == 200 and "landed" in redir_in.body
    assert third_party.error != "out-of-scope"  # intel buckets are not target-scoped
    assert eng.blocked_count >= 2


def test_http_client_does_not_follow_offscope_redirect(lab):
    from core.http import HttpClient
    c = HttpClient(_lab_guard(), rate=100, concurrency=2, jitter=0)

    async def go():
        out = await c.get(lab + "/redir-out")
        inn = await c.get(lab + "/redir-in")
        await c.close()
        return out.status, inn.status, inn._ghost_text

    out, inn, text = asyncio.run(go())
    assert out == 302 and inn == 200 and text == "landed"
    assert c.rejected_count == 1


def test_scope_guard_base_is_target_host_not_root():
    from core.scope import build_scope_guard
    single = SimpleNamespace(domain="app.example.com", root_domain="example.com", scope="single")
    g = build_scope_guard(single)
    assert g.is_in_scope("https://app.example.com/x")      # v15: False (!)
    assert g.is_in_scope("www.app.example.com")
    assert not g.is_in_scope("example.com")
    assert not g.is_in_scope("other.example.com")

    wild = SimpleNamespace(domain="sub.example.com", root_domain="example.com", scope="wildcard")
    g = build_scope_guard(wild)
    assert g.is_in_scope("a.b.sub.example.com")
    assert not g.is_in_scope("x.example.com")              # v15: True (too broad)


def test_scope_globs_and_scope_file():
    from core.scope import ScopeGuard, parse_scope_lines
    ah, dh, ac, dc = parse_scope_lines([
        "*.example.com", "!legacy.example.com", "203.0.113.0/24", "-203.0.113.66",
        "https://api.other.io/v1  # url form", "# comment", "",
    ])
    assert ah == ["*.example.com", "api.other.io"] and dh == ["legacy.example.com"]
    g = ScopeGuard(allow_hosts=ah, deny_hosts=dh, allow_cidrs=ac, deny_cidrs=dc)
    assert g.is_in_scope("a.b.example.com")
    assert not g.is_in_scope("legacy.example.com")
    assert g.is_in_scope("203.0.113.5") and not g.is_in_scope("203.0.113.66")
    assert not g.is_in_scope("10.0.0.1")


def test_origin_ip_is_added_to_scope():
    from core.scope import build_scope_guard
    cfg = SimpleNamespace(domain="example.com", root_domain="example.com", scope="single",
                          allow_hosts=["example.com"], origin_ip="198.51.100.7")
    assert build_scope_guard(cfg).is_in_scope("https://198.51.100.7/")


def test_ctx_drops_out_of_scope_assets():
    from core.db import GhostDB
    from core.context import Ctx
    from core.scope import ScopeGuard
    with tempfile.TemporaryDirectory() as tmp:
        db = GhostDB(Path(tmp) / "ghost.db")
        ctx = Ctx.new(db, "https://app.example.com", "app.example.com", "example.com")
        ctx.scope_guard = ScopeGuard(root_domain="app.example.com")
        ctx.add_subdomains_bulk(["app.example.com", "admin.example.com", "evil.com"])
        ctx.add_urls_bulk(["https://app.example.com/a?id=1", "https://cdn.other.net/x"])
        ctx.add_live_host("https://admin.example.com")
        ctx.add_js_file("https://cdn.other.net/lib.js")      # kept: not strict
        assert ctx.subdomains == ["app.example.com"]
        assert ctx.urls == {"https://app.example.com/a?id=1"}
        assert ctx.live_host_urls() == []
        assert "https://cdn.other.net/lib.js" in ctx.js_files
        assert {"admin.example.com", "evil.com", "cdn.other.net"} <= ctx.out_of_scope_hosts
        ctx.scope_guard.enforce = True                         # --strict-scope
        ctx.add_js_file("https://cdn2.other.net/lib.js")
        assert "https://cdn2.other.net/lib.js" not in ctx.js_files
        db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Resume
# ═══════════════════════════════════════════════════════════════════════════════

def test_legacy_checkpoint_maps_through_execution_order():
    from core.pipeline import completed_from_snapshot
    # v15 saved step_num+1 = 16 after the auth step (ID 15), which runs 5th.
    # v15 then skipped every step with ID < 16 — i.e. steps 4–14 never ran.
    assert completed_from_snapshot({}, 16) == {0, 1, 2, 3, 15}
    assert completed_from_snapshot({"completed_steps": [0, 1, 15]}, 99) == {0, 1, 15}
    assert completed_from_snapshot({}, 0) == set()


def test_completed_steps_round_trip_through_checkpoint():
    from core.db import GhostDB, get_resume_info
    from core.context import Ctx
    with tempfile.TemporaryDirectory() as tmp:
        db = GhostDB(Path(tmp) / "ghost.db")
        ctx = Ctx.new(db, "https://t.com", "t.com", "t.com")
        ctx.completed_steps = {0, 1, 2, 3, 15}
        ctx.save_checkpoint(16)
        db.close()
        info = get_resume_info(Path(tmp) / "ghost.db")
        assert sorted(info["ctx_snapshot"]["completed_steps"]) == [0, 1, 2, 3, 15]


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Config: stealth wiring, redaction, parsing, CLI
# ═══════════════════════════════════════════════════════════════════════════════

def test_http_client_uses_stealth_profile():
    from core.config import build_config
    from core.http import build_http_client
    cfg = build_config(["-u", "example.com", "--stealth", "high"])
    c = build_http_client(cfg, _lab_guard())
    assert c.jitter == 0.8 and c.cooldown == 15 and c.cooldown_every == 50  # v15: defaults
    cfg = build_config(["-u", "example.com", "--rate", "2.5", "--concurrency", "3",
                        "--proxy", "http://127.0.0.1:8080", "--user-agent", "Lab/1"])
    c = build_http_client(cfg, _lab_guard())
    assert c.bucket.rate == 2.5 and c._concurrency == 3
    assert c.proxy == "http://127.0.0.1:8080" and c.user_agent == "Lab/1"


def test_config_json_redacts_every_credential():
    from core.config import build_config
    cfg = build_config([
        "-u", "example.com", "--auth-cookie", "sid=SECRETCOOKIE", "--password", "SECRETPASS",
        "--login-url", "https://example.com/login", "--username", "bob",
        "--auth-header", "X-Api-Key: SECRETHEADER", "--role", "admin:bearer:SECRETROLE",
        "--auth-a", "SECRETA", "--github-token", "ghp_SECRETGH",
    ])
    blob = cfg.to_json()
    for needle in ("SECRETCOOKIE", "SECRETPASS", "SECRETHEADER", "SECRETROLE", "SECRETA", "SECRETGH"):
        assert needle not in blob, needle
    assert json.loads(blob)["auth_username"] == "bob"   # non-secret survives


def test_parse_target_public_suffix_and_port():
    from core.config import parse_target, registrable_domain
    assert parse_target("*.shop.example.co.uk") == ("https://shop.example.co.uk", "shop.example.co.uk", "example.co.uk", True)
    assert parse_target("http://App.Example.com:8080/x") == ("http://app.example.com:8080", "app.example.com", "example.com", False)
    assert registrable_domain("a.b.user.github.io") == "user.github.io"
    assert registrable_domain("10.1.2.3") == "10.1.2.3"
    with pytest.raises(ValueError):
        parse_target("https://")


def test_cli_roles_steps_scope_and_auth_inference():
    from core.config import build_config
    cfg = build_config(["-u", "example.com", "--role", "userA:cookie:sid=a",
                        "--role", "svc:header:X-Key: k", "--auth-b", "tokB",
                        "--steps", "0-4,15", "--skip-steps", "2",
                        "--exclude", "dev.example.com", "--include", "api.partner.io",
                        "--auth-bearer", "tok"])
    assert cfg.authz_roles == {"userA": {"cookie": "sid=a"}, "svc": {"headers": {"X-Key": "k"}},
                               "userB": {"bearer": "tokB"}, "anon": {}}
    assert cfg.steps == [0, 1, 2, 3, 4, 15] and not cfg.should_run_step(2)
    assert "dev.example.com" in cfg.deny_hosts
    assert {"example.com", "www.example.com", "api.partner.io"} <= set(cfg.allow_hosts)
    assert cfg.auth_mode == "bearer"


def test_cli_rejects_allowlist_that_excludes_target():
    from core.config import build_config
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("other.com\n")
    try:
        with pytest.raises(SystemExit):
            build_config(["-u", "example.com", "--scope-file", fh.name])
    finally:
        os.unlink(fh.name)


def test_config_file_with_cli_override():
    from core.config import build_config
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"url": "*.example.com", "stealth": "high", "fail_on": "medium",
                   "formats": ["json"], "deny_hosts": ["x.example.com"]}, fh)
    try:
        cfg = build_config(["--config", fh.name, "--stealth", "low"])
        assert cfg.scope == "wildcard" and cfg.stealth == "low" and cfg.rate == 30.0
        assert cfg.formats == ["json"] and cfg.deny_hosts == ["x.example.com"]
        assert cfg.fail_threshold_hit({"HIGH": 1}) and not cfg.fail_threshold_hit({"LOW": 4})
    finally:
        os.unlink(fh.name)


def test_main_list_steps_and_dry_run_send_nothing(capsys, tmp_path, monkeypatch):
    import ghost
    monkeypatch.chdir(tmp_path)
    assert ghost.main(["--list-steps", "--no-banner"]) == 0
    assert ghost.main(["-u", "example.com", "--dry-run", "--no-banner"]) == 0
    assert list(tmp_path.iterdir()) == []   # no workspace created
    assert "Dry run" in capsys.readouterr().out


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Auth session handling
# ═══════════════════════════════════════════════════════════════════════════════

def test_auth_step_persists_0600_and_arms_engine(lab, tmp_path):
    import ghost_core
    from core.http import HttpClient
    import modules.step_auth as step_auth

    http = HttpClient(_lab_guard(), rate=100, concurrency=2, jitter=0)
    eng = ghost_core.AsyncHttpEngine(rate=100)
    ctx = SimpleNamespace(http=http, url=lab, log=lambda m: None)
    cfg = SimpleNamespace(auth_mode="cookie", auth_cookie="session=good",
                          auth_verify_url=lab + "/protected", auth_success_markers=["Sign out"],
                          auth_failure_markers=["log in"], workspace=str(tmp_path))

    async def go():
        await step_auth.execute(ctx, eng, cfg)
        await http.close()
    asyncio.run(go())

    sess = tmp_path / "auth_session.json"
    assert http.auth.logged_in is True
    assert stat.S_IMODE(sess.stat().st_mode) == 0o600
    assert eng.auth_headers.get("Cookie") == "session=good"   # v15: engine stayed anonymous


def test_engine_sends_auth_headers_to_target_only(lab):
    import ghost_core
    eng = ghost_core.AsyncHttpEngine(rate=100)
    eng.auth_headers = {"Authorization": "Bearer T"}

    async def go():
        a = await eng.get(lab + "/whoami")
        b = await eng.get(lab + "/whoami", scope="osint")
        await eng.close()
        return a.body, b.body
    target, intel = asyncio.run(go())
    assert target == "Bearer T" and intel == "anon"


def test_authz_candidates_include_known_200_paths():
    from modules.step_authz import _candidate_endpoints
    ctx = SimpleNamespace(urls={"https://t.com/api/user?id=5", "https://t.com/about"},
                          paths_200=["https://t.com/admin"])
    out = _candidate_endpoints(ctx)
    assert "https://t.com/api/user?id=5" in out and "https://t.com/admin" in out


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Reports
# ═══════════════════════════════════════════════════════════════════════════════

_EVIL = '</script><script>alert(document.domain)</script><img src=x onerror=alert(1)>'


def _report_ctx(tmp):
    from core.db import GhostDB
    from core.context import Ctx
    db = GhostDB(Path(tmp) / "ghost.db")
    ctx = Ctx.new(db, "https://t.com", "t.com", "t.com")
    ctx.add_finding("HIGH", "XSS_REFLECTED", "https://t.com/?q=" + _EVIL, _EVIL,
                    detail="d", exploit="curl 'https://t.com/?q=```'", cwe="CWE-79", confidence="HIGH")
    ctx.add_finding("LOW", "OPEN_PORTS", "https://t.com:8443", "Port 8443 open")
    ctx.waf_detected = ["<b>waf</b>"]
    return db, ctx


def test_html_report_neutralises_hostile_finding_data(tmp_path):
    from reports.html_report import generate_html
    from core.config import Config
    db, ctx = _report_ctx(tmp_path)
    out = tmp_path / "r.html"
    generate_html(ctx, Config(workspace=str(tmp_path)), str(out), 12.0)
    html = out.read_text()
    assert _EVIL not in html
    assert html.count("</script>") == html.count("<script")    # no injected closers
    assert "<b>waf</b>" not in html
    db.close()


def test_exports_json_md_sarif(tmp_path):
    from reports.exporters import export_all
    from core.config import Config
    db, ctx = _report_ctx(tmp_path)
    cfg = Config(auth_password="hunter2")
    out = export_all(ctx, cfg, 61.0, ["json", "md", "sarif"], str(tmp_path / "reports"))
    summary = json.load(open(out["json"]))
    assert summary["severity_counts"]["HIGH"] == 1 and "hunter2" not in open(out["json"]).read()
    sarif = json.load(open(out["sarif"]))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and len(run["results"]) == 2
    assert {r["level"] for r in run["results"]} == {"error", "note"}
    md = open(out["md"]).read()
    assert "````" in md                    # fence longer than the ``` inside the PoC
    assert "| 1 | HIGH |" in md and "1m 1s" in md
    db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Tool resolution & detection fixes
# ═══════════════════════════════════════════════════════════════════════════════

def test_python_httpx_cli_is_not_mistaken_for_projectdiscovery(tmp_path, monkeypatch):
    from core import tools
    fake = tmp_path / "httpx"
    fake.write_text("#!/usr/bin/python3\nprint('HTTPX butterfly')\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("GOPATH", str(tmp_path / "nogo"))
    tools.resolve_pd_httpx.cache_clear()
    try:
        assert tools.resolve_pd_httpx() is None
        real = tmp_path / "httpx-toolkit"
        real.write_bytes(b"\x7fELF fake go binary")
        real.chmod(0o755)
        tools.resolve_pd_httpx.cache_clear()
        assert tools.resolve_pd_httpx() == str(real)
    finally:
        tools.resolve_pd_httpx.cache_clear()


def test_small_sensitive_files_are_recognised():
    from modules.step10_sensitive import _content_proves
    assert _content_proves(".git/HEAD", "ref: refs/heads/main\n")
    assert _content_proves(".env", "DB_PASSWORD=x\n")
    assert not _content_proves(".env", "<html>Not found</html>")
    assert not _content_proves(".git/HEAD", "<html>")
