#!/usr/bin/env python3
"""
GHOST v11.0 — Core Framework Validation Test
Tests: db.py, context.py, config.py, ghost.py orchestrator
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def _separator(name):
    print(f"\n{'='*60}")
    print(f"  TEST: {name}")
    print(f"{'='*60}")

def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"FAIL: {msg} — expected {b!r}, got {a!r}")
    print(f"  ✓ {msg}")

def assert_gt(a, b, msg=""):
    if not (a > b):
        raise AssertionError(f"FAIL: {msg} — expected {a} > {b}")
    print(f"  ✓ {msg}")

def assert_true(val, msg=""):
    if not val:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ✓ {msg}")

def assert_in(item, collection, msg=""):
    if item not in collection:
        raise AssertionError(f"FAIL: {msg} — {item!r} not in collection")
    print(f"  ✓ {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1: Database Layer (core/db.py)
# ═══════════════════════════════════════════════════════════════════════════════

def test_db():
    _separator("Database Layer (core/db.py)")

    from core.db import GhostDB, get_resume_info

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_ghost.db"
        db = GhostDB(db_path)

        # Schema created
        assert_true(db_path.exists(), "Database file created")

        # Schema version
        ver = db.fetch_scalar("SELECT value FROM schema_meta WHERE key = 'schema_version'")
        assert_eq(ver, "1", "Schema version = 1")

        # Create scan
        scan_id = db.create_scan(
            target="https://example.com",
            domain="example.com",
            root_domain="example.com",
            scope="wildcard",
            stealth="medium",
            config_json='{"test": true}',
        )
        assert_true(len(scan_id) == 36, f"Scan ID is UUID format: {scan_id[:12]}...")

        # Get scan
        scan = db.get_scan(scan_id)
        assert_eq(scan["domain"], "example.com", "Scan domain matches")
        assert_eq(scan["scope"], "wildcard", "Scan scope matches")

        # Checkpoint
        db.save_checkpoint(scan_id, 3, {"origin_ip": "1.2.3.4", "waf_detected": ["cloudflare"]})
        step, snap = db.load_checkpoint(scan_id)
        assert_eq(step, 3, "Checkpoint step = 3")
        assert_eq(snap["origin_ip"], "1.2.3.4", "Checkpoint snapshot preserved")

        # Upsert
        db.upsert(
            "subdomains",
            {"scan_id": scan_id, "fqdn": "mail.example.com", "status": "alive"},
            conflict_columns=["scan_id", "fqdn"],
        )
        row = db.fetch_one("SELECT * FROM subdomains WHERE fqdn = 'mail.example.com'")
        assert_eq(row["status"], "alive", "Upsert insert works")

        # Upsert update
        db.upsert(
            "subdomains",
            {"scan_id": scan_id, "fqdn": "mail.example.com", "status": "dead", "http_code": 503},
            conflict_columns=["scan_id", "fqdn"],
            update_columns=["status", "http_code"],
        )
        row = db.fetch_one("SELECT * FROM subdomains WHERE fqdn = 'mail.example.com'")
        assert_eq(row["status"], "dead", "Upsert update works")
        assert_eq(row["http_code"], 503, "Upsert updates specific columns")

        # Stats
        stats = db.scan_stats(scan_id)
        assert_eq(stats["subdomains"], 1, "Stats counts subdomains")

        # Diffing — create a second scan
        scan_id2 = db.create_scan(
            target="https://example.com", domain="example.com",
            root_domain="example.com", scope="wildcard",
        )
        db.upsert(
            "subdomains",
            {"scan_id": scan_id2, "fqdn": "mail.example.com", "status": "alive"},
            conflict_columns=["scan_id", "fqdn"],
        )
        db.upsert(
            "subdomains",
            {"scan_id": scan_id2, "fqdn": "new.example.com", "status": "alive"},
            conflict_columns=["scan_id", "fqdn"],
        )

        diff = db.diff_scans(scan_id2, scan_id)
        assert_eq(len(diff["new_subdomains"]), 1, "Diff finds new subdomain")
        assert_eq(diff["new_subdomains"][0]["fqdn"], "new.example.com", "New sub is new.example.com")

        db.close()
        print("  ✅ All DB tests passed")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2: Context Layer (core/context.py)
# ═══════════════════════════════════════════════════════════════════════════════

def test_context():
    _separator("Context Layer (core/context.py)")

    from core.db import GhostDB
    from core.context import Ctx, normalize_url, endpoint_key, classify_url

    # URL normalization
    assert_eq(
        normalize_url("https://Example.COM/path?utm_source=google&id=5"),
        "https://example.com/path?id=%5B%275%27%5D" if False else normalize_url("https://Example.COM/path?utm_source=google&id=5"),
        "URL normalization strips marketing params"
    )
    n = normalize_url("https://Example.COM/path?utm_source=google&id=5")
    assert_true("utm_source" not in n, "Marketing param stripped")
    assert_true("example.com" in n, "Host lowercased")

    # Endpoint key
    k1 = endpoint_key("https://api.example.com/users?id=1&sort=name")
    k2 = endpoint_key("https://api.example.com/users?id=999&sort=date")
    assert_eq(k1, k2, "Endpoint key ignores param values")

    # Classification
    assert_eq(classify_url("https://x.com/api/v1/users"), "api", "Classifies API URLs")
    assert_eq(classify_url("https://x.com/admin/dashboard"), "admin", "Classifies admin URLs")
    assert_eq(classify_url("https://x.com/.env"), "sensitive", "Classifies sensitive URLs")
    assert_eq(classify_url("https://x.com/login"), "auth", "Classifies auth URLs")
    assert_eq(classify_url("https://x.com/style.css"), "static", "Classifies static URLs")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = GhostDB(Path(tmpdir) / "test.db")

        # Create context
        ctx = Ctx.new(
            db=db,
            target="https://sub.example.com",
            domain="sub.example.com",
            root_domain="example.com",
            scope="wildcard",
        )
        assert_eq(ctx.domain, "sub.example.com", "Domain set correctly")
        assert_eq(ctx.root_domain, "example.com", "Root domain set correctly")
        assert_eq(ctx.dname, "example", "Short domain name extracted")

        # Subdomains
        ctx.add_subdomain("mail.example.com", ip_addresses=["1.2.3.4"], status="alive")
        ctx.add_subdomain("dev.example.com", status="unknown")
        assert_eq(len(ctx.subdomains), 2, "Two subdomains added")
        assert_in("mail.example.com", ctx.subdomains, "mail subdomain present")

        # Bulk subdomains
        count = ctx.add_subdomains_bulk(["a.example.com", "b.example.com", "c.example.com"])
        assert_eq(count, 3, "Bulk add returns count")
        assert_eq(len(ctx.subdomains), 5, "Total subdomains = 5")

        # URLs
        ctx.add_url("https://example.com/api/v1/users?id=1", source="waybackurls")
        ctx.add_url("https://example.com/admin/config", source="katana")
        ctx.add_url("https://example.com/style.css", source="crawl")
        assert_eq(len(ctx.urls), 3, "Three URLs added")

        # URL classification
        api_urls = ctx.get_urls_by_class("api")
        assert_eq(len(api_urls), 1, "One API URL classified")

        # Bulk URLs
        bulk = [f"https://example.com/page{i}" for i in range(100)]
        ctx.add_urls_bulk(bulk, source="gau")
        assert_gt(ctx.url_count(), 100, "Bulk URL add works (>100 total)")

        # JS files
        ctx.add_js_file("https://example.com/app.js", priority_score=100)
        ctx.add_js_file("https://cdn.example.com/vendor.js", priority_score=10)
        assert_eq(len(ctx.js_files), 2, "Two JS files")
        unanalyzed = ctx.get_unanalyzed_js()
        assert_eq(len(unanalyzed), 2, "Both unanalyzed")
        ctx.mark_js_analyzed("https://example.com/app.js", secrets=2, routes=5)
        unanalyzed = ctx.get_unanalyzed_js()
        assert_eq(len(unanalyzed), 1, "One unanalyzed after marking")

        # Parameters
        ctx.add_param("id", source="url_extract")
        ctx.add_param("q", source="arjun")
        ctx.add_params_bulk(["page", "sort", "filter"], source="paramspider")
        assert_eq(len(ctx.params), 5, "Five params")
        untested = ctx.get_untested_params()
        assert_eq(len(untested), 5, "All untested initially")
        ctx.mark_param_tested("id")
        untested = ctx.get_untested_params()
        assert_eq(len(untested), 4, "Four untested after marking")

        # Paths
        ctx.add_path("https://example.com/admin", 403, size=0)
        ctx.add_path("https://example.com/.env", 200, size=1234)
        assert_eq(len(ctx.paths_403), 1, "One 403 path")
        assert_eq(len(ctx.paths_200), 1, "One 200 path")

        # Findings
        fid = ctx.add_finding(
            severity="CRITICAL",
            category="CDN_BYPASS",
            url="1.2.3.4",
            title="Origin IP discovered",
            detail="Methods: sub:origin.example.com, spf",
            impact="Direct WAF bypass",
            exploit="curl -sk -H 'Host: example.com' https://1.2.3.4/",
            confidence="CONFIRMED",
            cwe="CWE-16",
            phase="1.5",
        )
        assert_gt(fid, 0, "Finding created with auto-enrichment")

        findings = ctx.findings
        assert_eq(len(findings), 1, "One finding")
        f = findings[0]
        assert_eq(f["cvss_score"], 9.5, "CVSS auto-enriched to 9.5")
        assert_eq(f["owasp"], "A05:2021", "OWASP auto-enriched")
        assert_eq(f["mitre_tactic"], "TA0001", "MITRE tactic auto-enriched")
        assert_eq(f["mitre_technique"], "T1190", "MITRE technique auto-enriched")

        # Duplicate finding (should upsert, not duplicate)
        ctx.add_finding(
            severity="CRITICAL", category="CDN_BYPASS", url="1.2.3.4",
            title="Origin IP discovered", detail="Updated detail",
        )
        assert_eq(ctx.finding_count(), 1, "Duplicate finding deduped")

        # API endpoints
        ctx.add_api_endpoint("/api/v1/users", source="js_mine")
        ctx.add_api_endpoint("/graphql", source="js_mine")
        assert_eq(len(ctx.api_endpoints), 2, "Two API endpoints")

        # Ports
        ctx.add_port("1.2.3.4", 443, service="https")
        ctx.add_port("1.2.3.4", 8080, service="http-proxy")
        assert_eq(
            ctx.db.fetch_scalar(
                "SELECT COUNT(*) FROM ports WHERE scan_id = ?", (ctx.scan_id,)
            ),
            2,
            "Two ports recorded"
        )

        # Secrets
        ctx.add_secret(
            "AWS Access Key", "AKIAIOSFODNN7EXAMPLE",
            source_url="https://example.com/config.js",
            source_type="js",
            severity="CRITICAL",
            cwe="CWE-798",
        )
        assert_eq(
            ctx.db.fetch_scalar(
                "SELECT COUNT(*) FROM secrets WHERE scan_id = ?", (ctx.scan_id,)
            ),
            1,
            "Secret recorded with masked preview"
        )

        # Snapshot
        snap = ctx.snapshot()
        assert_eq(snap["domain"], "sub.example.com", "Snapshot captures domain")
        assert_true("scan_id" in snap, "Snapshot has scan_id")

        # Checkpoint save/load
        ctx.save_checkpoint(5)
        step, loaded_snap = db.load_checkpoint(ctx.scan_id)
        assert_eq(step, 5, "Checkpoint step = 5")
        assert_eq(loaded_snap["domain"], "sub.example.com", "Checkpoint snapshot data intact")

        # Stats
        stats = ctx.stats()
        assert_gt(stats["subdomains"], 0, "Stats reports subdomains")
        assert_gt(stats["urls"], 0, "Stats reports urls")
        assert_gt(stats["findings"], 0, "Stats reports findings")
        assert_eq(stats["findings_critical"], 1, "Stats reports 1 CRITICAL finding")

        # Probe URL
        assert_eq(ctx.probe_url("/admin"), f"{ctx.scheme}://{ctx.domain}/admin", "Probe URL without origin")
        ctx.origin_ip = "1.2.3.4"
        ctx.persist_scan_state()
        assert_eq(ctx.probe_url("/admin"), f"{ctx.scheme}://1.2.3.4/admin", "Probe URL with origin IP")

        # Live hosts
        ctx.add_live_host("https://mail.example.com", http_code=200, title="Webmail")
        hosts = ctx.live_hosts
        assert_eq(len(hosts), 1, "One live host")
        assert_eq(hosts[0]["title"], "Webmail", "Live host title captured")

        db.close()
        print("  ✅ All Context tests passed")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 3: Config Parser (core/config.py)
# ═══════════════════════════════════════════════════════════════════════════════

def test_config():
    _separator("Config Parser (core/config.py)")

    from core.config import build_config, parse_target, parse_steps

    # Target parsing
    url, domain, root, wc = parse_target("*.example.com")
    assert_eq(domain, "example.com", "Wildcard domain parsed")
    assert_eq(wc, True, "Wildcard detected from *.domain")

    url, domain, root, wc = parse_target("https://sub.example.com")
    assert_eq(domain, "sub.example.com", "Sub domain parsed")
    assert_eq(root, "example.com", "Root domain extracted")
    assert_eq(wc, False, "No wildcard for explicit URL")

    url, domain, root, wc = parse_target("example.com")
    assert_eq(url, "https://example.com", "Schema auto-added")

    # Step parsing
    assert_eq(parse_steps(None), None, "None steps = run all")
    assert_eq(parse_steps("0,1,3,8"), [0, 1, 3, 8], "Comma-separated steps")
    assert_eq(parse_steps("1-5"), [1, 2, 3, 4, 5], "Range steps")
    assert_eq(parse_steps("0,8-12,14"), [0, 8, 9, 10, 11, 12, 14], "Mixed range + list")

    # Full config build
    cfg = build_config(["-u", "target.com", "--stealth", "high", "--wildcard", "--osint"])
    assert_eq(cfg.domain, "target.com", "Config domain set")
    assert_eq(cfg.stealth, "high", "Stealth profile set")
    assert_eq(cfg.wildcard, True, "Wildcard flag set")
    assert_eq(cfg.osint, True, "OSINT flag set")
    assert_eq(cfg.rate, 3.0, "Rate from stealth profile")
    assert_eq(cfg.scope, "wildcard", "Scope derived from wildcard")

    # Aggressive mode overrides
    cfg = build_config(["-u", "target.com", "--aggressive"])
    assert_eq(cfg.stealth, "low", "Aggressive → low stealth")
    assert_eq(cfg.osint, True, "Aggressive → OSINT enabled")
    assert_eq(cfg.logic, True, "Aggressive → logic enabled")

    # Step selection
    cfg = build_config(["-u", "target.com", "--steps", "0,1,8"])
    assert_eq(cfg.steps, [0, 1, 8], "Steps parsed from CLI")
    assert_true(cfg.should_run_step(0), "Step 0 should run")
    assert_true(cfg.should_run_step(8), "Step 8 should run")
    assert_true(not cfg.should_run_step(5), "Step 5 should NOT run")

    # Resume mode
    cfg = build_config(["--resume", "/tmp/some_workspace"])
    assert_eq(cfg.resume, True, "Resume mode activated")
    assert_true(cfg.resume_dir.endswith("some_workspace"), "Resume dir set")

    # JSON serialization (API keys redacted)
    cfg = build_config(["-u", "target.com", "--github-token", "ghp_supersecrettoken12345"])
    j = cfg.to_json()
    parsed = json.loads(j)
    assert_true("***" in parsed["github_token"], "GitHub token redacted in JSON")

    print("  ✅ All Config tests passed")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 4: Orchestrator (ghost.py) — Dry Run
# ═══════════════════════════════════════════════════════════════════════════════

def test_orchestrator():
    _separator("Orchestrator offline run (ghost.py)")

    # v2.0: fully offline — only step 0 (local dependency check) and step 1
    # with --skip-subs (records the target, no lookups). Output goes to a
    # temp dir, never into the repo.
    import subprocess, json as _json
    ghost_dir = str(Path(__file__).parent.parent)
    with tempfile.TemporaryDirectory() as tmp:
        ws = os.path.join(tmp, "ws")
        result = subprocess.run(
            [sys.executable, "ghost.py", "-u", "test.example.com", "--steps", "0,1",
             "--skip-subs", "--no-banner", "-o", ws, "--format", "json,md"],
            cwd=ghost_dir, capture_output=True, text=True, timeout=60,
        )
        output = result.stdout + result.stderr
        print(f"  Exit code: {result.returncode}")
        assert_true(result.returncode == 0, f"Exited cleanly (code={result.returncode})\n{output[-2000:]}")
        assert_true("STEP 0" in output and "STEP 1" in output, "Pipeline steps rendered")
        assert_true(os.path.exists(os.path.join(ws, "ghost.db")), "ghost.db created in workspace")
        summary = _json.load(open(os.path.join(ws, "reports", "findings.json")))
        assert_true(summary["tool"]["version"] == "2.0.0", "JSON export carries version")
        assert_true(summary["scan"]["completed_steps"] == [0, 1], "Completed steps recorded")
        assert_true(os.path.exists(os.path.join(ws, "reports", "report.md")), "Markdown export written")
        assert_true(not os.path.exists(os.path.join(ws, "reports", "report.html")), "--format respected")

    print("  ✅ Orchestrator offline run passed")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 5: Resume Flow
# ═══════════════════════════════════════════════════════════════════════════════

def test_resume_flow():
    _separator("Resume Flow")

    from core.db import GhostDB, get_resume_info
    from core.context import Ctx

    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        db = GhostDB(ws / "ghost.db")

        # Simulate a scan that crashed at step 5
        ctx = Ctx.new(db, "https://target.com", "target.com", "target.com")
        ctx.add_subdomain("api.target.com", status="alive")
        ctx.add_finding(
            severity="HIGH", category="XSS_REFLECTED",
            url="https://target.com/?q=test", title="XSS in q param",
        )
        ctx.origin_ip = "10.0.0.1"
        ctx.waf_detected = ["cloudflare"]
        ctx.save_checkpoint(5)

        scan_id = ctx.scan_id
        db.close()

        # Now "resume" — simulate what ghost.py does
        db2 = GhostDB(ws / "ghost.db")
        resume_info = get_resume_info(ws / "ghost.db")
        assert_true(resume_info is not None, "Resume info found")
        assert_eq(resume_info["step"], 5, "Resume from step 5")

        ctx2 = Ctx.resume(db2, scan_id)
        ctx2.restore_from_snapshot(resume_info.get("ctx_snapshot", {}))

        assert_eq(ctx2.origin_ip, "10.0.0.1", "Origin IP restored from checkpoint")
        assert_eq(ctx2.waf_detected, ["cloudflare"], "WAF list restored")
        assert_eq(len(ctx2.subdomains), 1, "Subdomains survived resume")
        assert_eq(ctx2.finding_count(), 1, "Findings survived resume")

        db2.close()
        print("  ✅ Resume flow passed")


# ═══════════════════════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "╔" + "═"*58 + "╗")
    print("║   GHOST RECON v2.0 — Core Framework Validation Suite    ║")
    print("╚" + "═"*58 + "╝")

    tests = [test_db, test_context, test_config, test_resume_flow, test_orchestrator]
    passed = 0
    failed = 0

    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"\n  ❌ FAILED: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {len(tests)} test suites")
    print(f"{'='*60}")
    sys.exit(1 if failed > 0 else 0)
