#!/usr/bin/env python3
"""
GHOST v11.0 — Step Module Validation
Tests: step00_deps.py, step01_discovery.py
Validates import, interface compliance, and dry-run execution.
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _separator(name):
    print(f"\n{'='*60}")
    print(f"  TEST: {name}")
    print(f"{'='*60}")


def assert_true(val, msg=""):
    if not val:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ✓ {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1: Step 00 — Module Interface & Execution
# ═══════════════════════════════════════════════════════════════════════════════

def test_step00():
    _separator("Step 00: Dependency Validation")

    import modules.step00_deps as step00

    # Interface compliance
    assert_true(hasattr(step00, "STEP_NUM"), "Has STEP_NUM")
    assert_true(hasattr(step00, "STEP_NAME"), "Has STEP_NAME")
    assert_true(hasattr(step00, "execute"), "Has execute()")
    assert_true(step00.STEP_NUM == 0, "STEP_NUM == 0")
    assert_true(asyncio.iscoroutinefunction(step00.execute), "execute() is async")

    # Dry-run execution
    from core.db import GhostDB
    from core.context import Ctx
    from core.config import Config

    with tempfile.TemporaryDirectory() as tmpdir:
        db = GhostDB(Path(tmpdir) / "test.db")
        ctx = Ctx.new(db, "https://test.com", "test.com", "test.com")
        config = Config(target_url="https://test.com", domain="test.com", root_domain="test.com")

        # Execute — should never crash even without any tools installed
        result_ctx = asyncio.run(step00.execute(ctx, None, config))
        assert_true(result_ctx is ctx, "Returns ctx unchanged")
        assert_true(result_ctx.finding_count() == 0, "No findings added (correct)")

        db.close()
    print("  ✅ Step 00 passed")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2: Step 01 — Module Interface & Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def test_step01_interface():
    _separator("Step 01: Interface & Helpers")

    import modules.step01_discovery as step01

    # Interface compliance
    assert_true(hasattr(step01, "STEP_NUM"), "Has STEP_NUM")
    assert_true(hasattr(step01, "STEP_NAME"), "Has STEP_NAME")
    assert_true(hasattr(step01, "execute"), "Has execute()")
    assert_true(step01.STEP_NUM == 1, "STEP_NUM == 1")
    assert_true(asyncio.iscoroutinefunction(step01.execute), "execute() is async")

    # Test _clean_subs helper
    raw = """
    [INF] sub.example.com
    mail.example.com
    https://dev.example.com/path
    *.test.example.com
    notrelated.other.com
    admin.example.com
    CAPS.example.com
    """
    subs = step01._clean_subs(raw, "example.com")
    assert_true("sub.example.com" in subs, "Extracts simple subdomain")
    assert_true("mail.example.com" in subs, "Extracts plain subdomain")
    assert_true("dev.example.com" in subs, "Extracts from URL")
    assert_true("test.example.com" in subs, "Strips wildcard prefix")
    assert_true("notrelated.other.com" not in subs, "Filters out-of-scope")
    assert_true("caps.example.com" in subs, "Lowercases domains")
    assert_true("admin.example.com" in subs, "Extracts admin subdomain")

    print("  ✅ Step 01 interface & helpers passed")


def test_step01_execution():
    _separator("Step 01: Dry-Run Execution (no tools)")

    import modules.step01_discovery as step01
    from core.db import GhostDB
    from core.context import Ctx
    from core.config import Config

    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir) / "workspace"
        ws.mkdir()
        (ws / "recon").mkdir()

        db = GhostDB(ws / "ghost.db")
        ctx = Ctx.new(db, "https://test.example.com", "test.example.com", "example.com",
                      scope="wildcard")
        config = Config(
            target_url="https://test.example.com",
            domain="test.example.com",
            root_domain="example.com",
            scope="wildcard",
            workspace=str(ws),
        )

        # Execute with no tools and no engine — should handle gracefully
        result_ctx = asyncio.run(step01.execute(ctx, None, config))

        # Should have at least the primary target + root domain
        subs = result_ctx.subdomains
        assert_true("test.example.com" in subs, "Primary target in subdomains")
        assert_true("example.com" in subs, "Root domain in subdomains")
        assert_true(len(subs) >= 2, f"At least 2 subdomains (got {len(subs)})")

        # Check that the subdomain file was written
        subs_file = ws / "recon" / "subdomains_raw.txt"
        assert_true(subs_file.exists(), "subdomains_raw.txt created")

        db.close()
    print("  ✅ Step 01 execution passed")


def test_step01_skip_subs():
    _separator("Step 01: --skip-subs Flag")

    import modules.step01_discovery as step01
    from core.db import GhostDB
    from core.context import Ctx
    from core.config import Config

    with tempfile.TemporaryDirectory() as tmpdir:
        db = GhostDB(Path(tmpdir) / "test.db")
        ctx = Ctx.new(db, "https://app.target.com", "app.target.com", "target.com")
        config = Config(
            target_url="https://app.target.com",
            domain="app.target.com",
            root_domain="target.com",
            skip_subs=True,
        )

        result_ctx = asyncio.run(step01.execute(ctx, None, config))

        subs = result_ctx.subdomains
        assert_true("app.target.com" in subs, "Primary target added despite --skip-subs")
        assert_true(len(subs) == 1, "Only primary target (skip-subs)")

        db.close()
    print("  ✅ Step 01 --skip-subs passed")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 3: Orchestrator Integration
# ═══════════════════════════════════════════════════════════════════════════════

def test_orchestrator_with_modules():
    _separator("Orchestrator with Step 0 + Step 1")

    import subprocess
    ghost_dir = str(Path(__file__).parent.parent)
    result = subprocess.run(
        [sys.executable, "ghost.py", "-u", "orchestrator-test.example.com", "--steps", "0,1",
         "--skip-subs", "--no-banner", "-o", os.path.join(tempfile.gettempdir(), "hunt_orchestrator_test")],
        cwd=ghost_dir,
        capture_output=True,
        text=True,
        timeout=30,
    )

    output = result.stdout + result.stderr

    # Step 0 should have run (not "not found")
    assert_true(
        "Dependency" in output or "environment" in output.lower() or "Tool" in output,
        "Step 0 executed (not skipped as missing)"
    )

    # Should complete cleanly
    assert_true(result.returncode == 0, f"Clean exit (code={result.returncode})")

    # Cleanup workspace
    import glob, shutil
    for ws in glob.glob(os.path.join(tempfile.gettempdir(), "hunt_orchestrator*")):
        shutil.rmtree(ws, ignore_errors=True)

    print("  ✅ Orchestrator integration passed")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 4: Concurrent Tool Execution (unit test _run_tool)
# ═══════════════════════════════════════════════════════════════════════════════

def test_run_tool():
    _separator("Async _run_tool helper")

    import modules.step01_discovery as step01

    async def _test():
        # Test with a tool that exists everywhere (echo)
        name, subs, error = await step01._run_tool(
            "echo_test",
            ["echo", "sub1.example.com\nsub2.example.com\ngarbage"],
            "example.com",
            timeout=5.0,
        )
        assert_true(name == "echo_test", "Returns tool name")
        assert_true(error is None, "No error for successful echo")
        assert_true("sub1.example.com" in subs, "Parsed sub1 from echo output")
        assert_true("sub2.example.com" in subs, "Parsed sub2 from echo output")
        assert_true(len(subs) == 2, f"Only valid subs extracted (got {len(subs)})")

        # Test with non-existent binary
        name2, subs2, error2 = await step01._run_tool(
            "fake_tool",
            ["this_binary_does_not_exist_xyz", "--help"],
            "example.com",
            timeout=5.0,
        )
        assert_true(error2 is not None, "Error returned for missing binary")
        assert_true(len(subs2) == 0, "No subs from missing binary")

        # Test timeout handling
        name3, subs3, error3 = await step01._run_tool(
            "timeout_test",
            ["sleep", "30"],
            "example.com",
            timeout=1.0,
        )
        assert_true("Timed out" in (error3 or ""), "Timeout detected and reported")

    asyncio.run(_test())
    print("  ✅ _run_tool helper passed")


# ═══════════════════════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "╔" + "═"*58 + "╗")
    print("║   GHOST v11.0 — Step Module Validation Suite             ║")
    print("╚" + "═"*58 + "╝")

    tests = [
        test_step00,
        test_step01_interface,
        test_step01_execution,
        test_step01_skip_subs,
        test_run_tool,
        test_orchestrator_with_modules,
    ]
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
    print(f"  RESULTS: {passed} passed, {failed} failed out of {len(tests)}")
    print(f"{'='*60}")
    sys.exit(1 if failed > 0 else 0)
