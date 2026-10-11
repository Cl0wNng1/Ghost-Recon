"""v15 tests: scope guard, token bucket rate limiter, authz matrix."""
import asyncio
import time

import pytest

from core.scope import ScopeGuard, build_scope_guard, ScopeError
from core.http import TokenBucket, AuthSession
from core.authz_matrix import AuthzMatrix


# ── ScopeGuard ──────────────────────────────────────────────────────────────
def test_scope_root_and_wildcard():
    g = ScopeGuard(root_domain="example.com", wildcard=True)
    assert g.is_in_scope("https://example.com/x")
    assert g.is_in_scope("https://api.example.com")
    assert not g.is_in_scope("https://evil.com")
    assert not g.is_in_scope("https://notexample.com")


def test_scope_single_rejects_subdomains():
    g = ScopeGuard(root_domain="example.com", wildcard=False)
    assert g.is_in_scope("https://example.com")
    assert not g.is_in_scope("https://api.example.com")


def test_scope_denylist_wins():
    g = ScopeGuard(root_domain="example.com", wildcard=True,
                   deny_hosts=["admin.example.com"])
    assert not g.is_in_scope("https://admin.example.com")
    assert g.is_in_scope("https://app.example.com")


def test_scope_blocks_private_ip():
    g = ScopeGuard(root_domain="example.com", wildcard=True)
    assert not g.is_in_scope("http://127.0.0.1")
    assert not g.is_in_scope("http://10.0.0.5")
    assert not g.is_in_scope("http://169.254.1.1")


def test_scope_allow_cidr_overrides_private():
    g = ScopeGuard(allow_cidrs=["10.0.0.0/24"])
    assert g.is_in_scope("http://10.0.0.5")
    assert not g.is_in_scope("http://10.0.1.5")


def test_scope_enforce_raises():
    g = ScopeGuard(root_domain="example.com", enforce=True)
    with pytest.raises(ScopeError):
        g.assert_in_scope("https://evil.com")


def test_scope_filter_and_rejected():
    g = ScopeGuard(root_domain="example.com", wildcard=True)
    urls = ["https://example.com/a", "https://evil.com", "https://x.example.com"]
    assert g.filter(urls) == ["https://example.com/a", "https://x.example.com"]
    assert g.rejected(urls) == ["https://evil.com"]


def test_build_scope_guard_from_config():
    class C:
        scope = "wildcard"
        wildcard = True
    class X:
        root_domain = "example.com"
    g = build_scope_guard(C(), X())
    assert g.is_in_scope("https://sub.example.com")


# ── TokenBucket ─────────────────────────────────────────────────────────────
def test_token_bucket_enforces_rate():
    async def run():
        tb = TokenBucket(rate=20.0, burst=1.0)  # ~20/s, tiny burst
        start = time.monotonic()
        for _ in range(5):
            await tb.acquire()
        return time.monotonic() - start
    elapsed = asyncio.run(run())
    # 5 tokens, burst 1 → ~4 refills at 20/s ≈ 0.2s. Allow slack.
    assert elapsed >= 0.15


# ── AuthSession ─────────────────────────────────────────────────────────────
def test_auth_session_headers_roundtrip():
    a = AuthSession(bearer="tok", csrf_token="c", cookies={"s": "1"})
    h = a.as_headers()
    assert h["Authorization"] == "Bearer tok"
    assert h["X-CSRF-Token"] == "c"
    a2 = AuthSession.from_dict(a.to_dict())
    assert a2.bearer == "tok" and a2.cookies == {"s": "1"}


# ── AuthzMatrix ─────────────────────────────────────────────────────────────
class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._ghost_text = body
        self.url = "http://t/"


class _FakeClient:
    """Returns a canned response per URL, ignoring auth (test double)."""
    def __init__(self, table):
        self.table = table
    async def request(self, method, url):
        status, body = self.table.get(url, (404, ""))
        return _FakeResp(status, body)


def test_authz_detects_privileged_access_by_lowpriv():
    admin_body = "SECRET ADMIN PANEL " * 50
    m = AuthzMatrix(similarity_threshold=0.9)
    # userA sees the same admin content it shouldn't
    m.add_identity("admin", _FakeClient({"http://t/admin": (200, admin_body)}), rank=4)
    m.add_identity("userA", _FakeClient({"http://t/admin": (200, admin_body)}), rank=1)
    findings = asyncio.run(m.probe(["http://t/admin"]))
    assert any(f["category"] == "Broken Access Control" for f in findings)


def test_authz_no_finding_when_lowpriv_blocked():
    admin_body = "SECRET ADMIN PANEL " * 50
    m = AuthzMatrix(similarity_threshold=0.9)
    m.add_identity("admin", _FakeClient({"http://t/admin": (200, admin_body)}), rank=4)
    m.add_identity("userA", _FakeClient({"http://t/admin": (403, "forbidden")}), rank=1)
    findings = asyncio.run(m.probe(["http://t/admin"]))
    assert not findings


def test_authz_anonymous_access_to_protected():
    m = AuthzMatrix()
    m.add_identity("admin", _FakeClient({"http://t/x": (302, "")}), rank=4)
    m.add_identity("anon", _FakeClient({"http://t/x": (200, "data here")}), rank=0)
    findings = asyncio.run(m.probe(["http://t/x"]))
    assert any("without authentication" in f["title"] for f in findings)
