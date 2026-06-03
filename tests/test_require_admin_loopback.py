"""Regression tests for require_admin's internal-tool loopback gate (H3).

The header-direct admin bypass must require BOTH a valid internal-tool token
AND a trusted (direct) loopback connection — a correct token alone, presented
from a remote/tunneled origin, must not grant admin.
"""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core.middleware import (
    require_admin,
    is_trusted_loopback,
    INTERNAL_TOOL_HEADER,
    INTERNAL_TOOL_TOKEN,
)


def _req(host, headers, current_user=None, auth_manager=None):
    return SimpleNamespace(
        client=SimpleNamespace(host=host),
        headers=headers,
        state=SimpleNamespace(current_user=current_user),
        app=SimpleNamespace(state=SimpleNamespace(auth_manager=auth_manager)),
    )


def _ensure_auth_on(monkeypatch):
    # require_admin returns early if AUTH_ENABLED=false; keep it on for these.
    monkeypatch.setenv("AUTH_ENABLED", "true")


# ── is_trusted_loopback ──────────────────────────────────────────────

def test_trusted_loopback_direct():
    assert is_trusted_loopback(_req("127.0.0.1", {}))
    assert is_trusted_loopback(_req("::1", {}))


def test_not_trusted_when_proxy_forwarded():
    assert not is_trusted_loopback(_req("127.0.0.1", {"x-forwarded-for": "1.2.3.4"}))
    assert not is_trusted_loopback(_req("127.0.0.1", {"cf-connecting-ip": "1.2.3.4"}))


def test_not_trusted_when_remote():
    assert not is_trusted_loopback(_req("8.8.8.8", {}))


# ── require_admin token-path gating ──────────────────────────────────

def test_valid_token_on_loopback_grants(monkeypatch):
    _ensure_auth_on(monkeypatch)
    # Must not raise.
    require_admin(_req("127.0.0.1", {INTERNAL_TOOL_HEADER: INTERNAL_TOOL_TOKEN}))


def test_valid_token_from_remote_denied(monkeypatch):
    """A correct token from a non-loopback client must NOT grant admin (H3)."""
    _ensure_auth_on(monkeypatch)
    with pytest.raises(HTTPException):
        require_admin(_req("8.8.8.8", {INTERNAL_TOOL_HEADER: INTERNAL_TOOL_TOKEN}))


def test_valid_token_with_proxy_header_denied(monkeypatch):
    """Loopback client IP but proxy-forwarded (tunnel) → not trusted (H3)."""
    _ensure_auth_on(monkeypatch)
    req = _req("127.0.0.1", {
        INTERNAL_TOOL_HEADER: INTERNAL_TOOL_TOKEN,
        "x-forwarded-for": "1.2.3.4",
    })
    with pytest.raises(HTTPException):
        require_admin(req)


def test_internal_tool_current_user_grants(monkeypatch):
    """Path (b): middleware already validated token+loopback and stamped the
    synthetic user — still honored."""
    _ensure_auth_on(monkeypatch)
    require_admin(_req("127.0.0.1", {}, current_user="internal-tool"))


def test_wrong_token_denied(monkeypatch):
    _ensure_auth_on(monkeypatch)
    with pytest.raises(HTTPException):
        require_admin(_req("127.0.0.1", {INTERNAL_TOOL_HEADER: "wrong"}))


def test_auth_disabled_grants(monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    require_admin(_req("8.8.8.8", {}))  # explicit single-user mode
