"""Regression tests for the /v1/chat base_url SSRF fix (C2).

Three layers:
  1. url_safety blocks CGNAT/Tailscale (100.64/10) when block_private=True
     (Python's is_private does NOT cover it), and keeps it usable otherwise.
  2. The llm_core dispatch chokepoint blocks metadata/link-local on every call
     while leaving local models (loopback / LAN / Tailnet) reachable.
  3. The chokepoint never hard-fails on a DNS hiccup (no SSRF possible there).
"""

import pytest
from fastapi import HTTPException


# ── url_safety: CGNAT handling ───────────────────────────────────────

def test_cgnat_blocked_when_private_blocked():
    from src.url_safety import check_outbound_url
    ok, reason = check_outbound_url("http://100.64.0.5:8000/v1", block_private=True)
    assert not ok
    assert "100.64.0.5" in reason


def test_cgnat_allowed_when_private_permitted():
    """Local models on a Tailnet must still work (block_private=False)."""
    from src.url_safety import check_outbound_url
    ok, _ = check_outbound_url("http://100.64.0.5:8000/v1", block_private=False)
    assert ok


def test_metadata_blocked_regardless_of_flag():
    from src.url_safety import check_outbound_url
    for bp in (True, False):
        ok, reason = check_outbound_url("http://169.254.169.254/latest", block_private=bp)
        assert not ok
        assert "link-local" in reason


def test_loopback_blocked_only_when_private_blocked():
    from src.url_safety import check_outbound_url
    assert check_outbound_url("http://127.0.0.1:11434/v1", block_private=False)[0]
    assert not check_outbound_url("http://127.0.0.1:11434/v1", block_private=True)[0]


# ── llm_core dispatch chokepoint (metadata-only net) ─────────────────

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434/v1/chat/completions",   # ollama
    "http://192.168.1.50:8000/v1/chat/completions",  # LAN vLLM
    "http://100.64.0.5:8000/v1/chat/completions",    # tailnet peer
    "https://api.openai.com/v1/chat/completions",     # cloud
])
def test_guard_allows_legitimate_targets(url):
    from src.llm_core import _guard_outbound_target
    _guard_outbound_target(url)  # must not raise


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/x",
])
def test_guard_blocks_metadata(url):
    from src.llm_core import _guard_outbound_target
    with pytest.raises(HTTPException):
        _guard_outbound_target(url)


def test_guard_passes_through_unresolvable_host():
    """A host that won't resolve can't be reached, so the guard must not hard-
    fail (httpx handles the real failure). No SSRF is possible here."""
    from src.llm_core import _guard_outbound_target
    _guard_outbound_target("http://no-such-host.invalid./v1")  # must not raise


@pytest.mark.asyncio
async def test_guard_async_blocks_metadata():
    from src.llm_core import _guard_outbound_target_async
    with pytest.raises(HTTPException):
        await _guard_outbound_target_async("http://169.254.169.254/latest")


@pytest.mark.asyncio
async def test_guard_async_allows_loopback():
    from src.llm_core import _guard_outbound_target_async
    await _guard_outbound_target_async("http://127.0.0.1:11434/v1")  # must not raise
