"""Regression tests for the app_api endpoint blocklist (M2).

The `app_api` agent tool loopbacks to internal endpoints with the internal-tool
(admin) token. Vault unlock/lock must never be agent-reachable: a prompt-injected
agent could POST /api/vault/unlock to brute-force the master password, or lock/
logout to DoS the user's vault. The blocklist check runs before any network call.
"""

import pytest


def test_vault_prefix_in_blocklist():
    from src.tool_implementations import _APP_API_BLOCKLIST_PREFIXES
    assert "/api/vault" in _APP_API_BLOCKLIST_PREFIXES


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/api/vault/unlock",
    "/api/vault/lock",
    "/api/vault/logout",
    "/api/vault/config",
    "/api/vault",
])
async def test_app_api_blocks_vault(path):
    import json
    from src.tool_implementations import do_app_api
    result = await do_app_api(json.dumps({"path": path, "method": "POST"}))
    assert "blocked" in (result.get("error") or "").lower()
    assert result.get("exit_code") == 1
