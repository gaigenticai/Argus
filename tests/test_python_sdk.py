"""Argus Python SDK (P3 #3.4) — integration tests against the test app.

httpx's ``ASGITransport`` is async-only, so the integration tests use
``ArgusAsyncClient``. The sync client (``ArgusClient``) shares all
auth / error / serdes logic with the async client; we cover that
shared logic + the sync-only context-manager behaviour with unit
tests at the bottom of this file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

# Ensure the SDK is importable without a pip install.
_ROOT = Path(__file__).resolve().parent.parent
_SDK = _ROOT / "clients" / "python"
if str(_SDK) not in sys.path:
    sys.path.insert(0, str(_SDK))

from argus_sdk import ArgusAsyncClient, ArgusClient, ArgusError    # noqa: E402

pytestmark = pytest.mark.asyncio


def _async_sdk_for(test_app, *, api_key: str | None = None,
                     access_token: str | None = None) -> ArgusAsyncClient:
    """Build an ArgusAsyncClient that routes through the in-memory ASGI app."""
    sdk = ArgusAsyncClient(
        base_url="http://testserver",
        api_key=api_key,
        access_token=access_token,
    )
    transport = httpx.ASGITransport(app=test_app)
    sdk._http = httpx.AsyncClient(
        base_url="http://testserver", transport=transport,
    )
    return sdk


# ── Integration tests via async client ──────────────────────────────


async def test_sdk_login_round_trip(client, analyst_user):
    from src.api.app import app
    sdk = _async_sdk_for(app)
    await sdk.login(analyst_user["email"], analyst_user["password"])
    assert sdk._access_token

    out = await sdk.alerts.list(limit=1)
    assert isinstance(out, list)
    await sdk.close()


async def test_sdk_login_bad_password_raises_argus_error(client, analyst_user):
    from src.api.app import app
    sdk = _async_sdk_for(app)
    with pytest.raises(ArgusError) as exc:
        await sdk.login(analyst_user["email"], "wrong-password")
    assert exc.value.status in (400, 401, 403)
    await sdk.close()


async def test_sdk_alerts_list_with_token(client, analyst_user):
    from src.api.app import app
    sdk = _async_sdk_for(app, access_token=analyst_user["token"])
    out = await sdk.alerts.list(limit=5)
    assert isinstance(out, list)
    await sdk.close()


async def test_sdk_alerts_list_without_auth_raises(client):
    from src.api.app import app
    sdk = _async_sdk_for(app)    # no api_key, no token
    with pytest.raises(ArgusError) as exc:
        await sdk.alerts.list()
    assert exc.value.status in (401, 403)
    await sdk.close()


async def test_sdk_intel_sigma_backends(client, analyst_user):
    from src.api.app import app
    sdk = _async_sdk_for(app, access_token=analyst_user["token"])
    backends = await sdk.intel.sigma_backends()
    assert isinstance(backends, list)
    await sdk.close()


async def test_sdk_intel_yara_availability(client, analyst_user):
    from src.api.app import app
    sdk = _async_sdk_for(app, access_token=analyst_user["token"])
    out = await sdk.intel.yara_availability()
    assert isinstance(out, dict)
    await sdk.close()


async def test_sdk_subscriptions_round_trip(client, analyst_user):
    """End-to-end: list → create → list → delete via the SDK."""
    from src.api.app import app
    sdk = _async_sdk_for(app, access_token=analyst_user["token"])
    initial = await sdk.subscriptions.list()
    assert isinstance(initial, list)
    created = await sdk.subscriptions.create(
        name="SDK test sub",
        filter={"severity": ["critical"]},
        channels=[{"type": "webhook",
                   "url": "https://example.invalid/hook"}],
    )
    assert created["name"] == "SDK test sub"
    assert "id" in created
    after_create = await sdk.subscriptions.list()
    assert any(s["id"] == created["id"] for s in after_create)
    await sdk.subscriptions.delete(created["id"])
    after_delete = await sdk.subscriptions.list()
    assert all(s["id"] != created["id"] for s in after_delete)
    await sdk.close()


async def test_sdk_argus_error_carries_detail(client, analyst_user):
    """The SDK converts FastAPI's HTTPException(detail=...) into an
    ArgusError whose .detail is the parsed string."""
    from src.api.app import app
    sdk = _async_sdk_for(app, access_token=analyst_user["token"])
    with pytest.raises(ArgusError) as exc:
        await sdk.alerts.get("00000000-0000-0000-0000-000000000000")
    assert exc.value.status in (404, 400, 422)
    assert exc.value.detail
    await sdk.close()


# ── Unit tests for the shared sync logic ───────────────────────────


def test_sdk_context_manager_closes_session():
    """``with ArgusClient(...) as c`` should close the httpx session."""
    sdk = ArgusClient(base_url="http://localhost")
    with sdk as c:
        assert c is sdk
    sdk.close()  # idempotent


def test_sdk_headers_prefer_token_over_api_key():
    """When both auth modes are present, Bearer token wins."""
    sdk = ArgusClient(
        base_url="http://localhost",
        api_key="key-1",
        access_token="tok-1",
    )
    h = sdk._headers()
    assert h["Authorization"] == "Bearer tok-1"
    assert "X-API-Key" not in h
    sdk.close()


def test_sdk_headers_fall_back_to_api_key():
    sdk = ArgusClient(base_url="http://localhost", api_key="key-1")
    h = sdk._headers()
    assert h["X-API-Key"] == "key-1"
    assert "Authorization" not in h
    sdk.close()


def test_sdk_headers_unauth_path_omits_credentials():
    sdk = ArgusClient(base_url="http://localhost", api_key="key-1")
    h = sdk._headers(auth_required=False)
    assert "X-API-Key" not in h
    assert "Authorization" not in h
    sdk.close()


def test_argus_error_str_includes_status():
    e = ArgusError(404, "not found")
    assert "HTTP 404" in str(e)
    assert "not found" in str(e)
    assert e.status == 404
