"""IBM X-Force Exchange enrichment — fixture tests.

Pins the /ipr/<ip> response parser, basic-auth header construction,
and the 401/402/404/429 error mapping. Realistic shapes mirror IBM's
X-Force API documentation (May 2026).
"""

from __future__ import annotations

import contextlib
from base64 import b64decode
from unittest.mock import patch

import pytest

import src.enrichment.xforce as xf_mod
from src.enrichment.xforce import XforceResult, check_ip, is_configured

pytestmark = pytest.mark.asyncio


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None, captured_headers=None):
        self.status = status
        self._json = json_body
        self._text = text_body or ""
        # Side-channel for assertions on auth header
        self._captured_headers = captured_headers

    async def json(self, content_type=None):
        return self._json

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response: _FakeResp, captured_headers: dict):
        self._response = response
        self._captured = captured_headers

    def get(self, url, *args, headers=None, **kwargs):
        if headers and self._captured is not None:
            self._captured.clear()
            self._captured.update(headers)
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(response: _FakeResp, captured_headers=None):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(response, captured_headers)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


@contextlib.contextmanager
def _no_cache():
    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(xf_mod, "_from_cache", _miss):
        with patch.object(xf_mod, "_store_cache", _store):
            yield


@contextlib.contextmanager
def _creds(monkeypatch_env_method, key="myapikey", password="mypassword"):
    monkeypatch_env_method.setenv("ARGUS_XFORCE_API_KEY", key)
    monkeypatch_env_method.setenv("ARGUS_XFORCE_API_PASSWORD", password)
    yield


# Realistic X-Force /ipr/<ip> response.
_HIT_PAYLOAD = {
    "ip": "203.0.113.42",
    "score": 7.4,
    "reason": "Anonymisation Services",
    "reasonDescription": "This IP appears in Anonymisation Services categories.",
    "cats": {"Anonymisation Services": 100, "Bots": 28},
    "subnets": [
        {"created": "2020-04-12T07:30:48.000Z", "ip": "203.0.113.0/24",
         "score": 7.4, "geo": {"country": "Romania", "countrycode": "RO"}},
    ],
    "geo": {"country": "Romania", "countrycode": "RO"},
    "history": [],
    "tags": [],
}


# ── is_configured ───────────────────────────────────────────────────


def test_is_configured_requires_both_key_and_password(monkeypatch):
    monkeypatch.delenv("ARGUS_XFORCE_API_KEY", raising=False)
    monkeypatch.delenv("ARGUS_XFORCE_API_PASSWORD", raising=False)
    assert is_configured() is False

    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    assert is_configured() is False  # password still missing

    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    assert is_configured() is True


# ── Hit path ────────────────────────────────────────────────────────


async def test_check_ip_hit_normalises_response(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")

    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=_HIT_PAYLOAD)):
        result = await check_ip("203.0.113.42")
    assert isinstance(result, XforceResult)
    assert result.success is True
    assert result.in_corpus is True
    assert result.score == 7.4
    assert result.reason == "Anonymisation Services"
    assert result.reason_description.startswith("This IP")
    assert result.categories == {"Anonymisation Services": 100, "Bots": 28}
    assert result.country == "Romania"


# ── Auth header pinning ─────────────────────────────────────────────


async def test_check_ip_sends_basic_auth_header(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "myapikey")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "myapipassword")

    captured: dict[str, str] = {}
    with _no_cache(), _patch_session(
        _FakeResp(status=200, json_body=_HIT_PAYLOAD), captured_headers=captured,
    ):
        await check_ip("8.8.8.8")

    assert "Authorization" in captured
    auth = captured["Authorization"]
    assert auth.startswith("Basic ")
    decoded = b64decode(auth[len("Basic "):]).decode()
    assert decoded == "myapikey:myapipassword"


# ── 404 → clean miss ────────────────────────────────────────────────


async def test_check_ip_404_is_clean_miss(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")

    with _no_cache(), _patch_session(_FakeResp(status=404)):
        result = await check_ip("192.0.2.1")
    assert result.success is True
    assert result.in_corpus is False
    assert result.error is None


# ── Error paths ─────────────────────────────────────────────────────


async def test_check_ip_unconfigured_short_circuits(monkeypatch):
    """No HTTP call when creds absent — no _patch_session would also
    catch it via NameError, but verify the explicit guard."""
    monkeypatch.delenv("ARGUS_XFORCE_API_KEY", raising=False)
    monkeypatch.delenv("ARGUS_XFORCE_API_PASSWORD", raising=False)
    result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "not configured" in (result.error or "").lower()


async def test_check_ip_401_credentials_rejected(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    with _no_cache(), _patch_session(_FakeResp(status=401)):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "401" in (result.error or "")
    assert "rejected" in (result.error or "").lower()


async def test_check_ip_402_quota_exhausted(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    with _no_cache(), _patch_session(_FakeResp(status=402)):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "quota" in (result.error or "").lower()


async def test_check_ip_429_rate_limited(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    with _no_cache(), _patch_session(_FakeResp(status=429)):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "429" in (result.error or "")


async def test_check_ip_500_returns_error(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    with _no_cache(), _patch_session(_FakeResp(status=500)):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "500" in (result.error or "")


async def test_check_ip_unexpected_payload(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=[])):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "unexpected" in (result.error or "").lower()


async def test_check_ip_empty_input(monkeypatch):
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    result = await check_ip("")
    assert result.success is False
    assert "empty" in (result.error or "").lower()


# ── Geo nullability ─────────────────────────────────────────────────


async def test_check_ip_handles_missing_geo(monkeypatch):
    """Some X-Force responses omit geo entirely. Don't crash."""
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    payload = {**_HIT_PAYLOAD}
    payload.pop("geo")
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=payload)):
        result = await check_ip("8.8.8.8")
    assert result.success is True
    assert result.country is None


async def test_check_ip_handles_geo_as_non_dict(monkeypatch):
    """Defensive — if X-Force returns geo as a list or string, country
    falls back to None."""
    monkeypatch.setenv("ARGUS_XFORCE_API_KEY", "k")
    monkeypatch.setenv("ARGUS_XFORCE_API_PASSWORD", "p")
    payload = {**_HIT_PAYLOAD, "geo": "garbage"}
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=payload)):
        result = await check_ip("8.8.8.8")
    assert result.success is True
    assert result.country is None
