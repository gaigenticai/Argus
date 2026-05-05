"""ipinfo.io Lite enrichment — fixture tests.

Pins the Lite tier response parser, token-not-set short-circuit,
and 401/429 error mapping.
"""

from __future__ import annotations

import contextlib
from unittest.mock import patch

import pytest

import src.enrichment.ipinfo_lite as il_mod
from src.enrichment.ipinfo_lite import IpinfoLiteResult, is_configured, lookup

pytestmark = pytest.mark.asyncio


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = text_body or ""

    async def json(self, content_type=None):
        return self._json

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response: _FakeResp):
        self._response = response

    def get(self, *args, **kwargs):
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(response: _FakeResp):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(response)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


@contextlib.contextmanager
def _no_cache():
    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(il_mod, "_from_cache", _miss):
        with patch.object(il_mod, "_store_cache", _store):
            yield


# Realistic ipinfo Lite response (May 2026 docs).
_HIT_PAYLOAD = {
    "ip": "8.8.8.8",
    "asn": "AS15169",
    "as_name": "Google LLC",
    "as_domain": "google.com",
    "country_code": "US",
    "country": "United States",
    "continent_code": "NA",
    "continent": "North America",
}


# ── is_configured ───────────────────────────────────────────────────


def test_is_configured_requires_token(monkeypatch):
    monkeypatch.delenv("ARGUS_IPINFO_LITE_TOKEN", raising=False)
    assert is_configured() is False
    monkeypatch.setenv("ARGUS_IPINFO_LITE_TOKEN", "xyz")
    assert is_configured() is True


# ── Hit path ────────────────────────────────────────────────────────


async def test_lookup_hit_normalises_response(monkeypatch):
    monkeypatch.setenv("ARGUS_IPINFO_LITE_TOKEN", "xyz")
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=_HIT_PAYLOAD)):
        result = await lookup("8.8.8.8")
    assert isinstance(result, IpinfoLiteResult)
    assert result.success is True
    assert result.asn == "AS15169"
    assert result.as_name == "Google LLC"
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.continent_code == "NA"


# ── Token missing short-circuits, no HTTP ──────────────────────────


async def test_lookup_no_token_short_circuits(monkeypatch):
    monkeypatch.delenv("ARGUS_IPINFO_LITE_TOKEN", raising=False)
    # No _patch_session would be invoked — test would crash if HTTP fired.
    result = await lookup("8.8.8.8")
    assert result.success is False
    assert "token" in (result.error or "").lower()


# ── Error paths ────────────────────────────────────────────────────


async def test_lookup_401_token_rejected(monkeypatch):
    monkeypatch.setenv("ARGUS_IPINFO_LITE_TOKEN", "bad")
    with _no_cache(), _patch_session(_FakeResp(status=401)):
        result = await lookup("8.8.8.8")
    assert result.success is False
    assert "401" in (result.error or "")
    assert "token rejected" in (result.error or "").lower()


async def test_lookup_429_rate_limited(monkeypatch):
    monkeypatch.setenv("ARGUS_IPINFO_LITE_TOKEN", "x")
    with _no_cache(), _patch_session(_FakeResp(status=429)):
        result = await lookup("8.8.8.8")
    assert result.success is False
    assert "429" in (result.error or "")


async def test_lookup_500_returns_error(monkeypatch):
    monkeypatch.setenv("ARGUS_IPINFO_LITE_TOKEN", "x")
    with _no_cache(), _patch_session(_FakeResp(status=500)):
        result = await lookup("8.8.8.8")
    assert result.success is False
    assert "500" in (result.error or "")


async def test_lookup_unexpected_payload(monkeypatch):
    monkeypatch.setenv("ARGUS_IPINFO_LITE_TOKEN", "x")
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=[])):
        result = await lookup("8.8.8.8")
    assert result.success is False
    assert "unexpected payload" in (result.error or "").lower()


async def test_lookup_empty_input(monkeypatch):
    monkeypatch.setenv("ARGUS_IPINFO_LITE_TOKEN", "x")
    result = await lookup("")
    assert result.success is False
    assert "empty" in (result.error or "").lower()


# ── to_dict shape pin ──────────────────────────────────────────────


def test_to_dict_round_trip():
    r = IpinfoLiteResult(
        ip="1.2.3.4", success=True, asn="AS1", as_name="N",
        country_code="US", country="United States",
    )
    d = r.to_dict()
    assert set(d.keys()) == {
        "ip", "success", "asn", "as_name", "as_domain",
        "country_code", "country", "continent_code", "continent",
        "error", "cached",
    }
