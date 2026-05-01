"""Breach-credential providers (P3 #3.9) — unit + HTTP-route tests.

Each provider is exercised against a stubbed aiohttp surface; the
unified-search fan-out is verified end-to-end.
"""

from __future__ import annotations

import contextlib
import json
from unittest.mock import patch

import pytest

from src.integrations.breach import (
    DehashedProvider,
    HibpProvider,
    IntelxProvider,
    list_available,
    search_email_unified,
)
from src.integrations.breach.base import BreachHit, ProviderResult

pytestmark = pytest.mark.asyncio


# ── Aiohttp double ──────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = (
            text_body
            if text_body is not None
            else (json.dumps(json_body) if json_body is not None else "")
        )
        self.request_url: str | None = None
        self.request_body: str | None = None
        self.request_headers: dict[str, str] | None = None
        self.request_params: dict[str, str] | None = None

    async def json(self):
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

    def get(self, url, **kwargs):
        return self._call(url, kwargs)

    def post(self, url, **kwargs):
        return self._call(url, kwargs)

    def _call(self, url, kwargs):
        self._response.request_url = url
        body = kwargs.get("json") or kwargs.get("data")
        if isinstance(body, (bytes, bytearray)):
            body = body.decode()
        elif isinstance(body, dict):
            body = json.dumps(body, default=str)
        self._response.request_body = body
        self._response.request_headers = kwargs.get("headers")
        self._response.request_params = kwargs.get("params")
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


# ── Registry ─────────────────────────────────────────────────────────


def test_list_available_lists_three_providers():
    out = list_available()
    names = {p["name"] for p in out}
    assert names == {"hibp", "intelx", "dehashed"}
    for p in out:
        assert p["configured"] is False  # CI venv has no keys


def test_breach_hit_to_dict_redacts_cleartext():
    h = BreachHit(
        provider="dehashed", breach_name="x", email="a@b",
        cleartext_password="hunter2",
    )
    d = h.to_dict()
    assert "cleartext_password" not in d
    assert d["cleartext_password_present"] is True


# ── HIBP ────────────────────────────────────────────────────────────


async def test_hibp_unconfigured_no_op(monkeypatch):
    monkeypatch.delenv("ARGUS_HIBP_API_KEY", raising=False)
    p = HibpProvider()
    r = await p.search_email("user@example.com")
    assert r.success is False
    assert r.hits == []


async def test_hibp_email_match(monkeypatch):
    monkeypatch.setenv("ARGUS_HIBP_API_KEY", "fake-hibp")
    resp = _FakeResp(status=200, json_body=[
        {"Name": "Adobe", "BreachDate": "2013-10-04",
         "Description": "Adobe breach", "DataClasses": ["Email", "Password"]},
        {"Name": "LinkedIn", "BreachDate": "2012-05-05",
         "Description": "LinkedIn 2012", "DataClasses": ["Email", "Password"]},
    ])
    with _patch_session(resp):
        r = await HibpProvider().search_email("user@example.com")
    assert r.success is True
    assert len(r.hits) == 2
    assert {h.breach_name for h in r.hits} == {"Adobe", "LinkedIn"}
    assert r.hits[0].email == "user@example.com"
    assert resp.request_headers["hibp-api-key"] == "fake-hibp"


async def test_hibp_email_404_means_clean(monkeypatch):
    monkeypatch.setenv("ARGUS_HIBP_API_KEY", "fake-hibp")
    with _patch_session(_FakeResp(status=404, text_body="")):
        r = await HibpProvider().search_email("clean@example.com")
    assert r.success is True
    assert r.hits == []
    assert "no breach record" in (r.note or "").lower()


async def test_hibp_password_lookup_match(monkeypatch):
    monkeypatch.setenv("ARGUS_HIBP_API_KEY", "fake-hibp")
    sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"  # "password"
    suffix = sha1[5:]
    body = f"{suffix}:300\nFFFF:0\n"
    with _patch_session(_FakeResp(status=200, text_body=body)):
        r = await HibpProvider().search_password_hash(sha1)
    assert r.success is True
    assert len(r.hits) == 1
    assert "300 occurrences" in r.hits[0].breach_name


async def test_hibp_password_lookup_no_match(monkeypatch):
    monkeypatch.setenv("ARGUS_HIBP_API_KEY", "fake-hibp")
    sha1 = "A" * 40
    body = "FFFF:0\n0001:1\n"  # neither matches the suffix
    with _patch_session(_FakeResp(status=200, text_body=body)):
        r = await HibpProvider().search_password_hash(sha1)
    assert r.success is True
    assert r.hits == []


async def test_hibp_password_invalid_hash(monkeypatch):
    monkeypatch.setenv("ARGUS_HIBP_API_KEY", "fake-hibp")
    r = await HibpProvider().search_password_hash("short")
    assert r.success is False
    assert "40-char" in (r.error or "")


# ── IntelX ──────────────────────────────────────────────────────────


async def test_intelx_unconfigured_no_op(monkeypatch):
    monkeypatch.delenv("ARGUS_INTELX_API_KEY", raising=False)
    p = IntelxProvider()
    r = await p.search_email("a@b")
    assert r.success is False


async def test_intelx_search_returns_hits(monkeypatch):
    monkeypatch.setenv("ARGUS_INTELX_API_KEY", "fake-intelx")
    # IntelX flow: POST /intelligent/search returns id, then poll
    # /intelligent/search/result. We stub a single response that
    # serves both calls.
    payload = {
        # Submit response shape
        "id": "search-1", "softselectorwarning": False, "status": 0,
        # Result poll response shape (same JSON satisfies our parser)
        "records": [
            {"name": "lookbook2024", "bucket": "leaks",
             "type": "credential", "date": "2024-08-01"},
            {"name": "stealer-dump-march", "bucket": "leaks",
             "type": "stealer", "date": "2024-03-12"},
        ],
        "status_final": 1,
    }
    with _patch_session(_FakeResp(status=200, json_body=payload)):
        r = await IntelxProvider().search_email("user@example.com")
    assert r.success is True
    assert len(r.hits) >= 1
    assert all(h.email == "user@example.com" for h in r.hits)


async def test_intelx_401_returns_error(monkeypatch):
    monkeypatch.setenv("ARGUS_INTELX_API_KEY", "fake-intelx")
    with _patch_session(_FakeResp(status=401, text_body="unauth")):
        r = await IntelxProvider().search_email("user@example.com")
    assert r.success is False
    assert "ARGUS_INTELX_API_KEY" in (r.error or "")


# ── Dehashed ────────────────────────────────────────────────────────


async def test_dehashed_unconfigured_no_op(monkeypatch):
    monkeypatch.delenv("ARGUS_DEHASHED_USERNAME", raising=False)
    monkeypatch.delenv("ARGUS_DEHASHED_API_KEY", raising=False)
    r = await DehashedProvider().search_email("a@b")
    assert r.success is False


async def test_dehashed_email_search(monkeypatch):
    monkeypatch.setenv("ARGUS_DEHASHED_USERNAME", "argus@example.com")
    monkeypatch.setenv("ARGUS_DEHASHED_API_KEY", "fake-dehashed")
    payload = {
        "entries": [
            {"database_name": "Collection1", "email": "user@example.com",
             "username": "user", "hashed_password": "$2a$abc",
             "password": "hunter2"},
        ],
    }
    resp = _FakeResp(status=200, json_body=payload)
    with _patch_session(resp):
        r = await DehashedProvider().search_email("user@example.com")
    assert r.success is True
    assert len(r.hits) == 1
    h = r.hits[0]
    assert h.cleartext_password == "hunter2"  # internal only
    assert h.password_hash == "$2a$abc"
    assert "password" in h.data_classes


# ── Unified search ──────────────────────────────────────────────────


async def test_unified_search_fan_out_unconfigured(monkeypatch):
    for k in (
        "ARGUS_HIBP_API_KEY", "ARGUS_INTELX_API_KEY",
        "ARGUS_DEHASHED_USERNAME", "ARGUS_DEHASHED_API_KEY",
    ):
        monkeypatch.delenv(k, raising=False)
    results = await search_email_unified("a@b")
    assert {r.provider for r in results} == {"hibp", "intelx", "dehashed"}
    assert all(r.success is False for r in results)


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_breach_providers_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/breach/providers",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    names = {p["name"] for p in r.json()["providers"]}
    assert names == {"hibp", "intelx", "dehashed"}


async def test_breach_search_email_unconfigured(client, analyst_user, monkeypatch):
    for k in (
        "ARGUS_HIBP_API_KEY", "ARGUS_INTELX_API_KEY",
        "ARGUS_DEHASHED_USERNAME", "ARGUS_DEHASHED_API_KEY",
    ):
        monkeypatch.delenv(k, raising=False)
    r = await client.post(
        "/api/v1/intel/breach/search/email",
        json={"email": "user@example.com"},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["results"]) == 3


async def test_breach_search_password_invalid(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/breach/search/password",
        json={"sha1_hash": "short"},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "40-char" in (body["error"] or "")


async def test_breach_route_requires_auth(client):
    r = await client.get("/api/v1/intel/breach/providers")
    assert r.status_code in (401, 403)
