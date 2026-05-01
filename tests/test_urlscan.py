"""urlscan.io enrichment — unit + HTTP-route tests."""

from __future__ import annotations

import contextlib
import json
from unittest.mock import patch

import pytest

from src.enrichment.urlscan import (
    is_configured,
    search_recent,
    submit_scan,
    health_check,
)

pytestmark = pytest.mark.asyncio


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._text = (
            text_body if text_body is not None
            else (json.dumps(json_body) if json_body is not None else "")
        )
        self.request_url: str | None = None
        self.request_params: dict | None = None
        self.request_body: str | None = None
        self.request_headers: dict | None = None

    async def text(self):
        return self._text

    async def json(self):
        return json.loads(self._text) if self._text else None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response):
        self._r = response

    def get(self, url, **kw):
        return self._call(url, kw)

    def post(self, url, **kw):
        return self._call(url, kw)

    def _call(self, url, kw):
        self._r.request_url = url
        self._r.request_params = kw.get("params")
        body = kw.get("json") or kw.get("data")
        self._r.request_body = (
            json.dumps(body) if isinstance(body, dict) else body
        )
        self._r.request_headers = kw.get("headers")
        return self._r

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(resp):
    import aiohttp
    with patch.object(aiohttp, "ClientSession", lambda *a, **k: _FakeSession(resp)):
        yield


# ── is_configured ──────────────────────────────────────────────────


def test_is_configured_requires_key(monkeypatch):
    monkeypatch.delenv("ARGUS_URLSCAN_API_KEY", raising=False)
    assert is_configured() is False
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    assert is_configured() is True


# ── search_recent ──────────────────────────────────────────────────


async def test_search_recent_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_URLSCAN_API_KEY", raising=False)
    r = await search_recent("argusdemobank.com")
    assert r.success is False
    assert "not configured" in (r.note or "")


async def test_search_recent_uses_domain_query_for_bare_domain(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    body = {"total": 0, "results": []}
    resp = _FakeResp(status=200, text_body=json.dumps(body))
    with _patch_session(resp):
        r = await search_recent("argusdemobank.com")
    assert r.success is True
    assert resp.request_params["q"] == "page.domain:argusdemobank.com"
    assert resp.request_headers["API-Key"] == "k"


async def test_search_recent_uses_url_query_for_url(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    resp = _FakeResp(status=200, text_body='{"total":0,"results":[]}')
    with _patch_session(resp):
        await search_recent("https://evil.example/login")
    q = resp.request_params["q"]
    assert q.startswith("page.url:")
    assert "evil.example/login" in q


async def test_search_recent_parses_results(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    body = {
        "total": 2,
        "results": [
            {
                "_id": "abc-1",
                "page": {"domain": "evil.example",
                          "url": "https://evil.example/",
                          "asn": "AS12345", "country": "RU"},
                "task": {"reportURL": "https://urlscan.io/result/abc-1/",
                          "url": "https://evil.example/",
                          "time": "2026-04-30T08:00:00Z"},
                "verdicts": {"overall": {"score": 95}},
            },
        ],
    }
    resp = _FakeResp(status=200, text_body=json.dumps(body))
    with _patch_session(resp):
        r = await search_recent("evil.example")
    assert r.success is True
    assert r.data["total"] == 2
    assert len(r.data["results"]) == 1
    first = r.data["results"][0]
    assert first["scan_id"] == "abc-1"
    assert first["country"] == "RU"
    assert first["verdict_score"] == 95


async def test_search_recent_handles_401(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "wrong")
    resp = _FakeResp(status=401, text_body="unauthorized")
    with _patch_session(resp):
        r = await search_recent("evil.example")
    assert r.success is False
    assert "401" in (r.error or "")


# ── submit_scan ────────────────────────────────────────────────────


async def test_submit_scan_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_URLSCAN_API_KEY", raising=False)
    r = await submit_scan("https://evil.example")
    assert r.success is False
    assert "not configured" in (r.note or "")


async def test_submit_scan_defaults_to_unlisted(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    body = {
        "uuid": "abc-uuid", "result": "https://urlscan.io/result/abc-uuid/",
        "api": "https://urlscan.io/api/v1/result/abc-uuid/",
        "visibility": "unlisted",
    }
    resp = _FakeResp(status=200, text_body=json.dumps(body))
    with _patch_session(resp):
        r = await submit_scan("https://evil.example")
    assert r.success is True
    assert r.data["uuid"] == "abc-uuid"
    sent = json.loads(resp.request_body or "{}")
    assert sent["visibility"] == "unlisted"
    assert sent["url"] == "https://evil.example"


async def test_submit_scan_rejects_bad_visibility(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    r = await submit_scan("https://evil.example", visibility="hacker-only")
    assert r.success is False
    assert "visibility" in (r.error or "")


async def test_submit_scan_429(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    resp = _FakeResp(status=429, text_body="too many requests")
    with _patch_session(resp):
        r = await submit_scan("https://evil.example")
    assert r.success is False
    assert "429" in (r.error or "") or "quota" in (r.error or "").lower()


# ── health_check ───────────────────────────────────────────────────


async def test_health_check_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_URLSCAN_API_KEY", raising=False)
    r = await health_check()
    assert r.success is False


async def test_health_check_ok(monkeypatch):
    monkeypatch.setenv("ARGUS_URLSCAN_API_KEY", "k")
    resp = _FakeResp(status=200, text_body='{"limits":{}}')
    with _patch_session(resp):
        r = await health_check()
    assert r.success is True
    assert resp.request_url.endswith("/quotas/")


# ── HTTP routes ────────────────────────────────────────────────────


async def test_route_availability(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_URLSCAN_API_KEY", raising=False)
    r = await client.get(
        "/api/v1/intel/urlscan/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["configured"] is False


async def test_route_search_unconfigured(client, analyst_user, monkeypatch):
    monkeypatch.delenv("ARGUS_URLSCAN_API_KEY", raising=False)
    r = await client.get(
        "/api/v1/intel/urlscan/search?target=evil.example",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_route_submit_requires_admin(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/urlscan/submit",
        json={"url": "https://evil.example"},
        headers=analyst_user["headers"],
    )
    assert r.status_code in (401, 403)


async def test_route_requires_auth(client):
    r = await client.get("/api/v1/intel/urlscan/availability")
    assert r.status_code in (401, 403)
