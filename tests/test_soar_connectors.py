"""SOAR push connectors (P3 #3.7) — unit + HTTP-route tests.

Stubs aiohttp the same way ``tests/test_siem_connectors.py`` does so
each connector's request shape (URL · headers · body) is verified
against a deterministic fake server.
"""

from __future__ import annotations

import contextlib
import json
from unittest.mock import patch

import pytest

from src.integrations.soar import (
    SplunkSoarConnector,
    TinesConnector,
    XsoarConnector,
    list_available,
)
from src.integrations.soar.base import _alert_to_incident

pytestmark = pytest.mark.asyncio


# ── Aiohttp double (same shape as the SIEM tests) ────────────────────


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
        self.request_headers: dict[str, str] | None = None
        self.request_body: str | None = None

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
        body = kwargs.get("data") or kwargs.get("json")
        if isinstance(body, (bytes, bytearray)):
            body = body.decode()
        elif isinstance(body, dict):
            body = json.dumps(body, default=str)
        self._response.request_body = body
        self._response.request_headers = kwargs.get("headers")
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


# ── Test fixtures ────────────────────────────────────────────────────


class _StubAlert:
    id = "alert-1"
    organization_id = "org-1"
    title = "Phishing wave"
    summary = "Spearphishing detected"
    severity = "high"
    category = "phishing"
    status = "new"
    confidence = 0.85
    created_at = None


def test_alert_to_incident_shape():
    inc = _alert_to_incident(_StubAlert())
    assert inc["title"] == "Phishing wave"
    assert inc["severity"] == "high"
    assert inc["source"] == "argus"


def test_list_available_lists_three_connectors():
    out = list_available()
    names = {c["name"] for c in out}
    assert names == {"xsoar", "tines", "splunk_soar"}
    for c in out:
        assert c["configured"] is False


# ── XSOAR ───────────────────────────────────────────────────────────


async def test_xsoar_unconfigured_no_op(monkeypatch):
    for k in (
        "ARGUS_XSOAR_URL", "ARGUS_XSOAR_API_KEY", "ARGUS_XSOAR_API_KEY_ID",
    ):
        monkeypatch.delenv(k, raising=False)
    conn = XsoarConnector()
    r = await conn.push_alert(_StubAlert())
    assert r.success is False
    assert "not configured" in (r.note or "").lower()


async def test_xsoar_push_alert_request_shape(monkeypatch):
    monkeypatch.setenv("ARGUS_XSOAR_URL", "https://xsoar.example")
    monkeypatch.setenv("ARGUS_XSOAR_API_KEY", "fake-key")
    monkeypatch.setenv("ARGUS_XSOAR_API_KEY_ID", "1")
    conn = XsoarConnector()

    resp = _FakeResp(status=200, json_body={"id": "INC-42"})
    with _patch_session(resp):
        r = await conn.push_alert(_StubAlert())
    assert r.success is True
    assert r.remote_ids == ["INC-42"]
    assert resp.request_url.endswith("/incident/create")
    assert resp.request_headers["Authorization"] == "fake-key"
    assert resp.request_headers["x-xdr-auth-id"] == "1"
    body = json.loads(resp.request_body)
    # XSOAR severity scale: high → 3
    assert body["severity"] == 3
    assert body["name"] == "Phishing wave"


async def test_xsoar_push_handles_4xx(monkeypatch):
    monkeypatch.setenv("ARGUS_XSOAR_URL", "https://xsoar.example")
    monkeypatch.setenv("ARGUS_XSOAR_API_KEY", "fake-key")
    monkeypatch.setenv("ARGUS_XSOAR_API_KEY_ID", "1")
    conn = XsoarConnector()
    with _patch_session(_FakeResp(status=403, text_body="forbidden")):
        r = await conn.push_alert(_StubAlert())
    # XSOAR returned an error and no remote_ids → push reports the error
    assert r.pushed_count == 0
    assert "HTTP 403" in (r.error or "")


async def test_xsoar_health_check(monkeypatch):
    monkeypatch.setenv("ARGUS_XSOAR_URL", "https://xsoar.example")
    monkeypatch.setenv("ARGUS_XSOAR_API_KEY", "fake-key")
    monkeypatch.setenv("ARGUS_XSOAR_API_KEY_ID", "1")
    conn = XsoarConnector()
    with _patch_session(_FakeResp(status=200, text_body="ok")):
        r = await conn.health_check()
    assert r.success is True


# ── Tines ───────────────────────────────────────────────────────────


async def test_tines_unconfigured_no_op(monkeypatch):
    monkeypatch.delenv("ARGUS_TINES_WEBHOOK_URL", raising=False)
    conn = TinesConnector()
    r = await conn.push_alert(_StubAlert())
    assert r.success is False


async def test_tines_push_alert(monkeypatch):
    monkeypatch.setenv("ARGUS_TINES_WEBHOOK_URL",
                        "https://hook.tines.io/webhook/abc")
    conn = TinesConnector()
    resp = _FakeResp(status=200, text_body="received")
    with _patch_session(resp):
        r = await conn.push_alert(_StubAlert())
    assert r.success is True
    assert r.pushed_count == 1
    assert resp.request_url == "https://hook.tines.io/webhook/abc"
    body = json.loads(resp.request_body)
    assert body["source"] == "argus"
    assert body["events"][0]["title"] == "Phishing wave"


async def test_tines_push_handles_4xx(monkeypatch):
    monkeypatch.setenv("ARGUS_TINES_WEBHOOK_URL",
                        "https://hook.tines.io/webhook/abc")
    conn = TinesConnector()
    with _patch_session(_FakeResp(status=400, text_body="bad request")):
        r = await conn.push_alert(_StubAlert())
    assert r.success is False


# ── Splunk SOAR ─────────────────────────────────────────────────────


async def test_splunk_soar_unconfigured_no_op(monkeypatch):
    for k in (
        "ARGUS_SPLUNK_SOAR_URL", "ARGUS_SPLUNK_SOAR_TOKEN",
    ):
        monkeypatch.delenv(k, raising=False)
    conn = SplunkSoarConnector()
    r = await conn.push_alert(_StubAlert())
    assert r.success is False


async def test_splunk_soar_push_creates_container(monkeypatch):
    monkeypatch.setenv("ARGUS_SPLUNK_SOAR_URL", "https://soar.example")
    monkeypatch.setenv("ARGUS_SPLUNK_SOAR_TOKEN", "ph-token")
    monkeypatch.setenv("ARGUS_SPLUNK_SOAR_LABEL", "argus_alerts")
    conn = SplunkSoarConnector()
    resp = _FakeResp(status=200, json_body={"id": 7777})
    with _patch_session(resp):
        r = await conn.push_alert(_StubAlert())
    assert r.success is True
    assert r.remote_ids == ["7777"]
    assert resp.request_url.endswith("/rest/container")
    assert resp.request_headers["ph-auth-token"] == "ph-token"
    body = json.loads(resp.request_body)
    assert body["label"] == "argus_alerts"
    # SOAR severity scale: high → high
    assert body["severity"] == "high"
    assert body["name"] == "Phishing wave"


async def test_splunk_soar_health_check(monkeypatch):
    monkeypatch.setenv("ARGUS_SPLUNK_SOAR_URL", "https://soar.example")
    monkeypatch.setenv("ARGUS_SPLUNK_SOAR_TOKEN", "ph-token")
    conn = SplunkSoarConnector()
    with _patch_session(_FakeResp(status=200, json_body={"version": "5.5"})):
        r = await conn.health_check()
    assert r.success is True


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_soar_connectors_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/soar/connectors",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    names = {c["name"] for c in r.json()["connectors"]}
    assert names == {"xsoar", "tines", "splunk_soar"}


async def test_soar_health_route_unknown_connector(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/soar/nope/health",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404


async def test_soar_push_route_unconfigured(client, admin_user, monkeypatch):
    # /soar/{name}/push is admin-gated (C6) — incident creation in
    # customer's SOAR.
    for k in ("ARGUS_TINES_WEBHOOK_URL",):
        monkeypatch.delenv(k, raising=False)
    r = await client.post(
        "/api/v1/intel/soar/tines/push",
        json={"events": [{"title": "x"}]},
        headers=admin_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_soar_push_rejects_analyst(client, analyst_user):
    """C6 — analyst tokens cannot push to customer SOAR."""
    r = await client.post(
        "/api/v1/intel/soar/tines/push",
        json={"events": [{"title": "x"}]},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 403


async def test_soar_route_requires_auth(client):
    r = await client.get("/api/v1/intel/soar/connectors")
    assert r.status_code in (401, 403)
