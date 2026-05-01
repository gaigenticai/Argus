"""Email-gateway connectors (P3 #3.3) — unit + HTTP-route tests."""

from __future__ import annotations

import contextlib
import json
from typing import Any
from unittest.mock import patch

import pytest

from src.integrations.email_gateway import (
    AbnormalConnector,
    EmailBlocklistItem,
    MimecastConnector,
    ProofpointTapConnector,
    list_available,
)

pytestmark = pytest.mark.asyncio


# ── Aiohttp double ──────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = (
            text_body if text_body is not None
            else (json.dumps(json_body) if json_body is not None else "")
        )
        self.request_url: str | None = None
        self.request_body: Any = None
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
        body = kwargs.get("data") or kwargs.get("json")
        if isinstance(body, (bytes, bytearray)):
            body = body.decode()
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


def test_list_available_lists_three_connectors():
    out = list_available()
    names = {c["name"] for c in out}
    assert names == {"proofpoint", "mimecast", "abnormal"}
    for c in out:
        assert c["configured"] is False


def test_list_available_exposes_blocklist_capability_flag():
    """Proofpoint TAP and Abnormal Security have no programmatic
    blocklist write API; the capability flag lets the dashboard grey
    out the action instead of misleading the analyst."""
    by_name = {c["name"]: c for c in list_available()}
    assert by_name["proofpoint"]["supports_blocklist_push"] is False
    assert by_name["abnormal"]["supports_blocklist_push"] is False
    assert by_name["mimecast"]["supports_blocklist_push"] is True


# ── Proofpoint TAP ──────────────────────────────────────────────────


async def test_proofpoint_unconfigured(monkeypatch):
    for k in ("ARGUS_PROOFPOINT_PRINCIPAL", "ARGUS_PROOFPOINT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    r = await ProofpointTapConnector().fetch_threats()
    assert r.success is False


async def test_proofpoint_fetch_threats(monkeypatch):
    monkeypatch.setenv("ARGUS_PROOFPOINT_PRINCIPAL", "principal")
    monkeypatch.setenv("ARGUS_PROOFPOINT_SECRET", "secret")
    body = {
        "clicksPermitted": [
            {"GUID": "g1", "url": "https://evil/login",
             "sender": "phisher@evil", "recipient": ["a@b"],
             "subject": "RE: invoice", "messageTime": "2026-05-01T08:00:00Z"},
        ],
        "messagesBlocked": [
            {"GUID": "g2", "sender": "x@y", "subject": "spam"},
        ],
    }
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await ProofpointTapConnector().fetch_threats(
            since_iso="2026-05-01T07:00:00Z",
        )
    assert r.success is True
    assert len(r.events) == 2
    classifications = {e.classification for e in r.events}
    assert classifications == {"phish", "malware"}
    # Recipient list normalised to first entry.
    phish = next(e for e in r.events if e.event_id == "g1")
    assert phish.recipient == "a@b"
    assert phish.threat_url == "https://evil/login"
    # since_iso was forwarded as sinceTime parameter.
    assert resp.request_params["sinceTime"] == "2026-05-01T07:00:00Z"


async def test_proofpoint_blocklist_returns_not_implemented(monkeypatch):
    monkeypatch.setenv("ARGUS_PROOFPOINT_PRINCIPAL", "principal")
    monkeypatch.setenv("ARGUS_PROOFPOINT_SECRET", "secret")
    r = await ProofpointTapConnector().push_blocklist(
        [EmailBlocklistItem(type="url", value="https://evil/")],
    )
    assert r.success is False
    assert "read-only" in (r.note or "").lower()


# ── Mimecast ────────────────────────────────────────────────────────


async def test_mimecast_unconfigured(monkeypatch):
    for k in ("ARGUS_MIMECAST_BASE_URL", "ARGUS_MIMECAST_APP_ID",
              "ARGUS_MIMECAST_APP_KEY", "ARGUS_MIMECAST_ACCESS_KEY",
              "ARGUS_MIMECAST_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = await MimecastConnector().fetch_threats()
    assert r.success is False


def _set_mimecast_env(monkeypatch):
    monkeypatch.setenv("ARGUS_MIMECAST_BASE_URL", "https://eu-api.mimecast.com")
    monkeypatch.setenv("ARGUS_MIMECAST_APP_ID", "app-id")
    monkeypatch.setenv("ARGUS_MIMECAST_APP_KEY", "app-key")
    monkeypatch.setenv("ARGUS_MIMECAST_ACCESS_KEY", "access")
    # Base64 of "secret-key"
    import base64
    monkeypatch.setenv("ARGUS_MIMECAST_SECRET_KEY",
                        base64.b64encode(b"secret-key").decode())


async def test_mimecast_fetch_threats(monkeypatch):
    _set_mimecast_env(monkeypatch)
    body = {"data": [{
        "clickLogs": [
            {"id": "c1", "userEmailAddress": "a@b",
             "senderAddress": "phisher@evil", "url": "https://evil",
             "subject": "Click", "scanResult": "malicious",
             "date": "2026-05-01"},
        ],
    }]}
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await MimecastConnector().fetch_threats()
    assert r.success is True
    assert len(r.events) == 1
    ev = r.events[0]
    assert ev.classification == "phish"
    assert ev.threat_url == "https://evil"
    # HMAC headers were set.
    assert resp.request_headers["x-mc-app-id"] == "app-id"
    assert resp.request_headers["Authorization"].startswith("MC access:")


async def test_mimecast_push_blocklist(monkeypatch):
    _set_mimecast_env(monkeypatch)
    resp = _FakeResp(status=200, json_body={"data": [{"id": "mc-1"}]})
    with _patch_session(resp):
        r = await MimecastConnector().push_blocklist([
            EmailBlocklistItem(type="sender", value="phisher@evil",
                                description="Argus"),
            EmailBlocklistItem(type="hash", value="abc"),  # filtered out
        ])
    # Only the sender entry was attempted.
    assert r.success is True
    assert r.pushed_count == 1


# ── Abnormal Security ──────────────────────────────────────────────


async def test_abnormal_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_ABNORMAL_TOKEN", raising=False)
    r = await AbnormalConnector().fetch_threats()
    assert r.success is False


async def test_abnormal_fetch_threats(monkeypatch):
    monkeypatch.setenv("ARGUS_ABNORMAL_TOKEN", "fake-abnormal")
    body = {"threats": [
        {"threatId": "t-1", "attackType": "phishing",
         "messages": [{"fromAddress": "phisher@evil",
                        "toAddresses": ["a@b"],
                        "subject": "Wire transfer",
                        "receivedTime": "2026-05-01T08:00:00Z"}]},
        {"threatId": "t-2", "attackType": "malware",
         "messages": []},
    ]}
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await AbnormalConnector().fetch_threats()
    assert r.success is True
    assert len(r.events) == 2
    # Maps "phishing" → "phish" via fallback to "phish".
    assert all(e.classification in {"phish", "malware", "spam", "other"}
               for e in r.events)
    assert resp.request_headers["Authorization"] == "Bearer fake-abnormal"


async def test_abnormal_blocklist_no_op(monkeypatch):
    monkeypatch.setenv("ARGUS_ABNORMAL_TOKEN", "fake-abnormal")
    r = await AbnormalConnector().push_blocklist([
        EmailBlocklistItem(type="sender", value="phisher@evil"),
    ])
    assert r.success is False
    assert "model-driven" in (r.note or "").lower()


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_email_gateway_connectors_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/email-gateway/connectors",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    names = {c["name"] for c in r.json()["connectors"]}
    assert names == {"proofpoint", "mimecast", "abnormal"}


async def test_email_gateway_unknown_connector(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/email-gateway/nope/health",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404


async def test_email_gateway_route_unconfigured(client, analyst_user, monkeypatch):
    for k in ("ARGUS_ABNORMAL_TOKEN",):
        monkeypatch.delenv(k, raising=False)
    r = await client.get(
        "/api/v1/intel/email-gateway/abnormal/threats",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_email_gateway_route_requires_auth(client):
    r = await client.get("/api/v1/intel/email-gateway/connectors")
    assert r.status_code in (401, 403)
