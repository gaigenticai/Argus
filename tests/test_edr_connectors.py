"""EDR push connectors (P3 #3.2) — unit + HTTP-route tests.

Stubs the aiohttp surface so each connector's request shape is
verified against a deterministic fake.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any
from unittest.mock import patch

import pytest

from src.integrations.edr import (
    CrowdStrikeConnector,
    EdrIoc,
    MicrosoftDefenderConnector,
    SentinelOneConnector,
    list_available,
)
from src.integrations.edr.crowdstrike import CrowdStrikeConnector as _CS
from src.integrations.edr.mde import MicrosoftDefenderConnector as _MDE

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
    assert names == {"crowdstrike", "sentinelone", "mde"}
    for c in out:
        assert c["configured"] is False


def test_edr_ioc_to_dict():
    ioc = EdrIoc(type="ipv4", value="1.2.3.4",
                 severity="high", action="prevent",
                 description="Argus C2")
    d = ioc.to_dict()
    assert set(d.keys()) == {"type", "value", "severity",
                              "action", "description"}


# ── CrowdStrike ─────────────────────────────────────────────────────


async def test_crowdstrike_unconfigured(monkeypatch):
    for k in ("ARGUS_FALCON_BASE_URL", "ARGUS_FALCON_CLIENT_ID",
              "ARGUS_FALCON_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    conn = CrowdStrikeConnector()
    r = await conn.push_iocs([EdrIoc(type="ipv4", value="1.2.3.4")])
    assert r.success is False


async def test_crowdstrike_push_with_stub_token(monkeypatch):
    monkeypatch.setenv("ARGUS_FALCON_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("ARGUS_FALCON_CLIENT_ID", "client")
    monkeypatch.setenv("ARGUS_FALCON_CLIENT_SECRET", "secret")
    _CS._TOKEN_CACHE.clear()
    conn = CrowdStrikeConnector()

    async def fake_token(self):
        return "fake-bearer"

    with patch.object(_CS, "_token", fake_token):
        resp = _FakeResp(status=200, json_body={
            "resources": [{"id": "ioc-1"}, {"id": "ioc-2"}],
        })
        with _patch_session(resp):
            r = await conn.push_iocs([
                EdrIoc(type="ipv4", value="1.2.3.4", severity="high"),
                EdrIoc(type="domain", value="evil.example.com"),
            ])

    assert r.success is True
    assert r.pushed_count == 2
    assert resp.request_headers["Authorization"] == "Bearer fake-bearer"
    body = json.loads(resp.request_body)
    assert len(body["indicators"]) == 2
    types = [i["type"] for i in body["indicators"]]
    assert "ipv4" in types and "domain" in types


async def test_crowdstrike_drops_unsupported_ioc_types(monkeypatch):
    monkeypatch.setenv("ARGUS_FALCON_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("ARGUS_FALCON_CLIENT_ID", "client")
    monkeypatch.setenv("ARGUS_FALCON_CLIENT_SECRET", "secret")
    _CS._TOKEN_CACHE.clear()
    conn = CrowdStrikeConnector()

    async def fake_token(self):
        return "fake-bearer"

    with patch.object(_CS, "_token", fake_token):
        # ja3 is not in Falcon's accepted IOC types.
        r = await conn.push_iocs([EdrIoc(type="ja3", value="xxxx")])

    assert r.success is False
    assert "no falcon-compatible" in (r.note or "").lower()


async def test_crowdstrike_isolate_with_stub_token(monkeypatch):
    monkeypatch.setenv("ARGUS_FALCON_BASE_URL", "https://api.crowdstrike.com")
    monkeypatch.setenv("ARGUS_FALCON_CLIENT_ID", "client")
    monkeypatch.setenv("ARGUS_FALCON_CLIENT_SECRET", "secret")
    _CS._TOKEN_CACHE.clear()
    conn = CrowdStrikeConnector()

    async def fake_token(self):
        return "fake-bearer"

    with patch.object(_CS, "_token", fake_token):
        with _patch_session(_FakeResp(status=200, json_body={})):
            r = await conn.isolate_host(host_id="host-1")
    assert r.success is True
    assert r.remote_ids == ["host-1"]


# ── SentinelOne ─────────────────────────────────────────────────────


async def test_sentinelone_unconfigured(monkeypatch):
    for k in ("ARGUS_S1_BASE_URL", "ARGUS_S1_API_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    r = await SentinelOneConnector().push_iocs(
        [EdrIoc(type="ipv4", value="1.2.3.4")],
    )
    assert r.success is False


async def test_sentinelone_push(monkeypatch):
    monkeypatch.setenv("ARGUS_S1_BASE_URL", "https://tenant.sentinelone.net")
    monkeypatch.setenv("ARGUS_S1_API_TOKEN", "fake-s1")
    monkeypatch.setenv("ARGUS_S1_ACCOUNT_ID", "acc-1")
    conn = SentinelOneConnector()
    resp = _FakeResp(status=200, json_body={
        "data": [{"id": "s1-ioc-1"}, {"id": "s1-ioc-2"}],
    })
    with _patch_session(resp):
        r = await conn.push_iocs([
            EdrIoc(type="ipv4", value="1.2.3.4"),
            EdrIoc(type="sha256", value="a" * 64),
        ])
    assert r.success is True
    assert r.pushed_count == 2
    assert resp.request_headers["Authorization"] == "ApiToken fake-s1"
    body = json.loads(resp.request_body)
    types = [i["type"] for i in body["data"]]
    assert "IPV4" in types and "SHA256" in types
    # Account scope was attached.
    assert all("acc-1" in i.get("accountIds", []) for i in body["data"])


async def test_sentinelone_isolate(monkeypatch):
    monkeypatch.setenv("ARGUS_S1_BASE_URL", "https://tenant.sentinelone.net")
    monkeypatch.setenv("ARGUS_S1_API_TOKEN", "fake-s1")
    conn = SentinelOneConnector()
    with _patch_session(_FakeResp(status=200, json_body={})):
        r = await conn.isolate_host(host_id="agent-42")
    assert r.success is True
    assert r.remote_ids == ["agent-42"]


# ── Microsoft Defender for Endpoint ─────────────────────────────────


async def test_mde_unconfigured(monkeypatch):
    for k in ("ARGUS_MDE_TENANT_ID", "ARGUS_MDE_CLIENT_ID",
              "ARGUS_MDE_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    r = await MicrosoftDefenderConnector().push_iocs(
        [EdrIoc(type="ipv4", value="1.2.3.4")],
    )
    assert r.success is False


async def test_mde_push_with_stub_token(monkeypatch):
    monkeypatch.setenv("ARGUS_MDE_TENANT_ID", "tenant-x")
    monkeypatch.setenv("ARGUS_MDE_CLIENT_ID", "client-x")
    monkeypatch.setenv("ARGUS_MDE_CLIENT_SECRET", "secret-x")
    _MDE._TOKEN_CACHE.clear()
    conn = MicrosoftDefenderConnector()

    async def fake_token(self):
        return "fake-bearer"

    with patch.object(_MDE, "_token", fake_token):
        # MDE endpoint takes one IOC per POST; we send two.
        resp = _FakeResp(status=200, json_body={"id": "ind-1"})
        with _patch_session(resp):
            r = await conn.push_iocs([
                EdrIoc(type="ipv4", value="1.2.3.4",
                       severity="high", action="prevent"),
                EdrIoc(type="domain", value="evil.example.com"),
            ])

    # Each POST goes through the same session; we get 2 ids back —
    # but since we reuse the same fake response, ids will dedup to
    # the single id reported. What matters is success + last request
    # body shape.
    assert r.success is True
    assert resp.request_url.endswith("/api/indicators")
    body = json.loads(resp.request_body)
    assert body["indicatorType"] in ("IpAddress", "DomainName")
    assert body["action"] in ("Audit", "Block")


async def test_mde_isolate(monkeypatch):
    monkeypatch.setenv("ARGUS_MDE_TENANT_ID", "tenant-x")
    monkeypatch.setenv("ARGUS_MDE_CLIENT_ID", "client-x")
    monkeypatch.setenv("ARGUS_MDE_CLIENT_SECRET", "secret-x")
    _MDE._TOKEN_CACHE.clear()
    conn = MicrosoftDefenderConnector()

    async def fake_token(self):
        return "fake-bearer"

    with patch.object(_MDE, "_token", fake_token):
        resp = _FakeResp(status=200, json_body={})
        with _patch_session(resp):
            r = await conn.isolate_host(host_id="machine-7")
    assert r.success is True
    body = json.loads(resp.request_body)
    assert body["IsolationType"] == "Full"
    assert resp.request_url.endswith("/api/machines/machine-7/isolate")


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_edr_connectors_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/edr/connectors",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    names = {c["name"] for c in r.json()["connectors"]}
    assert names == {"crowdstrike", "sentinelone", "mde"}


async def test_edr_unknown_connector(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/edr/nope/iocs/push",
        json={"iocs": [{"type": "ipv4", "value": "1.2.3.4"}]},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404


async def test_edr_push_route_unconfigured(client, analyst_user, monkeypatch):
    for k in ("ARGUS_FALCON_BASE_URL", "ARGUS_FALCON_CLIENT_ID",
              "ARGUS_FALCON_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    _CS._TOKEN_CACHE.clear()
    r = await client.post(
        "/api/v1/intel/edr/crowdstrike/iocs/push",
        json={"iocs": [{"type": "ipv4", "value": "1.2.3.4"}]},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_edr_route_requires_auth(client):
    r = await client.get("/api/v1/intel/edr/connectors")
    assert r.status_code in (401, 403)
