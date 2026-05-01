"""SIEM push connectors (P2 #2.7) — unit + HTTP-route tests.

Each connector is exercised against a stubbed aiohttp surface so we
verify the request shape (URL · headers · body NDJSON / ECS / bulk
format) without leaving network egress in the test suite.
"""

from __future__ import annotations

import contextlib
import json
from unittest.mock import patch

import pytest

from src.integrations.siem import (
    ElasticConnector,
    QRadarConnector,
    SentinelConnector,
    SplunkHecConnector,
    list_available,
)
from src.integrations.siem.base import (
    PushResult,
    _alert_to_event,
    _ioc_to_event,
)
from src.integrations.siem import sentinel as sentinel_mod

pytestmark = pytest.mark.asyncio


# ── Aiohttp double ───────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = (
            text_body
            if text_body is not None
            else (json.dumps(json_body) if json_body is not None else "")
        )
        # Capture inputs so tests can assert on them.
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
    """Records the outbound request and returns a canned response."""

    def __init__(self, response: _FakeResp):
        self._response = response

    def get(self, url, **kwargs):
        return self._call(url, kwargs.get("data"), kwargs.get("headers"))

    def post(self, url, **kwargs):
        return self._call(url, kwargs.get("data"), kwargs.get("headers"))

    def _call(self, url, data, headers):
        self._response.request_url = url
        self._response.request_body = data if isinstance(data, str) else (
            data.decode() if isinstance(data, (bytes, bytearray)) else None
        )
        self._response.request_headers = headers
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


# ── Common base ─────────────────────────────────────────────────────


class _StubAlert:
    id = "alert-1"
    organization_id = "org-1"
    title = "Phishing wave"
    summary = "Spearphishing detected"
    severity = "high"
    category = "phishing"
    status = "new"
    confidence = 0.85
    created_at = None  # let the helper handle None gracefully


class _StubIoc:
    id = "ioc-1"
    ioc_type = "ipv4"
    value = "203.0.113.7"
    confidence = 0.9
    first_seen = None
    last_seen = None
    tags = ["c2", "muddywater"]


def test_alert_to_event_and_ioc_to_event_shapes():
    a = _alert_to_event(_StubAlert())
    assert a["title"] == "Phishing wave"
    assert a["severity"] == "high"
    assert a["source"] == "argus"

    i = _ioc_to_event(_StubIoc())
    assert i["ioc_type"] == "ipv4"
    assert i["value"] == "203.0.113.7"
    assert "c2" in i["tags"]


def test_list_available_lists_all_four_connectors():
    out = list_available()
    names = {c["name"] for c in out}
    assert names == {"splunk_hec", "sentinel", "elastic", "qradar"}
    # All unconfigured by default in CI.
    for c in out:
        assert c["configured"] is False


# ── Splunk HEC ──────────────────────────────────────────────────────


async def test_splunk_unconfigured_no_op(monkeypatch):
    for k in (
        "ARGUS_SPLUNK_HEC_URL", "ARGUS_SPLUNK_HEC_TOKEN",
    ):
        monkeypatch.delenv(k, raising=False)
    conn = SplunkHecConnector()
    r = await conn.push_alert(_StubAlert())
    assert r.success is False
    assert "not configured" in (r.note or "").lower()


async def test_splunk_push_alert_shapes_ndjson(monkeypatch):
    monkeypatch.setenv("ARGUS_SPLUNK_HEC_URL", "https://splunk.example:8088")
    monkeypatch.setenv("ARGUS_SPLUNK_HEC_TOKEN", "fake-token")
    monkeypatch.setenv("ARGUS_SPLUNK_HEC_INDEX", "argus_index")
    conn = SplunkHecConnector()

    resp = _FakeResp(status=200, json_body={"text": "Success", "code": 0})
    with _patch_session(resp):
        r = await conn.push_alert(_StubAlert())

    assert r.success is True
    assert r.pushed_count == 1
    # Verified URL + auth shape.
    assert resp.request_url.endswith("/services/collector/event")
    assert resp.request_headers["Authorization"] == "Splunk fake-token"
    # Body is one JSON line containing the wrapped event.
    line = json.loads(resp.request_body)
    assert line["sourcetype"] == "argus:alert"
    assert line["index"] == "argus_index"
    assert line["event"]["title"] == "Phishing wave"


async def test_splunk_push_handles_4xx(monkeypatch):
    monkeypatch.setenv("ARGUS_SPLUNK_HEC_URL", "https://splunk.example:8088")
    monkeypatch.setenv("ARGUS_SPLUNK_HEC_TOKEN", "fake-token")
    conn = SplunkHecConnector()
    with _patch_session(_FakeResp(status=403, text_body="forbidden")):
        r = await conn.push_alert(_StubAlert())
    assert r.success is False
    assert "HTTP 403" in (r.error or "")


async def test_splunk_health_check(monkeypatch):
    monkeypatch.setenv("ARGUS_SPLUNK_HEC_URL", "https://splunk.example:8088")
    monkeypatch.setenv("ARGUS_SPLUNK_HEC_TOKEN", "fake-token")
    conn = SplunkHecConnector()
    with _patch_session(_FakeResp(status=200, json_body={"code": 0})):
        r = await conn.health_check()
    assert r.success is True


# ── Sentinel ────────────────────────────────────────────────────────


async def test_sentinel_unconfigured_no_op(monkeypatch):
    for k in (
        "ARGUS_SENTINEL_AUTH",
        "ARGUS_SENTINEL_DCE_URL", "ARGUS_SENTINEL_DCR_IMMUTABLE_ID",
        "ARGUS_SENTINEL_STREAM_NAME",
        "ARGUS_SENTINEL_TENANT_ID", "ARGUS_SENTINEL_CLIENT_ID",
        "ARGUS_SENTINEL_CLIENT_SECRET",
        "ARGUS_SENTINEL_WEBHOOK_URL", "ARGUS_SENTINEL_SHARED_KEY",
    ):
        monkeypatch.delenv(k, raising=False)
    conn = SentinelConnector()
    r = await conn.push_alert(_StubAlert())
    assert r.success is False


async def test_sentinel_token_mode_push(monkeypatch):
    monkeypatch.setenv("ARGUS_SENTINEL_AUTH", "token")
    monkeypatch.setenv("ARGUS_SENTINEL_WEBHOOK_URL",
                        "https://hook.example/api/logs")
    monkeypatch.setenv("ARGUS_SENTINEL_SHARED_KEY", "fake-key")
    conn = SentinelConnector()

    resp = _FakeResp(status=204, text_body="")
    with _patch_session(resp):
        r = await conn.push_alert(_StubAlert())

    assert r.success is True
    assert resp.request_url == "https://hook.example/api/logs"
    assert resp.request_headers["Authorization"] == "fake-key"
    body = json.loads(resp.request_body)
    assert body[0]["title"] == "Phishing wave"


async def test_sentinel_oauth_mode_acquires_token(monkeypatch):
    monkeypatch.setenv("ARGUS_SENTINEL_AUTH", "oauth")
    monkeypatch.setenv("ARGUS_SENTINEL_DCE_URL",
                        "https://argus-dce.ingest.monitor.azure.com")
    monkeypatch.setenv("ARGUS_SENTINEL_DCR_IMMUTABLE_ID", "dcr-fake")
    monkeypatch.setenv("ARGUS_SENTINEL_STREAM_NAME", "Custom-Argus_CL")
    monkeypatch.setenv("ARGUS_SENTINEL_TENANT_ID", "tenant-1")
    monkeypatch.setenv("ARGUS_SENTINEL_CLIENT_ID", "client-1")
    monkeypatch.setenv("ARGUS_SENTINEL_CLIENT_SECRET", "secret-1")

    # Clear cached token from any prior test.
    sentinel_mod._TOKEN_CACHE.clear()

    conn = SentinelConnector()

    # Stub _get_token to skip the real AAD call.
    async def fake_token():
        return "fake-bearer"

    with patch.object(conn, "_get_token", fake_token):
        resp = _FakeResp(status=204, text_body="")
        with _patch_session(resp):
            r = await conn.push_alert(_StubAlert())

    assert r.success is True
    assert "Bearer fake-bearer" == resp.request_headers["Authorization"]
    assert "/dataCollectionRules/dcr-fake/streams/Custom-Argus_CL" \
        in resp.request_url


# ── Elastic ─────────────────────────────────────────────────────────


async def test_elastic_unconfigured_no_op(monkeypatch):
    for k in (
        "ARGUS_ELASTIC_URL", "ARGUS_ELASTIC_API_KEY",
        "ARGUS_ELASTIC_USERNAME", "ARGUS_ELASTIC_PASSWORD",
    ):
        monkeypatch.delenv(k, raising=False)
    conn = ElasticConnector()
    r = await conn.push_alert(_StubAlert())
    assert r.success is False


async def test_elastic_push_alert_ecs_shape(monkeypatch):
    monkeypatch.setenv("ARGUS_ELASTIC_URL", "https://es.example:9200")
    monkeypatch.setenv("ARGUS_ELASTIC_API_KEY", "fake-api-key")
    monkeypatch.setenv("ARGUS_ELASTIC_INDEX", "argus-events")
    conn = ElasticConnector()

    body_resp = {"errors": False, "items": [
        {"index": {"_id": "alert-1", "result": "created", "status": 201}}
    ]}
    resp = _FakeResp(status=200, json_body=body_resp)
    with _patch_session(resp):
        r = await conn.push_alert(_StubAlert())

    assert r.success is True
    assert resp.request_url.endswith("/_bulk")
    assert resp.request_headers["Authorization"] == "ApiKey fake-api-key"
    # NDJSON body: action line + source line.
    lines = [ln for ln in resp.request_body.split("\n") if ln]
    assert len(lines) == 2
    action = json.loads(lines[0])
    assert action["index"]["_index"] == "argus-events"
    assert action["index"]["_id"] == "alert-1"
    source = json.loads(lines[1])
    assert source["event"]["kind"] == "alert"


async def test_elastic_push_ioc_threat_indicator(monkeypatch):
    monkeypatch.setenv("ARGUS_ELASTIC_URL", "https://es.example:9200")
    monkeypatch.setenv("ARGUS_ELASTIC_USERNAME", "elastic")
    monkeypatch.setenv("ARGUS_ELASTIC_PASSWORD", "changeme")
    conn = ElasticConnector()

    body_resp = {"errors": False, "items": [
        {"index": {"_id": "ioc-1", "result": "created", "status": 201}},
    ]}
    resp = _FakeResp(status=200, json_body=body_resp)
    with _patch_session(resp):
        r = await conn.push_ioc(_StubIoc())

    assert r.success is True
    # Basic auth header is set.
    assert resp.request_headers["Authorization"].startswith("Basic ")
    # ECS threat shape on IOC events.
    lines = [ln for ln in resp.request_body.split("\n") if ln]
    src = json.loads(lines[1])
    assert src["threat"]["indicator"]["type"] == "ipv4"
    assert src["threat"]["indicator"]["name"] == "203.0.113.7"


async def test_elastic_partial_errors_surface(monkeypatch):
    monkeypatch.setenv("ARGUS_ELASTIC_URL", "https://es.example:9200")
    monkeypatch.setenv("ARGUS_ELASTIC_API_KEY", "fake")
    conn = ElasticConnector()
    body = {"errors": True, "items": [
        {"index": {"_id": "x", "status": 201}},
        {"index": {"_id": "y", "error": {"type": "mapper_parsing_exception"}}},
    ]}
    resp = _FakeResp(status=200, json_body=body)
    with _patch_session(resp):
        r = await conn.push_events([{"id": "x"}, {"id": "y"}])
    assert r.success is True       # at least one ok
    assert r.pushed_count == 1
    assert "1 doc(s) had ingest errors" in (r.note or "")


async def test_elastic_health_check(monkeypatch):
    monkeypatch.setenv("ARGUS_ELASTIC_URL", "https://es.example:9200")
    monkeypatch.setenv("ARGUS_ELASTIC_API_KEY", "fake")
    conn = ElasticConnector()
    with _patch_session(_FakeResp(status=200, json_body={"status": "green"})):
        r = await conn.health_check()
    assert r.success is True
    assert "green" in (r.note or "")


# ── QRadar ──────────────────────────────────────────────────────────


async def test_qradar_unconfigured_no_op(monkeypatch):
    for k in (
        "ARGUS_QRADAR_URL", "ARGUS_QRADAR_TOKEN",
    ):
        monkeypatch.delenv(k, raising=False)
    conn = QRadarConnector()
    r = await conn.push_ioc(_StubIoc())
    assert r.success is False


async def test_qradar_pushes_ioc_value_to_reference_set(monkeypatch):
    monkeypatch.setenv("ARGUS_QRADAR_URL", "https://qradar.example")
    monkeypatch.setenv("ARGUS_QRADAR_TOKEN", "sec-token")
    monkeypatch.setenv("ARGUS_QRADAR_REFERENCE_SET", "ArgusIOCs")
    conn = QRadarConnector()
    with _patch_session(_FakeResp(status=200, text_body="updated")) as _:
        resp = _FakeResp(status=200, text_body="updated")
        with _patch_session(resp):
            r = await conn.push_ioc(_StubIoc())
    assert r.success is True
    assert r.pushed_count == 1
    assert "/api/reference_data/sets/bulk_load/ArgusIOCs" in resp.request_url
    assert resp.request_headers["SEC"] == "sec-token"
    body = json.loads(resp.request_body)
    assert body == ["203.0.113.7"]


async def test_qradar_health_check_404_when_set_missing(monkeypatch):
    monkeypatch.setenv("ARGUS_QRADAR_URL", "https://qradar.example")
    monkeypatch.setenv("ARGUS_QRADAR_TOKEN", "sec-token")
    monkeypatch.setenv("ARGUS_QRADAR_REFERENCE_SET", "Nonexistent")
    conn = QRadarConnector()
    with _patch_session(_FakeResp(status=404, text_body="not found")):
        r = await conn.health_check()
    assert r.success is False
    assert "not found" in (r.error or "").lower()


# ── HTTP routes ──────────────────────────────────────────────────────


async def test_siem_connectors_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/siem/connectors",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    names = {c["name"] for c in r.json()["connectors"]}
    assert names == {"splunk_hec", "sentinel", "elastic", "qradar"}


async def test_siem_health_route_unknown_connector(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/siem/nope/health",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404


async def test_siem_push_route_unconfigured(client, analyst_user, monkeypatch):
    for k in ("ARGUS_SPLUNK_HEC_URL", "ARGUS_SPLUNK_HEC_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    r = await client.post(
        "/api/v1/intel/siem/splunk_hec/push",
        json={"events": [{"title": "x"}]},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


async def test_siem_route_requires_auth(client):
    r = await client.get("/api/v1/intel/siem/connectors")
    assert r.status_code in (401, 403)
