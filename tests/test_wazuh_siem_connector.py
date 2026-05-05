"""Wazuh Indexer SIEM connector — fixture tests.

Pins the NDJSON _bulk index payload shape, basic-auth construction,
ECS-event projection, and the errors=true partial-failure handling.
"""

from __future__ import annotations

import contextlib
import json
from base64 import b64decode
from unittest.mock import patch

import pytest

from src.integrations.siem.wazuh_siem import WazuhSiemConnector

pytestmark = pytest.mark.asyncio


# ── Test doubles ────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, text_body=""):
        self.status = status
        self._text = text_body

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response: _FakeResp,
                 captured_headers=None, captured_body=None):
        self._response = response
        self._captured_headers = captured_headers
        self._captured_body = captured_body

    def get(self, url, *args, headers=None, **kwargs):
        if headers and self._captured_headers is not None:
            self._captured_headers.update(headers)
        return self._response

    def post(self, url, *args, headers=None, data=None, **kwargs):
        if headers and self._captured_headers is not None:
            self._captured_headers.update(headers)
        if data is not None and self._captured_body is not None:
            self._captured_body.append(data)
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(response: _FakeResp,
                   captured_headers=None, captured_body=None):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(response, captured_headers, captured_body)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


def _connector(monkeypatch, *, password="wazuh-pw", index="argus-test"):
    monkeypatch.setenv("ARGUS_WAZUH_INDEXER_URL", "http://wazuh.test:9200")
    monkeypatch.setenv("ARGUS_WAZUH_INDEXER_USERNAME", "admin")
    monkeypatch.setenv("ARGUS_WAZUH_INDEXER_PASSWORD", password)
    monkeypatch.setenv("ARGUS_WAZUH_INDEXER_INDEX", index)
    return WazuhSiemConnector()


# ── is_configured ───────────────────────────────────────────────────


def test_is_configured_requires_url_and_password(monkeypatch):
    monkeypatch.delenv("ARGUS_WAZUH_INDEXER_URL", raising=False)
    monkeypatch.delenv("ARGUS_WAZUH_INDEXER_PASSWORD", raising=False)
    assert WazuhSiemConnector().is_configured() is False
    monkeypatch.setenv("ARGUS_WAZUH_INDEXER_URL", "http://x")
    assert WazuhSiemConnector().is_configured() is False
    monkeypatch.setenv("ARGUS_WAZUH_INDEXER_PASSWORD", "p")
    assert WazuhSiemConnector().is_configured() is True


# ── Auth header pinning ─────────────────────────────────────────────


async def test_push_events_sends_basic_auth(monkeypatch):
    conn = _connector(monkeypatch, password="my-wazuh-pw")
    captured: dict[str, str] = {}
    body_log: list[str] = []
    with _patch_session(_FakeResp(status=200, text_body='{"errors": false, "items": []}'),
                       captured_headers=captured, captured_body=body_log):
        await conn.push_events([{"id": "1", "title": "t"}])
    assert "Authorization" in captured
    auth = captured["Authorization"]
    assert auth.startswith("Basic ")
    decoded = b64decode(auth[len("Basic "):]).decode()
    assert decoded == "admin:my-wazuh-pw"
    assert captured["Content-Type"] == "application/x-www-form-urlencoded" or \
           captured["Content-Type"] == "application/x-ndjson"


# ── NDJSON _bulk shape ─────────────────────────────────────────────


async def test_push_events_composes_valid_ndjson(monkeypatch):
    """NDJSON _bulk format: alternating action + doc lines, trailing
    newline. Pin so a refactor doesn't accidentally break it."""
    conn = _connector(monkeypatch, index="argus-test-idx")
    body_log: list[str] = []
    with _patch_session(_FakeResp(status=200, text_body='{"errors": false}'),
                       captured_body=body_log):
        await conn.push_events([
            {"id": "alert-1", "title": "Phishing detected", "severity": "high"},
            {"id": "ioc-1", "value": "1.2.3.4"},
        ])

    body = body_log[0]
    lines = [l for l in body.split("\n") if l]
    # 2 events × 2 lines each = 4 lines
    assert len(lines) == 4
    # Action lines
    a1 = json.loads(lines[0])
    assert a1 == {"index": {"_index": "argus-test-idx"}}
    # Doc lines have ECS shape
    d1 = json.loads(lines[1])
    assert "@timestamp" in d1
    assert d1["argus"]["title"] == "Phishing detected"
    assert d1["event"]["kind"] == "alert"  # has 'title' → alert
    assert d1["event"]["module"] == "argus"

    d2 = json.loads(lines[3])
    assert d2["event"]["kind"] == "indicator"  # no 'title' → indicator


async def test_push_events_uses_alert_created_at_when_present(monkeypatch):
    conn = _connector(monkeypatch)
    body_log: list[str] = []
    with _patch_session(_FakeResp(status=200, text_body='{"errors": false}'),
                       captured_body=body_log):
        await conn.push_events([{
            "id": "1", "title": "x", "created_at": "2026-04-30T12:34:56+00:00",
        }])
    body = body_log[0]
    doc_line = body.split("\n")[1]
    assert "2026-04-30T12:34:56" in doc_line


async def test_push_events_falls_back_to_now_when_no_created_at(monkeypatch):
    conn = _connector(monkeypatch)
    body_log: list[str] = []
    with _patch_session(_FakeResp(status=200, text_body='{"errors": false}'),
                       captured_body=body_log):
        await conn.push_events([{"id": "1", "title": "x"}])
    body = body_log[0]
    doc_line = body.split("\n")[1]
    doc = json.loads(doc_line)
    # @timestamp must be present and ISO-shaped
    assert doc["@timestamp"]
    assert "T" in doc["@timestamp"]


# ── Errors=true partial-failure handling ──────────────────────────


async def test_push_events_partial_failure_surfaces_count(monkeypatch):
    """When _bulk responds errors=true, the connector should report
    how many docs failed — silent partial loss is the worst kind of
    SIEM bug."""
    conn = _connector(monkeypatch)
    bulk_response = json.dumps({
        "errors": True,
        "items": [
            {"index": {"_id": "1", "status": 200}},
            {"index": {"_id": "2", "status": 400, "error": {"type": "mapper_parsing_exception"}}},
        ],
    })
    with _patch_session(_FakeResp(status=200, text_body=bulk_response)):
        result = await conn.push_events([
            {"id": "1", "title": "t1"},
            {"id": "2", "title": "t2"},
        ])
    assert result.success is False
    assert "1 doc failures" in (result.error or "")


async def test_push_events_clean_response(monkeypatch):
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=200, text_body='{"errors": false, "items": []}')):
        result = await conn.push_events([{"id": "1", "title": "t"}])
    assert result.success is True
    assert result.pushed_count == 1


# ── Error paths ────────────────────────────────────────────────────


async def test_push_events_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_WAZUH_INDEXER_URL", raising=False)
    monkeypatch.delenv("ARGUS_WAZUH_INDEXER_PASSWORD", raising=False)
    conn = WazuhSiemConnector()
    result = await conn.push_events([{"id": "1"}])
    assert result.success is False
    assert "not configured" in (result.note or "").lower()


async def test_push_events_empty_list(monkeypatch):
    conn = _connector(monkeypatch)
    result = await conn.push_events([])
    assert result.success is True
    assert result.pushed_count == 0


async def test_push_events_500_returns_error(monkeypatch):
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=500, text_body="indexer down")):
        result = await conn.push_events([{"id": "1", "title": "t"}])
    assert result.success is False
    assert "500" in (result.error or "")
