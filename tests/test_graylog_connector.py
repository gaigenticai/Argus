"""Graylog GELF push connector — fixture tests.

Pins the GELF v1.1 transformer (_to_gelf), severity → syslog level
mapping, custom-field projection (_argus_*), and the per-event POST
loop semantics.
"""

from __future__ import annotations

import contextlib
import json
from base64 import b64decode
from unittest.mock import patch

import pytest

from src.integrations.siem.graylog import (
    GraylogConnector,
    _SEV_TO_GELF_LEVEL,
)

pytestmark = pytest.mark.asyncio


# ── Test doubles ────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=202, text_body=""):
        self.status = status
        self._text = text_body

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response_or_callable, captured_headers=None,
                 captured_bodies=None):
        self._resp = response_or_callable
        self._captured_headers = captured_headers
        self._captured_bodies = captured_bodies

    def post(self, url, *args, headers=None, data=None, **kwargs):
        if headers and self._captured_headers is not None:
            self._captured_headers.update(headers)
        if data is not None and self._captured_bodies is not None:
            self._captured_bodies.append(data)
        if callable(self._resp):
            return self._resp()
        return self._resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(response, captured_headers=None, captured_bodies=None):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(response, captured_headers, captured_bodies)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


def _connector(monkeypatch, *, basic_user="", basic_password="", host="argus-test"):
    monkeypatch.setenv("ARGUS_GRAYLOG_GELF_URL", "https://graylog.test:12201/gelf")
    monkeypatch.setenv("ARGUS_GRAYLOG_HOST_FIELD", host)
    if basic_user:
        monkeypatch.setenv("ARGUS_GRAYLOG_BASIC_USER", basic_user)
    if basic_password:
        monkeypatch.setenv("ARGUS_GRAYLOG_BASIC_PASSWORD", basic_password)
    return GraylogConnector()


# ── _to_gelf transformer (the highest-risk surface) ────────────────


def test_to_gelf_required_fields_present(monkeypatch):
    conn = _connector(monkeypatch)
    ev = {"id": "alert-1", "title": "Phishing", "severity": "critical"}
    g = conn._to_gelf(ev)
    # GELF v1.1 spec required keys
    assert g["version"] == "1.1"
    assert g["host"] == "argus-test"
    assert g["short_message"] == "Phishing"
    assert "timestamp" in g
    assert g["level"] == 2  # critical → syslog 'critical'


def test_to_gelf_severity_to_syslog_level_mapping():
    """Pin the mapping table — silent drift here causes alert
    severity to display wrong in Graylog dashboards."""
    assert _SEV_TO_GELF_LEVEL == {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
    }


def test_to_gelf_custom_fields_use_argus_prefix(monkeypatch):
    """All non-standard keys must be ``_`` prefixed per GELF spec.
    We use ``_argus_<key>`` so they're filterable + non-colliding."""
    conn = _connector(monkeypatch)
    ev = {
        "id": "x", "title": "t", "severity": "high",
        "category": "phishing", "confidence": 0.85,
    }
    g = conn._to_gelf(ev)
    assert g["_argus_id"] == "x"
    assert g["_argus_category"] == "phishing"
    assert g["_argus_confidence"] == 0.85
    assert g["_argus_severity"] == "high"


def test_to_gelf_lists_and_dicts_are_jsonified(monkeypatch):
    """Graylog's GELF schema accepts only scalars for custom fields;
    lists/dicts must be json-stringified, not raw-passed."""
    conn = _connector(monkeypatch)
    ev = {
        "id": "x", "title": "t", "severity": "high",
        "matched_entities": {"src_ip": "1.2.3.4", "ports": [80, 443]},
        "tags": ["malware", "stealer"],
    }
    g = conn._to_gelf(ev)
    # Both should be strings (json-encoded), not list/dict
    assert isinstance(g["_argus_matched_entities"], str)
    assert isinstance(g["_argus_tags"], str)
    # And they must round-trip
    assert json.loads(g["_argus_matched_entities"])["src_ip"] == "1.2.3.4"
    assert json.loads(g["_argus_tags"]) == ["malware", "stealer"]


def test_to_gelf_summary_truncated_to_8000(monkeypatch):
    conn = _connector(monkeypatch)
    long_summary = "x" * 10000
    ev = {"id": "x", "title": "t", "summary": long_summary, "severity": "low"}
    g = conn._to_gelf(ev)
    assert len(g["full_message"]) == 8000


def test_to_gelf_short_message_truncated_to_240(monkeypatch):
    conn = _connector(monkeypatch)
    long_title = "x" * 500
    ev = {"id": "x", "title": long_title, "severity": "low"}
    g = conn._to_gelf(ev)
    assert len(g["short_message"]) == 240


def test_to_gelf_falls_back_to_value_when_no_title(monkeypatch):
    """For IOC events (no 'title' field) use 'value' as short_message."""
    conn = _connector(monkeypatch)
    ev = {"id": "ioc-1", "value": "1.2.3.4", "severity": "high"}
    g = conn._to_gelf(ev)
    assert g["short_message"] == "1.2.3.4"


def test_to_gelf_strips_dashes_from_keys(monkeypatch):
    """GELF custom field names must match ``[\\w.-]+`` — we replace
    dashes with underscores defensively."""
    conn = _connector(monkeypatch)
    ev = {"id": "x", "title": "t", "severity": "high", "x-custom-field": "v"}
    g = conn._to_gelf(ev)
    assert "_argus_x_custom_field" in g
    assert "_argus_x-custom-field" not in g


def test_to_gelf_drops_none_values(monkeypatch):
    """None values would clutter Graylog with empty fields. Drop them."""
    conn = _connector(monkeypatch)
    ev = {"id": "x", "title": "t", "severity": "high", "optional_thing": None}
    g = conn._to_gelf(ev)
    assert "_argus_optional_thing" not in g


def test_to_gelf_unknown_severity_defaults_to_info_level(monkeypatch):
    conn = _connector(monkeypatch)
    ev = {"id": "x", "title": "t", "severity": "weird-value"}
    g = conn._to_gelf(ev)
    # Falls back to syslog 6 (info)
    assert g["level"] == 6


def test_to_gelf_host_override_via_env(monkeypatch):
    conn = _connector(monkeypatch, host="argus-prod-eu1")
    g = conn._to_gelf({"id": "x", "title": "t", "severity": "low"})
    assert g["host"] == "argus-prod-eu1"


# ── push_events POST loop ──────────────────────────────────────────


async def test_push_events_one_post_per_event(monkeypatch):
    """Graylog HTTP GELF is one event per POST — verify the loop sends
    N requests for N events."""
    conn = _connector(monkeypatch)
    bodies: list[str] = []
    with _patch_session(_FakeResp(status=202), captured_bodies=bodies):
        result = await conn.push_events([
            {"id": "1", "title": "t1", "severity": "high"},
            {"id": "2", "title": "t2", "severity": "low"},
            {"id": "3", "title": "t3", "severity": "critical"},
        ])
    assert result.success is True
    assert result.pushed_count == 3
    assert len(bodies) == 3


async def test_push_events_basic_auth_header(monkeypatch):
    conn = _connector(monkeypatch, basic_user="gluser", basic_password="glpass")
    captured: dict[str, str] = {}
    with _patch_session(_FakeResp(status=202), captured_headers=captured):
        await conn.push_events([{"id": "1", "title": "t", "severity": "low"}])
    auth = captured.get("Authorization", "")
    assert auth.startswith("Basic ")
    decoded = b64decode(auth[len("Basic "):]).decode()
    assert decoded == "gluser:glpass"


async def test_push_events_partial_failure_pushed_count_reflects_real_success(monkeypatch):
    """If some POSTs return 200/202 and others fail, pushed_count
    must reflect ONLY the actually-accepted events."""
    conn = _connector(monkeypatch)
    # Alternate: success / fail / success.
    counter = {"i": 0}
    responses = [
        _FakeResp(status=202),
        _FakeResp(status=500, text_body="oops"),
        _FakeResp(status=202),
    ]

    def _factory():
        r = responses[counter["i"] % len(responses)]
        counter["i"] += 1
        return r

    with _patch_session(_factory):
        result = await conn.push_events([
            {"id": "1", "title": "t1", "severity": "low"},
            {"id": "2", "title": "t2", "severity": "low"},
            {"id": "3", "title": "t3", "severity": "low"},
        ])
    assert result.success is True
    assert result.pushed_count == 2  # only the 2 successful POSTs


async def test_push_events_all_fail_returns_error(monkeypatch):
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=500, text_body="bad")):
        result = await conn.push_events([{"id": "1", "title": "t", "severity": "low"}])
    assert result.success is False
    assert "500" in (result.error or "")


async def test_push_events_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_GRAYLOG_GELF_URL", raising=False)
    conn = GraylogConnector()
    result = await conn.push_events([{"id": "1"}])
    assert result.success is False
    assert "not configured" in (result.note or "").lower()


async def test_push_events_empty_list(monkeypatch):
    conn = _connector(monkeypatch)
    result = await conn.push_events([])
    assert result.success is True
    assert result.pushed_count == 0
