"""Cortex (TheHive Project) SOAR connector — fixture tests.

Pins the observable extraction from Argus alert dicts, the
run_analyzer dataType validation, the Bearer-token auth header,
and the push_events fanout flow.
"""

from __future__ import annotations

import contextlib
import json
from unittest.mock import patch

import pytest

from src.integrations.soar.cortex import CortexConnector

pytestmark = pytest.mark.asyncio


# ── Test doubles ────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, text_body="", captured_body=None):
        self.status = status
        self._text = text_body
        # Side-channel for body inspection on POST
        self._captured_body = captured_body

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, route_table, captured_headers, captured_bodies):
        self._table = route_table
        self._captured_headers = captured_headers
        self._captured_bodies = captured_bodies

    def _resp_for(self, url: str) -> _FakeResp:
        for needle, resp in self._table.items():
            if needle in url:
                return resp
        return _FakeResp(status=404, text_body="not mocked")

    def get(self, url, *args, headers=None, **kwargs):
        if headers and self._captured_headers is not None:
            self._captured_headers.update(headers)
        return self._resp_for(url)

    def post(self, url, *args, headers=None, json=None, **kwargs):
        if headers and self._captured_headers is not None:
            self._captured_headers.update(headers)
        if json is not None and self._captured_bodies is not None:
            self._captured_bodies.append(json)
        return self._resp_for(url)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(route_table, captured_headers=None, captured_bodies=None):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(route_table, captured_headers, captured_bodies)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


def _connector(monkeypatch):
    monkeypatch.setenv("ARGUS_CORTEX_URL", "http://cortex.test:9001")
    monkeypatch.setenv("ARGUS_CORTEX_API_KEY", "cortex-test-key")
    return CortexConnector()


# ── _extract_observables ────────────────────────────────────────────


def test_extract_observables_from_matched_entities():
    ev = {
        "id": "alert-1",
        "matched_entities": {
            "src_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
            "domain": "evil.example.com",
            "sha256": "a" * 64,
        },
    }
    obs = CortexConnector._extract_observables(ev)
    obs_set = set(obs)
    assert ("ip", "1.2.3.4") in obs_set
    assert ("ip", "5.6.7.8") in obs_set
    assert ("domain", "evil.example.com") in obs_set
    assert ("hash", "a" * 64) in obs_set


def test_extract_observables_dedupes():
    ev = {
        "matched_entities": {"src_ip": "1.2.3.4"},
        "details": {"src_ip": "1.2.3.4", "ip_address": "1.2.3.4"},
    }
    obs = CortexConnector._extract_observables(ev)
    # 1.2.3.4 should appear once even though it's in matched_entities
    # AND details under different key names.
    assert obs.count(("ip", "1.2.3.4")) == 1


def test_extract_observables_falls_back_to_details():
    ev = {"details": {"hostname": "compromised.example.com"}}
    obs = CortexConnector._extract_observables(ev)
    assert ("domain", "compromised.example.com") in obs


def test_extract_observables_skips_empty_values():
    ev = {"matched_entities": {"src_ip": "", "domain": "  ", "sha256": "abc"}}
    obs = CortexConnector._extract_observables(ev)
    # Only the non-empty hash extracted
    assert obs == [("hash", "abc")]


def test_extract_observables_no_recognised_keys():
    """If the alert has no observables we know how to extract, return
    empty — never crash."""
    ev = {"matched_entities": {"random_field": "x"}, "details": {"foo": "bar"}}
    obs = CortexConnector._extract_observables(ev)
    assert obs == []


def test_extract_observables_handles_non_dict_event():
    """Defensive — should not crash on a malformed event dict."""
    obs = CortexConnector._extract_observables({})
    assert obs == []


def test_extract_observables_handles_non_string_values():
    """Numeric values in matched_entities (rare but possible) should
    be skipped silently, not raise on .strip()."""
    ev = {"matched_entities": {"src_ip": 42, "domain": "real.example"}}
    obs = CortexConnector._extract_observables(ev)
    assert obs == [("domain", "real.example")]


# ── run_analyzer happy path ─────────────────────────────────────────


async def test_run_analyzer_submits_job(monkeypatch):
    conn = _connector(monkeypatch)
    routes = {
        "/api/analyzer/AbuseIPDB_1_0/run": _FakeResp(
            status=200, text_body='{"id": "job-abc-123"}',
        ),
    }
    captured_headers: dict[str, str] = {}
    captured_bodies: list[dict] = []
    with _patch_session(routes, captured_headers, captured_bodies):
        result = await conn.run_analyzer(
            "AbuseIPDB_1_0", data="1.2.3.4", data_type="ip", message="argus alert 99",
        )

    assert result.success is True
    assert result.remote_ids == ["job-abc-123"]

    # Auth header pinned
    assert captured_headers.get("Authorization") == "Bearer cortex-test-key"
    assert captured_headers.get("Content-Type") == "application/json"

    # Body shape pinned
    body = captured_bodies[0]
    assert body["data"] == "1.2.3.4"
    assert body["dataType"] == "ip"
    assert body["tlp"] == 2
    assert body["message"].startswith("argus alert 99")


async def test_run_analyzer_rejects_unsupported_datatype(monkeypatch):
    """The dataType param is strict — Cortex's analyzers reject unknown
    types, so the connector should short-circuit before sending."""
    conn = _connector(monkeypatch)
    # No _patch_session → test would fail loudly if HTTP fired.
    result = await conn.run_analyzer(
        "Whatever_1_0", data="garbage", data_type="quantum_state",
    )
    assert result.success is False
    assert "unsupported dataType" in (result.error or "")


async def test_run_analyzer_normalises_datatype_aliases(monkeypatch):
    """Argus uses 'sha256' / 'fqdn' / 'mail' as colloquial aliases;
    they get normalised to Cortex's canonical 'hash' / 'domain' / 'mail'."""
    conn = _connector(monkeypatch)
    routes = {"/api/analyzer/x/run": _FakeResp(status=200, text_body='{"id": "j"}')}
    captured_bodies: list[dict] = []
    with _patch_session(routes, captured_bodies=captured_bodies):
        await conn.run_analyzer("x", data="a" * 64, data_type="sha256")
        await conn.run_analyzer("x", data="evil.com", data_type="fqdn")
        await conn.run_analyzer("x", data="b@c.io", data_type="email")

    assert captured_bodies[0]["dataType"] == "hash"
    assert captured_bodies[1]["dataType"] == "domain"
    assert captured_bodies[2]["dataType"] == "mail"


async def test_run_analyzer_handles_missing_id_in_response(monkeypatch):
    conn = _connector(monkeypatch)
    routes = {"/api/analyzer/x/run": _FakeResp(status=200, text_body="{}")}
    with _patch_session(routes):
        result = await conn.run_analyzer("x", data="1.2.3.4", data_type="ip")
    assert result.success is False
    assert "no job id" in (result.error or "").lower()


async def test_run_analyzer_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_CORTEX_URL", raising=False)
    monkeypatch.delenv("ARGUS_CORTEX_API_KEY", raising=False)
    conn = CortexConnector()
    result = await conn.run_analyzer("x", data="1.2.3.4", data_type="ip")
    assert result.success is False
    assert "not configured" in (result.note or "").lower()


# ── push_events fanout ─────────────────────────────────────────────


async def test_push_events_fans_out_observables(monkeypatch):
    """An alert with 2 observables (ip + domain) should produce 2
    analyzer-job submissions when the default analyzer is configured."""
    conn = _connector(monkeypatch)
    routes = {"/api/analyzer/AbuseIPDB_1_0/run": _FakeResp(
        status=200, text_body='{"id": "job-X"}',
    )}
    bodies: list[dict] = []
    with _patch_session(routes, captured_bodies=bodies):
        result = await conn.push_events([{
            "id": "alert-1",
            "title": "Suspicious activity",
            "matched_entities": {"src_ip": "1.2.3.4", "domain": "evil.example"},
        }])

    assert result.success is True
    assert result.pushed_count == 2
    assert len(result.remote_ids) == 2
    # Both observables sent via separate POSTs
    body_pairs = [(b["dataType"], b["data"]) for b in bodies]
    assert ("ip", "1.2.3.4") in body_pairs
    assert ("domain", "evil.example") in body_pairs


async def test_push_events_no_observables_returns_zero_submitted(monkeypatch):
    """An alert with no extractable observables should pushed_count=0
    with success=True (it's not an error)."""
    conn = _connector(monkeypatch)
    with _patch_session({}):
        result = await conn.push_events([{"id": "1", "title": "vague alert"}])
    assert result.success is True
    assert result.pushed_count == 0


async def test_push_events_empty_list(monkeypatch):
    conn = _connector(monkeypatch)
    result = await conn.push_events([])
    assert result.success is True
    assert result.pushed_count == 0


# ── is_configured ─────────────────────────────────────────────────


def test_is_configured_requires_both_url_and_key(monkeypatch):
    monkeypatch.delenv("ARGUS_CORTEX_URL", raising=False)
    monkeypatch.delenv("ARGUS_CORTEX_API_KEY", raising=False)
    assert CortexConnector().is_configured() is False
    monkeypatch.setenv("ARGUS_CORTEX_URL", "http://cortex.test")
    assert CortexConnector().is_configured() is False
    monkeypatch.setenv("ARGUS_CORTEX_API_KEY", "k")
    assert CortexConnector().is_configured() is True
