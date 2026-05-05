"""Rspamd email-gateway connector — fixture tests.

Pins the /history parser across both modern (v4 with ``rows[]``) and
legacy (bare-array) shapes, the action→classification map, the
phishing-symbol override, and the auth-rejection paths.
"""

from __future__ import annotations

import contextlib
import json
from unittest.mock import patch

import pytest

from src.integrations.email_gateway.rspamd import RspamdConnector

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
    def __init__(self, response: _FakeResp, captured_headers=None):
        self._response = response
        self._captured = captured_headers

    def get(self, url, *args, headers=None, **kwargs):
        if headers and self._captured is not None:
            self._captured.update(headers)
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@contextlib.contextmanager
def _patch_session(response: _FakeResp, captured_headers=None):
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(response, captured_headers)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


def _connector(monkeypatch, *, password="rspamd-pw"):
    monkeypatch.setenv("ARGUS_RSPAMD_URL", "http://rspamd.test:11334")
    if password:
        monkeypatch.setenv("ARGUS_RSPAMD_PASSWORD", password)
    return RspamdConnector()


# ── Realistic /history payloads ─────────────────────────────────────


_PHISH_ROW = {
    "message-id": "<phish-1@evil.example>",
    "subject": "URGENT: Verify your account",
    "sender_smtp": "attacker@evil.example",
    "sender_mime": "Bank Support <noreply@bank-fake.example>",
    "rcpt_smtp": ["victim@company.example"],
    "score": 12.5,
    "required_score": 10.0,
    "action": "reject",
    "symbols": {
        "PHISHING": {"score": 5.0, "options": ["evil.example"]},
        "URIBL_PHISH": {"score": 3.0},
        "FROM_NEQ_DISPLAY_NAME": {"score": 2.0},
    },
    "urls": ["https://evil.example/login", "https://bank-fake.example/verify"],
    "time_real": 0.512,
    "unix_time": 1735689600,
}


_HIDDEN_PHISH_ROW = {
    # Action says no_action but a phishing symbol fired — should still
    # be classified as phish via the symbol override.
    "message-id": "<sneaky@x>",
    "subject": "Resume.pdf",
    "sender_smtp": "hr@partner.example",
    "score": 6.0,
    "action": "no action",
    "symbols": {"HFILTER_URL_PHISHED": {"score": 4.0}},
    "urls": ["http://drive.fake-google.example/?file=resume.pdf"],
    "unix_time": 1735689700,
}


_CLEAN_ROW = {
    "message-id": "<legit@ok.example>",
    "subject": "Lunch tomorrow?",
    "score": 1.0,
    "action": "no action",
    "symbols": {"BAYES_HAM": {"score": -1.0}},
    "urls": [],
    "unix_time": 1735689800,
}


def _modern_payload(rows):
    return json.dumps({"version": 4, "rows": rows})


def _legacy_payload(rows):
    return json.dumps(rows)


# ── Modern v4 history shape ─────────────────────────────────────────


async def test_fetch_threats_modern_history(monkeypatch):
    conn = _connector(monkeypatch)
    body = _modern_payload([_PHISH_ROW, _CLEAN_ROW])
    with _patch_session(_FakeResp(status=200, text_body=body)):
        result = await conn.fetch_threats()

    assert result.success is True
    # 1 phish event + 0 clean = 1 (clean rows filtered out)
    assert len(result.events) == 1
    ev = result.events[0]
    assert ev.classification == "phish"
    assert ev.subject == "URGENT: Verify your account"
    assert ev.sender == "attacker@evil.example"
    assert ev.recipient == "victim@company.example"
    assert ev.threat_url == "https://evil.example/login"
    assert "PHISHING" in ev.raw["symbols"]
    assert ev.raw["score"] == 12.5


# ── Legacy bare-array history shape ─────────────────────────────────


async def test_fetch_threats_legacy_history(monkeypatch):
    """Older Rspamd controllers return a bare JSON array. Must
    handle both shapes interchangeably."""
    conn = _connector(monkeypatch)
    body = _legacy_payload([_PHISH_ROW])
    with _patch_session(_FakeResp(status=200, text_body=body)):
        result = await conn.fetch_threats()
    assert result.success is True
    assert len(result.events) == 1
    assert result.events[0].classification == "phish"


# ── Phishing-symbol override ────────────────────────────────────────


async def test_phishing_symbol_overrides_no_action(monkeypatch):
    """Even with ``action == "no action"`` (clean by default), the
    presence of a phishing-flavoured symbol must promote the event
    to phish — operators tune Rspamd action thresholds variably and
    we don't want to miss an obvious phish because the threshold
    was loose."""
    conn = _connector(monkeypatch)
    body = _modern_payload([_HIDDEN_PHISH_ROW])
    with _patch_session(_FakeResp(status=200, text_body=body)):
        result = await conn.fetch_threats()
    assert len(result.events) == 1
    assert result.events[0].classification == "phish"


async def test_clean_rows_skipped(monkeypatch):
    """Rows with no phishing/malware verdict and no phishing symbols
    must NOT be ingested as IOCs."""
    conn = _connector(monkeypatch)
    body = _modern_payload([_CLEAN_ROW])
    with _patch_session(_FakeResp(status=200, text_body=body)):
        result = await conn.fetch_threats()
    assert result.success is True
    assert result.events == []


# ── Auth paths ──────────────────────────────────────────────────────


async def test_fetch_threats_sends_password_header(monkeypatch):
    conn = _connector(monkeypatch, password="my-rspamd-pw")
    captured: dict[str, str] = {}
    with _patch_session(_FakeResp(status=200, text_body="[]"), captured_headers=captured):
        await conn.fetch_threats()
    assert captured.get("Password") == "my-rspamd-pw"


async def test_fetch_threats_401_password_rejected(monkeypatch):
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=401)):
        result = await conn.fetch_threats()
    assert result.success is False
    assert "rejected" in (result.error or "").lower()


async def test_fetch_threats_403_password_rejected(monkeypatch):
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=403)):
        result = await conn.fetch_threats()
    assert result.success is False
    assert "rejected" in (result.error or "").lower()


async def test_fetch_threats_500_returns_error(monkeypatch):
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=500, text_body="boom")):
        result = await conn.fetch_threats()
    assert result.success is False
    assert "500" in (result.error or "")


async def test_fetch_threats_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_RSPAMD_URL", raising=False)
    conn = RspamdConnector()
    result = await conn.fetch_threats()
    assert result.success is False
    assert "not configured" in (result.note or "").lower()


# ── Defensive ──────────────────────────────────────────────────────


async def test_fetch_threats_unexpected_payload_shape(monkeypatch):
    """If Rspamd ever returns something other than rows[] / array,
    the adapter should surface a clean failure, not crash."""
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=200, text_body='{"version": 4}')):
        result = await conn.fetch_threats()
    assert result.success is False
    assert "unexpected" in (result.error or "").lower()


async def test_fetch_threats_malformed_json(monkeypatch):
    conn = _connector(monkeypatch)
    with _patch_session(_FakeResp(status=200, text_body="not-json")):
        result = await conn.fetch_threats()
    assert result.success is False
    assert "JSON parse" in (result.error or "")


# ── push_blocklist is intentionally unsupported ────────────────────


async def test_push_blocklist_returns_unsupported(monkeypatch):
    """Rspamd doesn't expose a programmatic blocklist write API. The
    connector must surface that clearly so operators don't silently
    expect blocklist propagation that won't happen."""
    conn = _connector(monkeypatch)
    result = await conn.push_blocklist([])
    assert result.success is False
    assert "doesn't expose" in (result.note or "").lower() or "not expose" in (result.note or "").lower()
    assert "multimap" in (result.note or "").lower()


def test_supports_blocklist_push_flag():
    """Pin the capability flag — frontend reads this to grey out the
    Block button."""
    assert RspamdConnector.supports_blocklist_push is False
