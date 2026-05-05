"""XposedOrNot breach provider — fixture tests.

Pins the ``_payload_to_hits`` parser and ``search_email`` HTTP path
against realistic-shape responses. Catches drift if XposedOrNot
changes their response shape (Adobe-breach example below is an
abridged real response from /v1/breach-analytics).

The fixture payloads were captured from XposedOrNot's documented
response examples in May 2026. If the upstream rotates field names
again, these tests will fail loudly instead of silently returning
empty hit lists in production.
"""

from __future__ import annotations

import contextlib
from unittest.mock import patch

import pytest

from src.integrations.breach.xposedornot import (
    XposedOrNotProvider,
    _payload_to_hits,
)

pytestmark = pytest.mark.asyncio


# ── Aiohttp test doubles (same shape as test_circl_enrichment) ────────


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = text_body or ""

    async def json(self, content_type=None):
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

    def get(self, *args, **kwargs):
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


# ── Realistic-shape payloads (abridged from xposedornot.com docs) ─────


_ADOBE_PAYLOAD = {
    "BreachMetrics": {
        "get_details": [],
        "industry": [["Software", 1]],
        "passwords_strength": [{"EasyToCrack": 1}],
        "risk": [{"label": "high", "score": 8}],
        "xposed_data": [],
        "yearwise_details": [{"y2013": 1}],
    },
    "BreachesSummary": {"site": "Adobe;LinkedIn"},
    "ExposedBreaches": {
        "breaches_details": [
            {
                "breach": "Adobe",
                "details": "In October 2013, 153 million Adobe accounts were breached.",
                "domain": "adobe.com",
                "industry": "Software",
                "logo": "https://...",
                "password_risk": "easy",
                "xposed_data": "Email addresses;Password hints;Passwords;Usernames",
                "xposed_date": "2013-10",
                "xposed_records": 152445165,
                "added": "2014-12-04",
            },
            {
                "breach": "LinkedIn",
                "details": "In May 2016, LinkedIn had 164 million emails leaked.",
                "domain": "linkedin.com",
                "industry": "Social",
                "logo": "https://...",
                "password_risk": "medium",
                "xposed_data": "Email addresses;Passwords",
                "xposed_date": "2016-05",
                "xposed_records": 164611595,
                "added": "2016-06-08",
            },
        ],
    },
}


_NOT_FOUND_PAYLOAD = {"Error": "Not found"}


# ── _payload_to_hits ──────────────────────────────────────────────────


def test_payload_to_hits_parses_two_breaches():
    hits = _payload_to_hits("xposedornot", "user@adobe.com", _ADOBE_PAYLOAD)
    assert len(hits) == 2

    adobe = next(h for h in hits if h.breach_name == "Adobe")
    assert adobe.email == "user@adobe.com"
    assert adobe.breach_date == "2013-10"
    assert "Email addresses" in adobe.data_classes
    assert "Password hints" in adobe.data_classes
    assert "Passwords" in adobe.data_classes
    assert "Usernames" in adobe.data_classes
    assert adobe.raw["records"] == 152445165
    assert adobe.raw["domain"] == "adobe.com"
    assert adobe.raw["password_risk"] == "easy"

    linkedin = next(h for h in hits if h.breach_name == "LinkedIn")
    assert linkedin.raw["records"] == 164611595


def test_payload_to_hits_handles_empty_exposed():
    """Some users have BreachMetrics but no ExposedBreaches detail —
    don't fabricate hits."""
    payload = {"BreachMetrics": {}, "ExposedBreaches": {}}
    assert _payload_to_hits("xposedornot", "x@y.z", payload) == []


def test_payload_to_hits_handles_missing_fields():
    """Defensive — a stripped-down breach record (only the breach name)
    should still produce a hit, falling back to defaults."""
    payload = {"ExposedBreaches": {"breaches_details": [{"breach": "MysteryDump"}]}}
    hits = _payload_to_hits("xposedornot", "x@y.z", payload)
    assert len(hits) == 1
    assert hits[0].breach_name == "MysteryDump"
    # Default data_classes when xposed_data is empty
    assert hits[0].data_classes == ["Emails"]


def test_payload_to_hits_skips_non_dict_entries():
    """Defensive against future schema changes — non-dict entries in
    breaches_details should be ignored, not crash."""
    payload = {
        "ExposedBreaches": {
            "breaches_details": [
                {"breach": "Real"},
                "garbage-string",
                None,
                42,
            ],
        },
    }
    hits = _payload_to_hits("xposedornot", "x@y.z", payload)
    assert len(hits) == 1
    assert hits[0].breach_name == "Real"


def test_payload_to_hits_non_dict_payload():
    """Top-level non-dict payload should return [] silently."""
    assert _payload_to_hits("xposedornot", "x@y.z", "garbage") == []
    assert _payload_to_hits("xposedornot", "x@y.z", []) == []
    assert _payload_to_hits("xposedornot", "x@y.z", None) == []


# ── search_email integration paths ────────────────────────────────────


async def test_search_email_in_corpus():
    p = XposedOrNotProvider()
    with _patch_session(_FakeResp(status=200, json_body=_ADOBE_PAYLOAD)):
        result = await p.search_email("user@adobe.com")
    assert result.success is True
    assert result.error is None
    assert len(result.hits) == 2


async def test_search_email_not_in_corpus_capital_E():
    """XposedOrNot returns ``{"Error": "Not found"}`` (capital E) for
    misses with HTTP 200. The adapter must treat that as a clean
    not-in-corpus, not a parse failure."""
    p = XposedOrNotProvider()
    with _patch_session(_FakeResp(status=200, json_body=_NOT_FOUND_PAYLOAD)):
        result = await p.search_email("ghost@nowhere.example")
    assert result.success is True
    assert result.hits == []
    assert "not in" in (result.note or "").lower()


async def test_search_email_404():
    p = XposedOrNotProvider()
    with _patch_session(_FakeResp(status=404)):
        result = await p.search_email("ghost@nowhere.example")
    assert result.success is True
    assert result.hits == []


async def test_search_email_429_rate_limit():
    p = XposedOrNotProvider()
    with _patch_session(_FakeResp(status=429)):
        result = await p.search_email("user@adobe.com")
    assert result.success is False
    assert "429" in (result.error or "")
    assert "rate-limited" in (result.error or "").lower()


async def test_search_email_5xx_error():
    p = XposedOrNotProvider()
    with _patch_session(_FakeResp(status=500, text_body="upstream is down")):
        result = await p.search_email("user@adobe.com")
    assert result.success is False
    assert "500" in (result.error or "")


async def test_search_email_empty_input_short_circuits():
    """No HTTP call should fire for empty/malformed inputs."""
    p = XposedOrNotProvider()
    # No _patch_session — would raise if HTTP were attempted.
    result_empty = await p.search_email("")
    result_no_at = await p.search_email("not-an-email")
    assert result_empty.success is False
    assert result_no_at.success is False
    assert "malformed" in (result_empty.error or "").lower()


async def test_search_domain_returns_unsupported():
    """Domain endpoint requires paid tier per docs — adapter should
    surface a clear ``error`` rather than silently failing."""
    p = XposedOrNotProvider()
    result = await p.search_domain("adobe.com")
    assert result.success is False
    assert "paid" in (result.error or "").lower()
    # Cavalier should be the recommended free path.
    assert "cavalier" in (result.error or "").lower()


# ── is_configured ─────────────────────────────────────────────────────


def test_is_configured_true_without_key():
    """Public endpoints don't require a key — the provider is
    is_configured()=True regardless of env."""
    p = XposedOrNotProvider()
    assert p.is_configured() is True
