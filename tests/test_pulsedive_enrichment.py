"""Pulsedive enrichment — fixture tests.

Pins the lookup parser, iid==0 → in_corpus=False semantics, and the
threats/feeds/riskfactors normalisation pipeline.

Fixture shapes match the documented Pulsedive /api/indicator.php
response (May 2026 — docs.pulsedive.com).
"""

from __future__ import annotations

import contextlib
from unittest.mock import patch

import pytest

import src.enrichment.pulsedive as pd_mod
from src.enrichment.pulsedive import PulsediveResult, lookup

pytestmark = pytest.mark.asyncio


# ── Aiohttp test doubles ─────────────────────────────────────────────


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


@contextlib.contextmanager
def _no_cache():
    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(pd_mod, "_from_cache", _miss):
        with patch.object(pd_mod, "_store_cache", _store):
            yield


# ── Realistic Pulsedive payloads ─────────────────────────────────────


_HIT_PAYLOAD = {
    "qid": None,
    "iid": 12345,
    "indicator": "evil.example.com",
    "type": "domain",
    "risk": "high",
    "risk_recommended": "high",
    "manualrisk": 0,
    "retired": 0,
    "stamp_added": "2024-01-15 10:00:00",
    "stamp_updated": "2026-04-30 12:00:00",
    "stamp_seen": "2026-05-01 08:30:00",
    "stamp_probed": "2026-05-01 09:00:00",
    "recent": 1,
    "submissions": 47,
    "umbrella_rank": 99999,
    "umbrella_domain": "example.com",
    "riskfactors": [
        {"description": "Hosted on bulletproof IP", "rfid": 12},
        {"description": "Domain registered <30 days", "rfid": 8},
    ],
    "threats": [
        {"name": "Lumma Stealer", "tid": 100},
        {"name": "Generic Phishing", "tid": 101},
    ],
    "feeds": [
        {"name": "abuse.ch URLhaus", "fid": 1},
        {"name": "PhishTank", "fid": 2},
    ],
    "comments": [],
    "attributes": {},
    "properties": {},
}


_MISS_PAYLOAD = {
    "qid": None,
    "iid": 0,
    "indicator": "ghost.example",
    "type": None,
    "risk": "unknown",
    "risk_recommended": "unknown",
    "stamp_added": None,
    "threats": [],
    "feeds": [],
    "riskfactors": [],
}


# ── Hit path ─────────────────────────────────────────────────────────


async def test_lookup_hit_normalises_response():
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=_HIT_PAYLOAD)):
        result = await lookup("evil.example.com")
    assert isinstance(result, PulsediveResult)
    assert result.success is True
    assert result.in_corpus is True
    assert result.type == "domain"
    assert result.risk == "high"
    assert result.risk_recommended == "high"
    assert result.threats == ["Lumma Stealer", "Generic Phishing"]
    assert result.feeds == ["abuse.ch URLhaus", "PhishTank"]
    assert "Hosted on bulletproof IP" in result.riskfactors
    assert "Domain registered <30 days" in result.riskfactors
    assert result.stamp_seen == "2026-05-01 08:30:00"


# ── Miss (iid==0) ───────────────────────────────────────────────────


async def test_lookup_iid_zero_is_clean_miss():
    """Pulsedive returns 200 + iid=0 for indicators not in their corpus.
    This must NOT surface as success=False — chained enrichments
    rely on the parsers returning a clean miss."""
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=_MISS_PAYLOAD)):
        result = await lookup("ghost.example")
    assert result.success is True
    assert result.in_corpus is False
    assert result.error is None


# ── Failure paths populate error, never raise ───────────────────────


async def test_lookup_429_rate_limit():
    with _no_cache(), _patch_session(_FakeResp(status=429)):
        result = await lookup("evil.example.com")
    assert result.success is False
    assert "429" in (result.error or "")


async def test_lookup_403_invalid_key():
    with _no_cache(), _patch_session(_FakeResp(status=403)):
        result = await lookup("evil.example.com")
    assert result.success is False
    assert "403" in (result.error or "")


async def test_lookup_500_returns_error():
    with _no_cache(), _patch_session(_FakeResp(status=500)):
        result = await lookup("evil.example.com")
    assert result.success is False
    assert "500" in (result.error or "")


async def test_lookup_unexpected_payload_type():
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=[])):
        result = await lookup("evil.example.com")
    assert result.success is False
    assert "unexpected payload" in (result.error or "").lower()


async def test_lookup_empty_input():
    """No HTTP call on empty input."""
    result = await lookup("")
    assert result.success is False
    assert "empty" in (result.error or "").lower()


# ── Threats/feeds/riskfactors edge cases ────────────────────────────


async def test_threats_skips_non_dict_entries():
    payload = {
        **_HIT_PAYLOAD,
        "threats": [{"name": "Real"}, "garbage", None, {}],
    }
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=payload)):
        result = await lookup("x")
    assert result.threats == ["Real"]


async def test_riskfactors_falls_back_to_rfid_when_no_description():
    """When description is absent, rfid is coerced to str so the
    declared ``list[str]`` annotation holds and frontend JSON
    serialisation doesn't get a mixed list."""
    payload = {**_HIT_PAYLOAD, "riskfactors": [{"rfid": 99}, {"description": "Real risk"}]}
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=payload)):
        result = await lookup("x")
    assert result.riskfactors == ["99", "Real risk"]
    # All entries must be str (no ints leaking through)
    assert all(isinstance(rf, str) for rf in result.riskfactors)


# ── Cache key shape pins (auth: vs anon:) ───────────────────────────


def test_cache_key_form_distinguishes_auth_from_anon():
    """Anonymous and authenticated lookups for the same indicator must
    have distinct cache keys — different rate limits + result tiers
    means the responses are not interchangeable."""
    anon = pd_mod._cache_key("evil.example.com", "")
    auth = pd_mod._cache_key("evil.example.com", "secret-key")
    assert anon != auth
    assert "anon:" in anon
    assert "auth:" in auth


# ── to_dict shape pin ───────────────────────────────────────────────


def test_to_dict_round_trip():
    r = PulsediveResult(
        indicator="x", success=True, in_corpus=True,
        type="domain", risk="high", threats=["A", "B"],
        feeds=["f1"], riskfactors=["r1"],
    )
    d = r.to_dict()
    assert set(d.keys()) == {
        "indicator", "success", "in_corpus", "type",
        "risk", "risk_recommended", "threats", "feeds",
        "riskfactors", "stamp_seen", "error", "cached",
    }
