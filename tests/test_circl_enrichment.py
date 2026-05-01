"""CIRCL public-API enrichment (P2 #2.8) — integration tests.

Each test patches the aiohttp call surface so we exercise the real
code paths (parsing, classification, error handling) without leaving
network egress in the test suite.
"""

from __future__ import annotations

import contextlib
from unittest.mock import patch

import pytest

from src.enrichment import circl as circl_mod
from src.enrichment.circl import (
    HashlookupResult,
    PdnsRecord,
    _detect_hash_kind,
    hashlookup,
    passive_ssl_query,
    pdns_query,
)

pytestmark = pytest.mark.asyncio


# ── _detect_hash_kind ────────────────────────────────────────────────


@pytest.mark.parametrize("digest,expected", [
    ("a" * 32, "md5"),
    ("b" * 40, "sha1"),
    ("c" * 64, "sha256"),
    ("short", None),
    ("", None),
])
def test_detect_hash_kind(digest, expected):
    assert _detect_hash_kind(digest) == expected


# ── Aiohttp double ────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, *, status=200, json_body=None, text_body=None):
        self.status = status
        self._json = json_body
        self._text = text_body

    async def json(self):
        return self._json

    async def text(self):
        return self._text or ""

    def raise_for_status(self):
        if self.status >= 400:
            import aiohttp
            raise aiohttp.ClientResponseError(
                request_info=None, history=(), status=self.status,
                message=f"HTTP {self.status}",
            )

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
    """Force ``aiohttp.ClientSession(...)`` calls to return our fake."""
    import aiohttp

    def factory(*args, **kwargs):
        return _FakeSession(response)

    with patch.object(aiohttp, "ClientSession", factory):
        yield


# ── hashlookup ────────────────────────────────────────────────────────


async def test_hashlookup_known_good_hash():
    with _patch_session(_FakeResp(status=200, json_body={
        "SHA-1": "B" * 40, "FileName": "winload.exe",
        "KnownMalicious": False,
    })):
        result = await hashlookup("B" * 40)
    assert isinstance(result, HashlookupResult)
    assert result.classification == "known-good"
    assert result.hash_kind == "sha1"
    assert result.known is True


async def test_hashlookup_known_bad_hash():
    with _patch_session(_FakeResp(status=200, json_body={
        "SHA-256": "C" * 64, "KnownMalicious": True,
    })):
        result = await hashlookup("C" * 64)
    assert result.classification == "known-bad"
    assert result.hash_kind == "sha256"


async def test_hashlookup_404_returns_unknown_classification():
    with _patch_session(_FakeResp(status=404)):
        result = await hashlookup("a" * 64)
    assert result is not None
    assert result.classification == "unknown"
    assert result.known is False


async def test_hashlookup_invalid_digest_returns_none():
    """Short input doesn't match any known hash format — short-circuit
    before any network call."""
    result = await hashlookup("notahash")
    assert result is None


# ── pdns ──────────────────────────────────────────────────────────────


async def test_pdns_skips_when_no_credentials(monkeypatch):
    monkeypatch.delenv("ARGUS_CIRCL_USERNAME", raising=False)
    monkeypatch.delenv("ARGUS_CIRCL_PASSWORD", raising=False)
    out = await pdns_query("example.com")
    assert out == []


async def test_pdns_parses_ndjson(monkeypatch):
    monkeypatch.setenv("ARGUS_CIRCL_USERNAME", "u")
    monkeypatch.setenv("ARGUS_CIRCL_PASSWORD", "p")
    ndjson = (
        '{"rrname":"example.com","rrtype":"A","rdata":"1.2.3.4",'
        '"time_first":1714000000,"time_last":1714999999,"count":42}\n'
        '{"rrname":"example.com","rrtype":"AAAA","rdata":"::1",'
        '"time_first":1714500000,"time_last":1714999999,"count":7}\n'
        'not-json-line\n'
    )
    with _patch_session(_FakeResp(status=200, text_body=ndjson)):
        out = await pdns_query("example.com")
    assert len(out) == 2
    assert out[0].rrname == "example.com"
    assert out[0].rdata == "1.2.3.4"
    assert out[1].rrtype == "AAAA"


async def test_pdns_404_yields_empty(monkeypatch):
    monkeypatch.setenv("ARGUS_CIRCL_USERNAME", "u")
    monkeypatch.setenv("ARGUS_CIRCL_PASSWORD", "p")
    with _patch_session(_FakeResp(status=404)):
        assert await pdns_query("nope.example") == []


# ── passive ssl ──────────────────────────────────────────────────────


async def test_passive_ssl_skips_when_no_credentials(monkeypatch):
    monkeypatch.delenv("ARGUS_CIRCL_USERNAME", raising=False)
    monkeypatch.delenv("ARGUS_CIRCL_PASSWORD", raising=False)
    assert await passive_ssl_query("8.8.8.8") == []


async def test_passive_ssl_parses_certificate_dict(monkeypatch):
    monkeypatch.setenv("ARGUS_CIRCL_USERNAME", "u")
    monkeypatch.setenv("ARGUS_CIRCL_PASSWORD", "p")
    payload = {
        "certificates": [
            {"hash": "DE" * 20, "subject": "CN=evil.example",
             "issuer": "CN=Let's Encrypt R3",
             "not_before": "2026-04-01", "not_after": "2026-07-01"},
            {"hash": "AB" * 20, "subject": "CN=other.example"},
        ],
    }
    with _patch_session(_FakeResp(status=200, json_body=payload)):
        out = await passive_ssl_query("203.0.113.7")
    assert len(out) == 2
    assert out[0].fingerprint_sha1 == ("de" * 20)
    assert "evil.example" in (out[0].subject or "")


async def test_passive_ssl_404_yields_empty(monkeypatch):
    monkeypatch.setenv("ARGUS_CIRCL_USERNAME", "u")
    monkeypatch.setenv("ARGUS_CIRCL_PASSWORD", "p")
    with _patch_session(_FakeResp(status=404)):
        assert await passive_ssl_query("203.0.113.99") == []


# ── HTTP route ────────────────────────────────────────────────────────


async def test_circl_enrich_route_validates_input(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/circl/enrich",
        json={}, headers=analyst_user["headers"],
    )
    assert r.status_code == 400


async def test_circl_enrich_route_hashlookup(client, analyst_user):
    """Patch the module-level hashlookup so the route doesn't hit the
    network. Verifies the route shapes the response correctly."""
    fake = HashlookupResult(
        hash="A" * 64, hash_kind="sha256", known=True,
        classification="known-bad", source="circl_hashlookup",
        raw={"KnownMalicious": True},
    )

    async def fake_hashlookup(h):
        return fake

    with patch.object(circl_mod, "hashlookup", fake_hashlookup):
        r = await client.post(
            "/api/v1/intel/circl/enrich",
            json={"hash": "A" * 64},
            headers=analyst_user["headers"],
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "hash"
    assert body["result"]["classification"] == "known-bad"
