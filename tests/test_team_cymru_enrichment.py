"""Team Cymru IP→ASN WHOIS enrichment — fixture tests.

Pins the verbose-line parser (caught a real IndexError bug during
adapter authoring), bulk response parsing, and the cache-miss
batching path. WHOIS responses are byte-exact reproductions from
real ``whois -h whois.cymru.com`` output.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

import src.enrichment.team_cymru as tc_mod
from src.enrichment.team_cymru import (
    TeamCymruResult,
    _parse_response_line,
    lookup,
    lookup_bulk,
)

pytestmark = pytest.mark.asyncio


# Real-shape verbose responses from whois.cymru.com (May 2026).
_HEADER_LINE = "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name"
_DATA_LINE_1 = "23028   | 216.90.108.31   | 216.90.108.0/24     | US | arin     | 1998-09-25 | TEAM-CYMRU - Team Cymru Inc., US"
_DATA_LINE_2 = "15169   | 8.8.8.8         | 8.8.8.0/24          | US | arin     | 1992-12-01 | GOOGLE - Google LLC, US"


def _build_response(lines: list[str]) -> str:
    return _HEADER_LINE + "\n" + "\n".join(lines) + "\n"


# ── _parse_response_line — the caught-IndexError surface ─────────────


def test_parse_response_line_rejects_header():
    """The empty-string lstrip-then-split bug from authoring lived
    here. Pin so it can never come back silently."""
    assert _parse_response_line(_HEADER_LINE) is None


def test_parse_response_line_parses_real_response():
    parsed = _parse_response_line(_DATA_LINE_1)
    assert parsed is not None
    assert parsed["asn"] == "AS23028"
    assert parsed["ip"] == "216.90.108.31"
    assert parsed["bgp_prefix"] == "216.90.108.0/24"
    assert parsed["country_code"] == "US"
    assert parsed["registry"] == "arin"
    assert parsed["as_name"] == "TEAM-CYMRU - Team Cymru Inc., US"


def test_parse_response_line_handles_too_few_fields():
    assert _parse_response_line("23028 | 1.2.3.4") is None
    assert _parse_response_line("") is None
    assert _parse_response_line("not pipe-delimited") is None


def test_parse_response_line_already_AS_prefixed():
    """Some Cymru variants return the asn pre-prefixed; we shouldn't
    double-prefix to ASAS123."""
    line = "AS23028 | 216.90.108.31 | 216.90.108.0/24 | US | arin | 1998-09-25 | 2005-12-25 | TEAM-CYMRU"
    parsed = _parse_response_line(line)
    assert parsed is not None
    assert parsed["asn"] == "AS23028"
    assert not parsed["asn"].startswith("ASAS")


# ── Single-IP lookup ─────────────────────────────────────────────────


async def test_lookup_single_ip(monkeypatch):
    """End-to-end single-IP WHOIS query path."""
    text = _build_response([_DATA_LINE_1])

    async def _fake_query(query: str):
        # Single-IP queries start with " -v "
        assert query.startswith(" -v ")
        return text

    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(tc_mod, "_whois_query", _fake_query), \
         patch.object(tc_mod, "_from_cache", _miss), \
         patch.object(tc_mod, "_store_cache", _store):
        result = await lookup("216.90.108.31")

    assert isinstance(result, TeamCymruResult)
    assert result.success is True
    assert result.asn == "AS23028"
    assert result.country_code == "US"
    assert result.bgp_prefix == "216.90.108.0/24"


async def test_lookup_no_match(monkeypatch):
    """If WHOIS responds but no ASN matches, the result has
    success=True (WHOIS DID respond) but error explains."""
    text = _HEADER_LINE + "\n"  # header only, no data row

    async def _fake_query(query: str):
        return text

    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(tc_mod, "_whois_query", _fake_query), \
         patch.object(tc_mod, "_from_cache", _miss), \
         patch.object(tc_mod, "_store_cache", _store):
        result = await lookup("192.0.2.1")
    assert result.success is True
    assert result.asn is None
    assert "no ASN match" in (result.error or "")


async def test_lookup_network_failure(monkeypatch):
    """Connection failure must populate error, not raise."""
    async def _fake_query(query: str):
        raise ConnectionError("network down")

    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(tc_mod, "_whois_query", _fake_query), \
         patch.object(tc_mod, "_from_cache", _miss), \
         patch.object(tc_mod, "_store_cache", _store):
        result = await lookup("8.8.8.8")
    assert result.success is False
    assert "ConnectionError" in (result.error or "")


async def test_lookup_empty_input():
    result = await lookup("")
    assert result.success is False
    assert "empty" in (result.error or "").lower()


# ── Bulk lookup ──────────────────────────────────────────────────────


async def test_lookup_bulk_parses_multiple_ips(monkeypatch):
    """Bulk mode sends ONE TCP query for N IPs, parses N rows back."""
    text = _build_response([_DATA_LINE_1, _DATA_LINE_2])
    captured: dict[str, str] = {}

    async def _fake_query(query: str):
        # Bulk queries open with "begin\nverbose\n..."
        captured["q"] = query
        return text

    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(tc_mod, "_whois_query", _fake_query), \
         patch.object(tc_mod, "_from_cache", _miss), \
         patch.object(tc_mod, "_store_cache", _store):
        results = await lookup_bulk(["216.90.108.31", "8.8.8.8"])

    assert set(results.keys()) == {"216.90.108.31", "8.8.8.8"}
    assert results["216.90.108.31"].asn == "AS23028"
    assert results["8.8.8.8"].asn == "AS15169"
    # Bulk envelope was used
    assert "begin" in captured["q"]
    assert "verbose" in captured["q"]
    assert "end" in captured["q"]


async def test_lookup_bulk_skips_cached_ips(monkeypatch):
    """IPs already in cache must not appear in the bulk query
    payload."""
    text = _build_response([_DATA_LINE_2])  # only 8.8.8.8 in response
    captured: dict[str, str] = {}

    async def _fake_query(query: str):
        captured["q"] = query
        return text

    async def _hit_for_one(key: str):
        # Key is the redis cache key; extract IP from end.
        ip = key.rsplit(":", 1)[-1]
        if ip == "216.90.108.31":
            return TeamCymruResult(
                ip=ip, success=True, asn="AS23028", country_code="US",
                cached=True,
            )
        return None

    async def _store(*args, **kwargs):
        return None

    # _from_cache(ip) — wrap our hit_for_one
    async def _from_cache_proxy(ip):
        return await _hit_for_one(tc_mod._CACHE_KEY_PREFIX + ip)

    with patch.object(tc_mod, "_whois_query", _fake_query), \
         patch.object(tc_mod, "_from_cache", _from_cache_proxy), \
         patch.object(tc_mod, "_store_cache", _store):
        results = await lookup_bulk(["216.90.108.31", "8.8.8.8"])

    # Cached IP returns the cached result
    assert results["216.90.108.31"].cached is True
    # The bulk query payload should only contain the cache-miss IP
    assert "8.8.8.8" in captured["q"]
    assert "216.90.108.31" not in captured["q"]


async def test_lookup_bulk_empty_input_returns_empty():
    result = await lookup_bulk([])
    assert result == {}
    result = await lookup_bulk(["", None, ""])  # type: ignore[list-item]
    assert result == {}


async def test_lookup_bulk_failure_populates_errors(monkeypatch):
    """If the WHOIS connection fails, every cache-miss IP must be
    populated with success=False — not silently dropped."""
    async def _fake_query(query: str):
        raise OSError("conn refused")

    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(tc_mod, "_whois_query", _fake_query), \
         patch.object(tc_mod, "_from_cache", _miss), \
         patch.object(tc_mod, "_store_cache", _store):
        results = await lookup_bulk(["1.2.3.4", "5.6.7.8"])

    assert set(results.keys()) == {"1.2.3.4", "5.6.7.8"}
    assert all(not r.success for r in results.values())
    assert all("OSError" in (r.error or "") for r in results.values())
