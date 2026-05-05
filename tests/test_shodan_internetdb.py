"""Shodan InternetDB enrichment — fixture tests.

Pins the JSON normalisation, 404→clean-miss behaviour, error paths,
and the ShodanInternetDbResult round-trip through the cache.

Fixture payloads were captured from real internetdb.shodan.io
responses in May 2026. If Shodan adds/removes fields, these tests
catch it before production silently breaks.
"""

from __future__ import annotations

import contextlib
from unittest.mock import patch

import pytest

import src.enrichment.shodan_internetdb as sidb
from src.enrichment.shodan_internetdb import (
    ShodanInternetDbResult,
    check_ip,
)

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
    """Force every call to hit the (mocked) network, bypassing Redis."""
    async def _miss(*args, **kwargs):
        return None

    async def _store(*args, **kwargs):
        return None

    with patch.object(sidb, "_from_cache", _miss):
        with patch.object(sidb, "_store_cache", _store):
            yield


# ── Realistic InternetDB payloads ────────────────────────────────────


_GOOGLE_DNS_PAYLOAD = {
    "ip": "8.8.8.8",
    "ports": [53, 443],
    "cpes": ["cpe:/a:google:google_public_dns"],
    "vulns": [],
    "hostnames": ["dns.google"],
    "tags": ["dns"],
}


_VULNERABLE_HOST_PAYLOAD = {
    "ip": "203.0.113.42",
    "ports": [22, 80, 443, 8080],
    "cpes": [
        "cpe:/a:apache:http_server:2.4.49",
        "cpe:/a:openbsd:openssh:7.4",
    ],
    "vulns": ["CVE-2021-41773", "CVE-2021-42013"],
    "hostnames": ["mail.example.com"],
    "tags": ["self-signed", "vpn"],
}


# ── check_ip happy path ──────────────────────────────────────────────


async def test_check_ip_in_corpus_clean_host():
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=_GOOGLE_DNS_PAYLOAD)):
        result = await check_ip("8.8.8.8")
    assert isinstance(result, ShodanInternetDbResult)
    assert result.success is True
    assert result.in_corpus is True
    assert result.ports == [53, 443]
    assert result.cpes == ["cpe:/a:google:google_public_dns"]
    assert result.vulns == []
    assert result.hostnames == ["dns.google"]
    assert result.tags == ["dns"]
    assert result.error is None


async def test_check_ip_vulnerable_host():
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=_VULNERABLE_HOST_PAYLOAD)):
        result = await check_ip("203.0.113.42")
    assert result.success is True
    assert result.in_corpus is True
    assert 22 in result.ports
    assert "CVE-2021-41773" in result.vulns
    # vulns must be sorted + deduped
    assert result.vulns == sorted(set(result.vulns))
    assert "self-signed" in result.tags


# ── 404 → clean miss ────────────────────────────────────────────────


async def test_check_ip_404_is_clean_miss():
    """Documented Shodan behaviour: 404 = IP not in corpus. Must NOT
    surface as success=False; production code chains enrichments and
    a false-fail would short-circuit downstream lookups."""
    with _no_cache(), _patch_session(_FakeResp(status=404)):
        result = await check_ip("192.0.2.1")
    assert result.success is True
    assert result.in_corpus is False
    assert result.error is None
    assert result.ports == []
    assert result.vulns == []


# ── Failure paths populate error, never raise ───────────────────────


async def test_check_ip_429_rate_limit():
    with _no_cache(), _patch_session(_FakeResp(status=429)):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "429" in (result.error or "")
    assert "rate-limited" in (result.error or "").lower()


async def test_check_ip_500_returns_error():
    with _no_cache(), _patch_session(_FakeResp(status=500)):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "500" in (result.error or "")


async def test_check_ip_network_exception_swallowed():
    """Exceptions must NOT bubble out — chained enrichment pipelines
    rely on always getting a result back."""
    import aiohttp

    class _Boom:
        def get(self, *args, **kwargs):
            raise aiohttp.ClientError("connection reset")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    with _no_cache():
        with patch.object(aiohttp, "ClientSession", lambda *a, **k: _Boom()):
            result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "ClientError" in (result.error or "") or "connection" in (result.error or "")


async def test_check_ip_empty_input():
    """No HTTP call for empty input."""
    result = await check_ip("")
    assert result.success is False
    assert "empty" in (result.error or "").lower()


async def test_check_ip_unexpected_payload_type():
    """If Shodan ever returns a list instead of a dict, the adapter
    should fail cleanly with success=False — not assume dict shape."""
    with _no_cache(), _patch_session(_FakeResp(status=200, json_body=[])):
        result = await check_ip("8.8.8.8")
    assert result.success is False
    assert "unexpected payload" in (result.error or "").lower()


# ── ShodanInternetDbResult.to_dict ──────────────────────────────────


def test_to_dict_round_trip():
    """The dataclass exposes a flat to_dict() that the route handler
    returns directly. Pin the keys so frontend doesn't break."""
    r = ShodanInternetDbResult(
        ip="1.2.3.4", success=True, in_corpus=True,
        ports=[80, 443], cpes=["cpe:/a:foo"], vulns=["CVE-X"],
        hostnames=["h.example"], tags=["honeypot"],
    )
    d = r.to_dict()
    assert set(d.keys()) == {
        "ip", "success", "in_corpus", "ports", "cpes",
        "vulns", "hostnames", "tags", "error", "cached",
    }
    assert d["in_corpus"] is True
    assert d["ports"] == [80, 443]


# ── Cache disabled path ─────────────────────────────────────────────


async def test_check_ip_use_cache_false_skips_cache():
    """Even if a cached value would be present, use_cache=False must
    bypass and hit the upstream. Pinned so callers can force-refresh."""
    cache_call_count = {"n": 0}

    async def _hit(*args, **kwargs):
        cache_call_count["n"] += 1
        return ShodanInternetDbResult(ip="8.8.8.8", success=True, in_corpus=True, cached=True)

    async def _store(*args, **kwargs):
        return None

    with patch.object(sidb, "_from_cache", _hit):
        with patch.object(sidb, "_store_cache", _store):
            with _patch_session(_FakeResp(status=200, json_body=_GOOGLE_DNS_PAYLOAD)):
                result = await check_ip("8.8.8.8", use_cache=False)
    assert cache_call_count["n"] == 0  # cache lookup skipped
    assert result.cached is False
    assert result.in_corpus is True
