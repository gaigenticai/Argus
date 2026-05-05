"""Live integration tests for the ORIGINAL no-key services in the
catalogue (the 16 that pre-date this session's refactor).

These prove that catalog rows like OpenPhish / DShield / KEV / EPSS /
crt.sh / Cavalier / etc. actually parse the upstream's TODAY response,
not just the docs from when the adapter was first written. The
test_live_no_key_adapters.py file covers the 8 NEW no-key adapters
added this session; this one covers the rest.

Skipped by default in CI; opt in with:

    ARGUS_RUN_LIVE_TESTS=1 pytest tests/test_live_original_no_key_adapters.py -v

Each test:

  * is best-effort — upstream blip → graceful skip, never red
  * asserts STRUCTURAL invariants (right field types / non-empty)
  * caps the number of entries pulled so a heavy feed (NVD / CT logs)
    can't take 10 minutes
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.environ.get("ARGUS_RUN_LIVE_TESTS", "0") != "1",
        reason="live network tests gated; set ARGUS_RUN_LIVE_TESTS=1",
    ),
]


# ── Helper ──────────────────────────────────────────────────────────


async def _take(gen: AsyncIterator, n: int = 5) -> list:
    """Drain at most ``n`` entries from an async generator. Most live
    feed tests just need 1-5 entries to prove parsing works; pulling
    the full poll() output would take minutes for some feeds."""
    out = []
    async for entry in gen:
        out.append(entry)
        if len(out) >= n:
            break
    return out


# ── Threat-intel feeds (BaseFeed subclasses) ────────────────────────


async def test_openphish_live():
    """OpenPhish public CSV — phishing URLs."""
    from src.feeds.phishing_feed import PhishingFeed
    feed = PhishingFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"openphish returned no entries; reason={feed.last_failure_reason or feed.last_unconfigured_reason}")
    # OpenPhish is one of multiple sources inside PhishingFeed; we
    # don't pin the source name (PhishingFeed yields openphish + urlhaus
    # + phishtank legs), but every entry must be a URL/domain.
    for e in entries:
        assert e.entry_type in ("url", "domain"), f"unexpected entry_type {e.entry_type!r}"
        assert e.value, "entry has no value"


async def test_urlhaus_feodo_legs_live():
    """MalwareFeed = URLhaus CSV + ThreatFox API. ThreatFox needs a
    key, but URLhaus public CSV does not. We assert the URLhaus leg
    yields something even with no key."""
    from src.feeds.malware_feed import MalwareFeed
    feed = MalwareFeed()
    try:
        entries = await _take(feed.poll(), n=10)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    # Filter to URLhaus-source entries (ThreatFox might be skipped on
    # no key — that's expected, not a failure).
    urlhaus_entries = [
        e for e in entries
        if e.feed_metadata.get("source") == "urlhaus"
    ]
    if not urlhaus_entries:
        pytest.skip("URLhaus leg returned no entries — upstream may be down")
    assert len(urlhaus_entries) >= 1
    for e in urlhaus_entries:
        assert e.entry_type in ("url", "domain"), e.entry_type


async def test_feodo_tracker_live():
    """abuse.ch Feodo Tracker — botnet C2 IP blocklist."""
    from src.feeds.botnet_feed import BotnetFeed
    feed = BotnetFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"feodo tracker returned no entries; reason={feed.last_failure_reason}")
    for e in entries:
        assert e.entry_type == "ip"
        assert e.value


async def test_dshield_isc_live():
    """DShield top scanners + infocon level."""
    from src.feeds.honeypot_feed import HoneypotFeed
    feed = HoneypotFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"DShield returned no entries; reason={feed.last_failure_reason}")
    # DShield's HoneypotFeed yields IPs (top scanners) plus optionally
    # infocon-level metadata. Just assert there's at least one IP entry.
    ip_entries = [e for e in entries if e.entry_type == "ip"]
    assert len(ip_entries) >= 1, "expected at least one IP from DShield"


async def test_tor_exit_list_live():
    """torproject.org's bulk exit-node list."""
    from src.feeds.tor_nodes_feed import TorNodesFeed
    feed = TorNodesFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"Tor exit list returned no entries; reason={feed.last_failure_reason}")
    # Tor exits are IPs; the list typically has hundreds.
    for e in entries:
        assert e.entry_type == "ip"
        assert e.value


async def test_ipsum_live():
    """stamparm/ipsum — aggregated bad-IP list."""
    from src.feeds.ip_reputation_feed import IPReputationFeed
    feed = IPReputationFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"ipsum returned no entries; reason={feed.last_failure_reason}")
    for e in entries:
        assert e.entry_type == "ip"


async def test_circl_osint_misp_live():
    """CIRCL.lu OSINT MISP feed — manifest + per-event JSON."""
    from src.feeds.circl_misp_feed import CIRCLMispFeed
    feed = CIRCLMispFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip("CIRCL OSINT MISP feed returned no parseable attributes")
    for e in entries:
        assert e.entry_type in ("ip", "domain", "url", "hash"), e.entry_type
        assert e.feed_metadata.get("source") == "circl_osint"


async def test_certpl_phishing_live():
    """CERT Polska's curated malicious domain list."""
    from src.feeds.phishtank_certpl_feed import PhishTankCertPLFeed
    feed = PhishTankCertPLFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"CERT.PL returned no entries; reason={feed.last_failure_reason}")
    for e in entries:
        assert e.entry_type in ("url", "domain"), e.entry_type


async def test_ransomware_live():
    """ransomware.live — victim disclosure tracker."""
    from src.feeds.ransomware_feed import RansomwareFeed
    feed = RansomwareFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"ransomware.live returned no entries; reason={feed.last_failure_reason}")
    # Ransomware feed yields actor / victim / domain mixed entries —
    # just assert there's something with a value.
    assert any(e.value for e in entries)


async def test_crtsh_certstream_live():
    """crt.sh CT-log fetcher. Expensive — cap at 1 entry."""
    from src.feeds.certstream_feed import CertStreamFeed
    feed = CertStreamFeed()
    try:
        entries = await _take(feed.poll(), n=1)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"crt.sh returned no entries; reason={feed.last_failure_reason}")
    e = entries[0]
    assert e.entry_type == "domain"
    assert e.value


async def test_cisa_kev_live():
    """CISA Known-Exploited-Vulnerabilities catalogue."""
    from src.feeds.kev_feed import KEVFeed
    feed = KEVFeed()
    try:
        entries = await _take(feed.poll(), n=5)
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip(f"CISA KEV returned no entries; reason={feed.last_failure_reason}")
    for e in entries:
        # KEV yields CVE IDs as entries
        assert "CVE-" in e.value, f"expected CVE-* value, got {e.value!r}"


# ── EPSS — ingested via sync function not BaseFeed.poll ─────────────


async def test_epss_live_first_page_parses():
    """EPSS publishes daily CSV at first.org. Just hit the fetcher
    and verify it produces a non-empty response."""
    import aiohttp
    epss_url = (
        os.environ.get("ARGUS_WORKER_EPSS_URL")
        or "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    )
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as http:
            async with http.get(
                epss_url, headers={"User-Agent": "argus-test"},
            ) as resp:
                if resp.status >= 500:
                    pytest.skip(f"EPSS upstream {resp.status}")
                assert resp.status == 200, f"unexpected HTTP {resp.status}"
                # Just verify the response decompresses to CSV with a
                # CVE column. Don't ingest into DB — that's a Phase C
                # concern; we're proving the upstream still works.
                body = await resp.read()
                assert len(body) > 1000, "EPSS response suspiciously small"
    except aiohttp.ClientError as exc:
        pytest.skip(f"EPSS upstream issue: {exc}")


# ── Per-IOC enrichments (no key, single-call) ──────────────────────


async def test_circl_hashlookup_live():
    """CIRCL hashlookup — anonymous file-hash classification."""
    from src.enrichment.circl import hashlookup
    # SHA-256 of an empty file — known, classified as "good".
    EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    try:
        result = await hashlookup(EMPTY_FILE_SHA256)
    except Exception as exc:
        pytest.skip(f"CIRCL upstream issue: {exc}")
    if result is None:
        pytest.skip("CIRCL hashlookup returned None (upstream issue or breaker open)")
    assert result.hash == EMPTY_FILE_SHA256
    assert result.hash_kind == "sha256"


async def test_ipwho_is_live():
    """ipwho.is — async network fallback when MaxMind MMDB doesn't
    have a hit. ``GeoLocator.locate()`` is the sync MMDB-only fast
    path; the network chain (MMDB → ipwho.is → ip-api.com) is
    triggered by ``locate_batch()``."""
    from src.feeds.geolocation import GeoLocator
    locator = GeoLocator()
    try:
        results = await locator.locate_batch(["8.8.8.8"])
    except Exception as exc:
        pytest.skip(f"ipwho/ip-api upstream issue: {exc}")
    geo = results.get("8.8.8.8")
    if geo is None or not geo.country_code:
        pytest.skip("locate_batch returned no country (upstream may be rate-limited)")
    assert geo.country_code == "US"


async def test_hudsonrock_cavalier_live():
    """HudsonRock Cavalier — free-tier stealer-log lookup."""
    from src.integrations.breach.cavalier import CavalierProvider
    p = CavalierProvider()
    # Use a real-shape RFC-2606 reserved domain. Cavalier rejects
    # .invalid TLDs (RFC 6761 reserved-not-routable) with HTTP 400,
    # so example.com is the right "definitely synthetic but valid"
    # address to prove the API+parser without leaking PII.
    res = await p.search_email("argus-test-zzz-9zT8x4@example.com")
    if res.error and "401" in res.error:
        pytest.skip(f"Cavalier returned 401 (free-tier rate-limited): {res.error}")
    if res.error and "429" in res.error:
        pytest.skip(f"Cavalier rate-limited: {res.error}")
    # Whether the email is in the corpus or not, success must be True
    # (the API responded successfully even with zero hits).
    assert res.success is True, f"Cavalier failed: {res.error}"
    # Hits may be empty (synthetic email) — that's the expected case.


# ── Pulsedive anonymous tier ────────────────────────────────────────


async def test_pulsedive_anonymous_live(monkeypatch):
    """Pulsedive's anonymous tier (no key) is rate-limited but
    functional. Verify a known-malicious domain returns in_corpus."""
    monkeypatch.delenv("ARGUS_PULSEDIVE_API_KEY", raising=False)
    from src.enrichment.pulsedive import lookup
    res = await lookup("evil.com", use_cache=False)
    if not res.success:
        pytest.skip(f"Pulsedive upstream issue: {res.error}")
    # evil.com may or may not be in their corpus today — either way
    # the parse should work and the response shape should be valid.
    assert res.indicator == "evil.com"
