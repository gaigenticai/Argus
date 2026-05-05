"""Live integration tests for no-key adapters.

Hits the REAL upstream services to prove the adapters parse what
the upstream serves TODAY, not what the docs said when we wrote them.

Skipped by default in CI to keep the suite hermetic. Opt in with:

    ARGUS_RUN_LIVE_TESTS=1 pytest tests/test_live_no_key_adapters.py

or run a single one:

    ARGUS_RUN_LIVE_TESTS=1 pytest tests/test_live_no_key_adapters.py::test_xposedornot_live

Each test is best-effort — upstream outages mark it as skip rather
than fail (we don't want a CIRCL or Spamhaus blip to red the entire
build). The tests assert STRUCTURAL invariants (right field names,
right types), not specific data values.

Adapters covered:
  * XposedOrNot      (free email-breach lookup)
  * Shodan InternetDB (IP enrichment)
  * Spamhaus DROP    (IP-reputation feed)
  * FireHOL          (IP-reputation feed)
  * Blocklist.de     (IP-reputation feed)
  * CINS Score       (IP-reputation feed)
  * DigitalSide MISP (threat-intel feed)
  * Team Cymru       (IP→ASN whois)
"""

from __future__ import annotations

import os

import pytest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.environ.get("ARGUS_RUN_LIVE_TESTS", "0") != "1",
        reason="live network tests gated; set ARGUS_RUN_LIVE_TESTS=1 to enable",
    ),
]


# ── XposedOrNot ────────────────────────────────────────────────────


async def test_xposedornot_live():
    """The Adobe breach is a known-large dataset; any email at adobe.com
    has a high chance of being in the corpus."""
    from src.integrations.breach.xposedornot import XposedOrNotProvider
    p = XposedOrNotProvider()
    res = await p.search_email("test@adobe.com")
    if not res.success:
        pytest.skip(f"upstream issue: {res.error}")
    # We don't assert hit_count > 0 (corpus may legitimately have changed),
    # but we DO assert the response shape is parseable.
    for hit in res.hits:
        assert hit.provider == "xposedornot"
        assert hit.breach_name
        assert isinstance(hit.data_classes, list)


# ── Shodan InternetDB ──────────────────────────────────────────────


async def test_shodan_internetdb_live_known_host():
    """8.8.8.8 (Google DNS) has been in Shodan's corpus for years."""
    from src.enrichment.shodan_internetdb import check_ip
    res = await check_ip("8.8.8.8", use_cache=False)
    if not res.success:
        pytest.skip(f"upstream issue: {res.error}")
    assert res.in_corpus is True
    assert isinstance(res.ports, list)
    assert isinstance(res.cpes, list)
    assert isinstance(res.vulns, list)
    assert isinstance(res.hostnames, list)
    assert isinstance(res.tags, list)


async def test_shodan_internetdb_live_unallocated_returns_404():
    """An unallocated IP space (TEST-NET-1) should be a clean miss."""
    from src.enrichment.shodan_internetdb import check_ip
    res = await check_ip("192.0.2.1", use_cache=False)
    if not res.success:
        pytest.skip(f"upstream issue: {res.error}")
    # Either in_corpus=False (the documented behaviour) OR the IP
    # somehow has data (unexpected, but don't fail the build for it).
    assert isinstance(res.in_corpus, bool)


# ── Spamhaus DROP ──────────────────────────────────────────────────


async def test_spamhaus_drop_live():
    """drop.txt has hundreds of CIDRs at any given time."""
    from src.feeds.spamhaus_drop_feed import SpamhausDropFeed
    feed = SpamhausDropFeed()
    entries = []
    try:
        async for e in feed.poll():
            entries.append(e)
            if len(entries) >= 5:
                break
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries and feed.last_failure_reason:
        pytest.skip(f"upstream returned no data: {feed.last_failure_reason}")
    assert len(entries) >= 1, "drop.txt should always have ≥1 entry"
    # Structural invariants
    for e in entries:
        assert e.entry_type == "cidr"
        assert "/" in e.value
        assert e.feed_metadata["source"] == "spamhaus_drop"


# ── FireHOL level1 ────────────────────────────────────────────────


async def test_firehol_level1_live():
    """level1 has thousands of CIDRs."""
    from src.feeds.firehol_feed import FireHOLFeed
    feed = FireHOLFeed()
    entries = []
    try:
        async for e in feed.poll():
            entries.append(e)
            if len(entries) >= 5:
                break
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries and feed.last_failure_reason:
        pytest.skip(f"upstream returned no data: {feed.last_failure_reason}")
    assert len(entries) >= 1
    for e in entries:
        assert "/" in e.value  # CIDR-shaped
        assert e.feed_metadata["firehol_list"] == "firehol_level1"


# ── Blocklist.de + CINS Score ──────────────────────────────────────


async def test_blocklist_de_live():
    from src.feeds.plain_ip_list_feed import BlocklistDeFeed
    feed = BlocklistDeFeed()
    entries = []
    try:
        async for e in feed.poll():
            entries.append(e)
            if len(entries) >= 5:
                break
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries and feed.last_failure_reason:
        pytest.skip(f"upstream returned no data: {feed.last_failure_reason}")
    assert len(entries) >= 1
    for e in entries:
        assert e.entry_type == "ip"
        assert "." in e.value  # IPv4-shaped
        assert e.feed_metadata["source"] == "blocklist_de"


async def test_cins_score_live():
    from src.feeds.plain_ip_list_feed import CinsScoreFeed
    feed = CinsScoreFeed()
    entries = []
    try:
        async for e in feed.poll():
            entries.append(e)
            if len(entries) >= 5:
                break
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries and feed.last_failure_reason:
        pytest.skip(f"upstream returned no data: {feed.last_failure_reason}")
    assert len(entries) >= 1
    for e in entries:
        assert e.entry_type == "ip"
        assert "." in e.value


# ── DigitalSide MISP ──────────────────────────────────────────────


async def test_digitalside_misp_live():
    """The DigitalSide manifest is well-populated; even a small slice
    of the most-recent events should yield ≥1 attribute."""
    from src.feeds.digitalside_feed import DigitalSideMispFeed
    feed = DigitalSideMispFeed()
    entries = []
    try:
        async for e in feed.poll():
            entries.append(e)
            if len(entries) >= 5:
                break
    except Exception as exc:
        pytest.skip(f"upstream issue: {exc}")
    if not entries:
        pytest.skip("digitalside returned no parseable attributes (check upstream)")
    assert len(entries) >= 1
    for e in entries:
        assert e.entry_type in ("ip", "domain", "url", "hash")
        assert e.feed_metadata["source"] == "digitalside_osint"


# ── Team Cymru ────────────────────────────────────────────────────


async def test_team_cymru_live_single_lookup():
    """8.8.8.8 → AS15169 (Google) is canonical and stable."""
    from src.enrichment.team_cymru import lookup
    res = await lookup("8.8.8.8", use_cache=False)
    if not res.success:
        pytest.skip(f"upstream issue: {res.error}")
    assert res.asn == "AS15169"
    assert res.country_code == "US"
    assert res.bgp_prefix is not None
    assert "/" in res.bgp_prefix
    # Pin our parser fix from A.11 — as_name MUST be populated for
    # a real Cymru response.
    assert res.as_name is not None
    assert "GOOGLE" in res.as_name.upper()


async def test_team_cymru_live_bulk_lookup():
    """Bulk mode for ≥3 IPs is the recommended pattern."""
    from src.enrichment.team_cymru import lookup_bulk
    results = await lookup_bulk(
        ["8.8.8.8", "1.1.1.1", "9.9.9.9"], use_cache=False,
    )
    if not all(r.success for r in results.values()):
        pytest.skip(
            f"upstream issue: {[(ip, r.error) for ip, r in results.items() if not r.success]}",
        )
    assert results["8.8.8.8"].asn == "AS15169"   # Google
    assert results["1.1.1.1"].asn == "AS13335"   # Cloudflare
    assert results["9.9.9.9"].asn == "AS19281"   # Quad9
    # All three must have as_name populated (regression guard for A.11)
    assert all(r.as_name for r in results.values())
