"""FireHOL aggregated IP-list feed — fixture tests.

Pins the .netset parser, list_label extraction from URL, bare-IPv4
→ /32 normalisation, and ARGUS_FEED_FIREHOL_URL override.

Fixture content was captured verbatim from the live
firehol_level1.netset header in May 2026.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from src.feeds.firehol_feed import FireHOLFeed

pytestmark = pytest.mark.asyncio


_SAMPLE_LEVEL1_NETSET = """\
#
# firehol_level1
#
# ipv4 hash:net ipset
#
# A firewall blacklist composed from IP lists, providing
# maximum protection with minimum false positives. Suitable
# for basic protection on all internet facing servers,
# routers and firewalls. (includes: dshield feodo fullbogons
# spamhaus_drop)
#
# Maintainer      : FireHOL
# Maintainer URL  : http://iplists.firehol.org/
# List source URL :
# Source File Date: Sat May  2 20:55:03 UTC 2026
#
# Category        : attacks
# Version         : 32258
#
# This File Date  : Sat May  2 21:42:17 UTC 2026
# Update Frequency: 1 min
# Aggregation     : none
# Entries         : 3753 subnets, 611405121 unique IPs
#
0.0.0.0/8
1.10.16.0/20
1.19.0.0/16
198.51.100.42
2.56.192.0/22
"""


async def _collect(feed):
    return [e async for e in feed.poll()]


def _patch_lines(feed, text):
    async def _fake(*args, **kwargs):
        return text.splitlines(keepends=False)

    return patch.object(feed, "_fetch_csv_lines", _fake)


# ── Parser happy path ──────────────────────────────────────────────


async def test_poll_parses_level1_netset():
    feed = FireHOLFeed()
    with _patch_lines(feed, _SAMPLE_LEVEL1_NETSET):
        entries = await _collect(feed)

    cidrs = [e.value for e in entries]
    assert "0.0.0.0/8" in cidrs
    assert "1.10.16.0/20" in cidrs
    assert "1.19.0.0/16" in cidrs
    assert "2.56.192.0/22" in cidrs
    # Bare IP normalised to /32
    assert "198.51.100.42/32" in cidrs
    assert len(entries) == 5


async def test_poll_skips_comment_block():
    """The fixture has 23 comment lines; none should bleed into
    entries."""
    feed = FireHOLFeed()
    with _patch_lines(feed, _SAMPLE_LEVEL1_NETSET):
        entries = await _collect(feed)
    for e in entries:
        assert "#" not in e.value
        assert "FireHOL" not in e.value
        # All emitted entries are CIDR-shaped
        assert "/" in e.value


async def test_poll_extracts_list_label_from_default_url():
    feed = FireHOLFeed()
    # Default URL → firehol_level1
    label = feed._list_label_from_url(feed._resolve_url())
    assert label == "firehol_level1"


async def test_poll_attaches_list_label_to_entries(monkeypatch):
    feed = FireHOLFeed()
    with _patch_lines(feed, _SAMPLE_LEVEL1_NETSET):
        entries = await _collect(feed)
    for e in entries:
        assert e.feed_metadata["firehol_list"] == "firehol_level1"
        assert "FireHOL firehol_level1:" in e.label
        assert e.entry_type == "cidr"
        assert e.severity == "high"


async def test_poll_respects_url_env_override(monkeypatch):
    """When ARGUS_FEED_FIREHOL_URL points at level3, list_label flips."""
    monkeypatch.setenv(
        "ARGUS_FEED_FIREHOL_URL",
        "https://iplists.firehol.org/files/firehol_level3.netset",
    )
    feed = FireHOLFeed()
    label = feed._list_label_from_url(feed._resolve_url())
    assert label == "firehol_level3"

    with _patch_lines(feed, _SAMPLE_LEVEL1_NETSET):
        entries = await _collect(feed)
    for e in entries:
        assert e.feed_metadata["firehol_list"] == "firehol_level3"


async def test_poll_marks_failure_on_empty_response():
    feed = FireHOLFeed()
    with _patch_lines(feed, ""):
        entries = await _collect(feed)
    assert entries == []
    assert feed.last_failure_reason
    assert "no data" in feed.last_failure_reason.lower()


async def test_poll_handles_inline_whitespace_in_data_lines():
    """Some FireHOL forks include a count after the CIDR; we take only
    the first whitespace-separated token."""
    feed = FireHOLFeed()
    text = "10.0.0.0/8 #count=999\n# comment\n11.0.0.0/8 some-trailing"
    with _patch_lines(feed, text):
        entries = await _collect(feed)
    cidrs = [e.value for e in entries]
    assert "10.0.0.0/8" in cidrs
    assert "11.0.0.0/8" in cidrs
