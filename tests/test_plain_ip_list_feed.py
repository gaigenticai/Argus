"""Plain IPv4 list feed pattern — fixture tests for the base + the two
production subclasses (Blocklist.de + CINS Score).

Pins the IPv4 validation, IPv6 skip, malformed-line skip, and the
per-subclass severity / confidence / description-template differences.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from src.feeds.plain_ip_list_feed import (
    BlocklistDeFeed,
    CinsScoreFeed,
    PlainIpListFeed,
)

pytestmark = pytest.mark.asyncio


_SAMPLE_PLAIN_IP_LIST = """\
# blocklist.de all.txt sample
1.0.143.115
1.0.143.71
1.10.226.10
2001:db8::1
not-an-ip
::1
192.168.1.1

# trailing comment
"""


async def _collect(feed):
    return [e async for e in feed.poll()]


def _patch_lines(feed, text):
    async def _fake(*args, **kwargs):
        return text.splitlines(keepends=False)

    return patch.object(feed, "_fetch_csv_lines", _fake)


# ── Base parser ─────────────────────────────────────────────────────


async def test_base_class_requires_feed_url():
    """An accidentally-instantiated base class with no URL should
    fail loudly via last_failure_reason, not silently no-op."""
    feed = PlainIpListFeed()
    feed.name = "test_base"
    entries = await _collect(feed)
    assert entries == []
    assert feed.last_failure_reason
    assert "feed_url" in feed.last_failure_reason


async def test_blocklist_de_parses_ipv4_only():
    feed = BlocklistDeFeed()
    with _patch_lines(feed, _SAMPLE_PLAIN_IP_LIST):
        entries = await _collect(feed)
    values = [e.value for e in entries]
    # 4 valid IPv4s in the fixture (3 routable + 1 RFC1918 192.168.1.1)
    assert "1.0.143.115" in values
    assert "1.0.143.71" in values
    assert "1.10.226.10" in values
    assert "192.168.1.1" in values
    # IPv6 must be silently skipped
    assert "2001:db8::1" not in values
    assert "::1" not in values
    # malformed line skipped
    assert "not-an-ip" not in values
    assert len(entries) == 4


async def test_blocklist_de_attaches_correct_metadata():
    feed = BlocklistDeFeed()
    with _patch_lines(feed, "1.2.3.4\n5.6.7.8"):
        entries = await _collect(feed)
    e = entries[0]
    assert e.entry_type == "ip"
    assert e.feed_name == "blocklist_de"
    assert e.severity == "high"
    assert e.confidence == 0.85
    assert e.feed_metadata["source"] == "blocklist_de"
    assert "blocklist.de" in e.label
    assert "honeypots" in e.description.lower()
    assert e.expires_hours == 72


async def test_cins_score_distinct_from_blocklist_de():
    """CinsScoreFeed must produce different feed_name + label +
    description so analysts can pivot by source."""
    feed = CinsScoreFeed()
    with _patch_lines(feed, "1.2.3.4"):
        entries = await _collect(feed)
    e = entries[0]
    assert e.feed_name == "cins_score"
    assert "CINS Army" in e.label
    assert "Sentinel IPS" in e.description
    assert e.confidence == 0.8  # different from blocklist.de's 0.85


async def test_skips_comment_lines():
    feed = BlocklistDeFeed()
    text = "# header\n; semicolon comment\n1.2.3.4\n"
    with _patch_lines(feed, text):
        entries = await _collect(feed)
    assert len(entries) == 1
    assert entries[0].value == "1.2.3.4"


async def test_handles_empty_response():
    feed = BlocklistDeFeed()
    with _patch_lines(feed, ""):
        entries = await _collect(feed)
    assert entries == []
    assert feed.last_failure_reason
    assert "no data" in feed.last_failure_reason.lower()


async def test_inline_whitespace_token_split():
    """Some plain-IP lists include comments after the IP. Take the
    first whitespace token."""
    feed = BlocklistDeFeed()
    with _patch_lines(feed, "1.2.3.4 # caught at 2026-05-01\n"):
        entries = await _collect(feed)
    assert len(entries) == 1
    assert entries[0].value == "1.2.3.4"
