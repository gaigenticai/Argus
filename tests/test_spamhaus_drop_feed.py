"""Spamhaus DROP feed — fixture tests.

Pins the drop.txt parser: comment lines skipped, CIDR + SBL refs
extracted into the SBL pivot URL, malformed lines defended against.

Fixture content was captured verbatim from the live drop.txt header
+ a mix of real-style data lines in May 2026.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from src.feeds.spamhaus_drop_feed import SpamhausDropFeed

pytestmark = pytest.mark.asyncio


_SAMPLE_DROP_TXT = """\
; Spamhaus DROP List 2026/04/24 - (c) 2026 The Spamhaus Project SLU
; https://www.spamhaus.org/drop/drop.txt
; Last-Modified: Thu, 24 Apr 2026 14:32:55 GMT
; Expires: Thu, 24 Apr 2026 15:32:55 GMT
1.10.16.0/20 ; SBL256894
1.19.0.0/16 ; SBL387990
2.56.192.0/22 ; SBL567123

; another comment in the middle
5.42.69.0/24 ; SBL123456
# hash-style comment too
192.0.2.0/24
not-a-cidr-line
"""


async def _collect(feed):
    return [e async for e in feed.poll()]


def _patch_lines(feed, text):
    """Replace _fetch_csv_lines with our fixture text split into lines."""
    async def _fake(*args, **kwargs):
        return text.splitlines(keepends=False)

    return patch.object(feed, "_fetch_csv_lines", _fake)


# ── Parser happy path ──────────────────────────────────────────────


async def test_poll_extracts_cidrs_with_sbl_refs():
    feed = SpamhausDropFeed()
    with _patch_lines(feed, _SAMPLE_DROP_TXT):
        entries = await _collect(feed)

    # 5 valid CIDRs in the fixture (4 with SBL refs, 1 bare).
    # The 'not-a-cidr-line' is skipped because it has no slash.
    cidrs = [e.value for e in entries]
    assert "1.10.16.0/20" in cidrs
    assert "1.19.0.0/16" in cidrs
    assert "2.56.192.0/22" in cidrs
    assert "5.42.69.0/24" in cidrs
    assert "192.0.2.0/24" in cidrs  # bare CIDR with no SBL still ingests
    assert len(entries) == 5


async def test_poll_attaches_sbl_pivot_url():
    feed = SpamhausDropFeed()
    with _patch_lines(feed, _SAMPLE_DROP_TXT):
        entries = await _collect(feed)

    by_value = {e.value: e for e in entries}
    e = by_value["1.10.16.0/20"]
    assert e.feed_metadata["sbl_reference"] == "SBL256894"
    assert e.feed_metadata["sbl_url"] == "https://www.spamhaus.org/sbl/query/SBL256894"
    assert e.entry_type == "cidr"
    assert e.severity == "high"


async def test_poll_handles_bare_cidr_with_no_sbl():
    feed = SpamhausDropFeed()
    with _patch_lines(feed, _SAMPLE_DROP_TXT):
        entries = await _collect(feed)

    by_value = {e.value: e for e in entries}
    bare = by_value["192.0.2.0/24"]
    assert bare.feed_metadata["sbl_reference"] is None
    assert bare.feed_metadata["sbl_url"] is None


async def test_poll_skips_comment_lines():
    feed = SpamhausDropFeed()
    with _patch_lines(feed, _SAMPLE_DROP_TXT):
        entries = await _collect(feed)
    # All emitted entries must have a CIDR; comment-line content
    # ("Spamhaus DROP List") must NOT appear as a value.
    for e in entries:
        assert "/" in e.value
        assert "Spamhaus" not in e.value
        assert not e.value.startswith(";")
        assert not e.value.startswith("#")


async def test_poll_skips_lines_without_slash():
    """Defensive — a malformed line missing CIDR notation must not
    blow up the tick."""
    feed = SpamhausDropFeed()
    with _patch_lines(feed, _SAMPLE_DROP_TXT):
        entries = await _collect(feed)
    cidrs = [e.value for e in entries]
    assert "not-a-cidr-line" not in cidrs


async def test_poll_marks_failure_on_empty_response():
    """A genuinely empty response (e.g. upstream 5xx returning nothing)
    must mark a failure_reason so the feed_health row reflects it."""
    feed = SpamhausDropFeed()
    with _patch_lines(feed, ""):
        entries = await _collect(feed)
    assert entries == []
    assert feed.last_failure_reason
    assert "no data" in feed.last_failure_reason.lower()


async def test_poll_attaches_short_ttl_for_rotation():
    """DROP rotates daily; entries should have a short-ish TTL so
    de-listed CIDRs age out."""
    feed = SpamhausDropFeed()
    with _patch_lines(feed, _SAMPLE_DROP_TXT):
        entries = await _collect(feed)
    for e in entries:
        # 7 days = 168h; current value
        assert e.expires_hours == 168
