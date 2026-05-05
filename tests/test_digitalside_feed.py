"""DigitalSide OSINT MISP feed — fixture tests.

Pins the manifest → per-event fetch → MISP attribute parser pipeline.
Realistic shapes from osint.digitalside.it MISP feed format.

Catches: MISP type→entry_type mapping drift, threat-level → severity
drift, filename|hash composite split bug, missing-Attribute defence.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from src.feeds.digitalside_feed import (
    DigitalSideMispFeed,
    _MISP_TYPE_MAP,
)

pytestmark = pytest.mark.asyncio


_MANIFEST = {
    "abc123-event-uuid-1": {"timestamp": "1735689600", "info": "Lumma C2"},
    "def456-event-uuid-2": {"timestamp": "1735603200", "info": "Emotet IOCs"},
    # Older event — should be sorted to end
    "ghi789-event-uuid-3": {"timestamp": "1700000000", "info": "Older"},
}


def _make_event(info: str, threat_level: str, attributes: list[dict]) -> dict:
    return {
        "Event": {
            "info": info,
            "threat_level_id": threat_level,
            "date": "2026-04-30",
            "Attribute": attributes,
        },
    }


_EVENT_1 = _make_event(
    "Lumma C2",
    "1",  # critical
    [
        {"type": "ip-dst", "value": "203.0.113.50", "comment": "C2 server"},
        {"type": "domain", "value": "evil.example.com"},
        {
            "type": "filename|sha256",
            "value": "loader.exe|" + "a" * 64,
        },
        # Unmapped MISP type — should be skipped, not crash
        {"type": "vulnerability", "value": "CVE-9999-9999"},
        {"type": "url", "value": "http://evil.example.com/payload"},
        # Empty value — skip
        {"type": "ip-src", "value": ""},
        # Missing 'value' field — skip
        {"type": "domain"},
        # Non-dict — skip
        "garbage",
    ],
)


_EVENT_2 = _make_event(
    "Emotet IOCs",
    "3",  # medium
    [{"type": "md5", "value": "f" * 32}],
)


# Older event we don't expect to be included by default (limit 25 is
# fine here, just illustrating the sort).
_EVENT_3 = _make_event("Older", "4", [{"type": "domain", "value": "old.example.com"}])


async def _collect(feed):
    return [e async for e in feed.poll()]


def _patch_fetches(feed, manifest, events_by_uuid):
    """Make _fetch_json route based on URL: manifest URL → manifest;
    event URL → matching event by uuid (extracted from URL)."""
    async def _fake(url, *args, **kwargs):
        if "manifest.json" in url:
            return manifest
        # Extract uuid from URL trailing /<uuid>.json
        for uuid, payload in events_by_uuid.items():
            if uuid in url:
                return payload
        return None

    return patch.object(feed, "_fetch_json", _fake)


# ── Type mapping is the high-risk surface ───────────────────────────


def test_misp_type_map_pins_known_mappings():
    """Pin the mapping table — silent drift here causes whole event
    types to disappear from feed_health rows."""
    assert _MISP_TYPE_MAP["ip-src"] == "ip"
    assert _MISP_TYPE_MAP["ip-dst"] == "ip"
    assert _MISP_TYPE_MAP["domain"] == "domain"
    assert _MISP_TYPE_MAP["hostname"] == "domain"
    assert _MISP_TYPE_MAP["url"] == "url"
    assert _MISP_TYPE_MAP["sha256"] == "hash"
    assert _MISP_TYPE_MAP["filename|sha256"] == "hash"
    assert "vulnerability" not in _MISP_TYPE_MAP  # intentionally unmapped


# ── Pipeline ────────────────────────────────────────────────────────


async def test_poll_processes_events_in_timestamp_order():
    feed = DigitalSideMispFeed()
    events = {
        "abc123-event-uuid-1": _EVENT_1,
        "def456-event-uuid-2": _EVENT_2,
        "ghi789-event-uuid-3": _EVENT_3,
    }
    with _patch_fetches(feed, _MANIFEST, events):
        entries = await _collect(feed)

    # We expect every Event 1's mapped attributes (4 valid: ip, domain, hash, url)
    # + Event 2's (1: hash) + Event 3's (1: domain) = 6 total.
    assert len(entries) == 6


async def test_event_attributes_map_to_correct_entry_types():
    feed = DigitalSideMispFeed()
    with _patch_fetches(feed, _MANIFEST, {"abc123-event-uuid-1": _EVENT_1}):
        entries = await _collect(feed)

    by_value = {e.value: e for e in entries}
    assert by_value["203.0.113.50"].entry_type == "ip"
    assert by_value["evil.example.com"].entry_type == "domain"
    assert by_value["http://evil.example.com/payload"].entry_type == "url"
    # filename|sha256 composite must split → keep just the hash
    assert by_value["a" * 64].entry_type == "hash"


async def test_filename_sha256_composite_splits_correctly():
    """The composite ``loader.exe|abcdef...`` must yield the hash,
    not the literal composite string. Pin this — silent regression
    here means hash IOCs become unmatchable text strings."""
    feed = DigitalSideMispFeed()
    with _patch_fetches(feed, _MANIFEST, {"abc123-event-uuid-1": _EVENT_1}):
        entries = await _collect(feed)

    hash_entries = [e for e in entries if e.entry_type == "hash"]
    assert len(hash_entries) == 1
    assert hash_entries[0].value == "a" * 64  # NOT "loader.exe|aaaa..."


async def test_threat_level_maps_to_severity():
    """threat_level_id 1=critical, 2=high, 3=medium, 4=low."""
    feed = DigitalSideMispFeed()
    with _patch_fetches(feed, _MANIFEST, {
        "abc123-event-uuid-1": _EVENT_1,  # 1 → critical
        "def456-event-uuid-2": _EVENT_2,  # 3 → medium
        "ghi789-event-uuid-3": _EVENT_3,  # 4 → low
    }):
        entries = await _collect(feed)

    by_event = {}
    for e in entries:
        by_event.setdefault(e.feed_metadata["event_info"], []).append(e.severity)

    assert all(s == "critical" for s in by_event["Lumma C2"])
    assert all(s == "medium" for s in by_event["Emotet IOCs"])
    assert all(s == "low" for s in by_event["Older"])


async def test_skips_unmapped_misp_types():
    """An attribute with an unmapped MISP type (e.g. 'vulnerability')
    must be silently skipped — feed should not crash on it."""
    feed = DigitalSideMispFeed()
    with _patch_fetches(feed, _MANIFEST, {"abc123-event-uuid-1": _EVENT_1}):
        entries = await _collect(feed)
    values = [e.value for e in entries]
    assert "CVE-9999-9999" not in values  # unmapped 'vulnerability' type


async def test_skips_empty_and_missing_value_attributes():
    feed = DigitalSideMispFeed()
    with _patch_fetches(feed, _MANIFEST, {"abc123-event-uuid-1": _EVENT_1}):
        entries = await _collect(feed)
    # Event 1 has 8 attributes but only 4 should yield entries
    # (3 unmapped/empty/missing/garbage filtered out)
    event1_entries = [
        e for e in entries
        if e.feed_metadata["event_uuid"] == "abc123-event-uuid-1"
    ]
    assert len(event1_entries) == 4


async def test_handles_non_dict_manifest():
    """If DigitalSide ever returns a list manifest (or a string), the
    feed must exit cleanly — not crash the worker tick."""
    feed = DigitalSideMispFeed()
    with _patch_fetches(feed, ["garbage"], {}):
        entries = await _collect(feed)
    assert entries == []


async def test_handles_event_fetch_failures():
    """If the manifest lists an event but the per-event fetch returns
    None (network failure), skip the event silently and continue."""
    feed = DigitalSideMispFeed()
    # Manifest has 3 events but we only return payload for 1 → other 2 skip.
    with _patch_fetches(feed, _MANIFEST, {"abc123-event-uuid-1": _EVENT_1}):
        entries = await _collect(feed)
    # Only Event 1's 4 valid attributes
    assert len(entries) == 4
