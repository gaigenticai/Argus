"""CIRCL OSINT MISP feed (P1 #1.7 B).

Pulls events from CIRCL's free OSINT MISP feed. Strong on Iran-nexus
and European-targeted campaigns; pairs with the Iran-APT pack
(:mod:`src.intel.iran_apt_pack`) so the curated TTPs have matching
fresh IOCs.

Source: https://www.circl.lu/doc/misp/feed-osint/
Format: MISP feed manifest (``manifest.json``) → per-event JSON
        bundles. We pull the manifest, then fetch each new event in
        parallel-bounded batches.
License: CC0 / CC-BY — explicitly free for commercial use per CIRCL's
         OSINT Feed Terms of Use.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

# CIRCL publishes the OSINT feed in MISP feed format at this fixed URL.
_CIRCL_MANIFEST_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
_CIRCL_EVENT_URL = "https://www.circl.lu/doc/misp/feed-osint/{uuid}.json"

# Maximum events to ingest per poll. CIRCL publishes a few hundred
# active events at any time; pulling the whole manifest is cheap,
# fetching every event is not. We take the most-recently-modified slice.
_MAX_EVENTS_PER_POLL = 25


# MISP attribute "type" → Argus FeedEntry.entry_type. Not exhaustive —
# only the IOC types the rest of the platform consumes today.
_MISP_TYPE_MAP: dict[str, str] = {
    "ip-src": "ip", "ip-dst": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
    "filename|md5": "hash", "filename|sha1": "hash",
    "filename|sha256": "hash",
}


# Threat-level → Argus severity. MISP uses 1=high, 2=medium, 3=low,
# 4=undefined. We map conservatively.
_MISP_SEVERITY_MAP: dict[str, str] = {
    "1": "critical", "2": "high", "3": "medium", "4": "low",
}


class CIRCLMispFeed(BaseFeed):
    """CIRCL OSINT MISP feed."""

    name = "circl_osint"
    layer = "threat_intel"
    default_interval_seconds = 21600  # 6 hours

    async def poll(self) -> AsyncIterator[FeedEntry]:
        import asyncio
        manifest = await self._fetch_json(_CIRCL_MANIFEST_URL)
        if not isinstance(manifest, dict):
            logger.warning("[%s] manifest is not a dict (got %s)",
                           self.name, type(manifest).__name__)
            return

        # Manifest entries: {uuid: {Orgc, info, date, threat_level_id,
        #                            timestamp, ...}}
        # Sort by 'timestamp' (unix epoch string) DESC to get the most
        # recent events first.
        def _ts(entry: dict) -> int:
            try:
                return int(entry.get("timestamp") or 0)
            except (TypeError, ValueError):
                return 0

        sorted_entries = sorted(
            manifest.items(),
            key=lambda kv: _ts(kv[1] if isinstance(kv[1], dict) else {}),
            reverse=True,
        )

        # Concurrency: previously fetched the 25 event payloads
        # sequentially. circl.lu round-trips ~3s each from the lab,
        # so the worst case was 75s+ on top of the manifest fetch
        # — easy to hit the scheduler's 600s hard timeout when the
        # upstream is slow. ``asyncio.gather`` under a semaphore
        # keeps the politeness contract (max 4 in flight) while
        # capping wall-clock at ~10-15s for the typical case.
        sem = asyncio.Semaphore(4)
        async def _fetch_event(event_uuid: str) -> tuple[str, dict | None]:
            async with sem:
                payload = await self._fetch_json(_CIRCL_EVENT_URL.format(uuid=event_uuid))
                return event_uuid, (payload if isinstance(payload, dict) else None)

        candidates = [
            (uuid_, meta) for uuid_, meta in sorted_entries[:_MAX_EVENTS_PER_POLL]
            if isinstance(meta, dict)
        ]
        fetched = await asyncio.gather(
            *[_fetch_event(uuid_) for uuid_, _ in candidates],
            return_exceptions=False,
        )
        payloads_by_uuid = {uuid_: payload for uuid_, payload in fetched}

        events_processed = 0
        for event_uuid, meta in candidates:
            event_payload = payloads_by_uuid.get(event_uuid)
            if event_payload is None:
                continue
            event = event_payload.get("Event") or {}
            if not isinstance(event, dict):
                continue

            info = (event.get("info") or "").strip()
            threat_level = str(event.get("threat_level_id") or "3")
            severity = _MISP_SEVERITY_MAP.get(threat_level, "medium")
            event_date = (event.get("date") or "").strip()

            first_seen = None
            if event_date:
                try:
                    first_seen = datetime.strptime(
                        event_date, "%Y-%m-%d"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            attributes = event.get("Attribute") or []
            for attr in attributes:
                if not isinstance(attr, dict):
                    continue
                misp_type = (attr.get("type") or "").lower()
                entry_type = _MISP_TYPE_MAP.get(misp_type)
                if not entry_type:
                    continue
                value = (attr.get("value") or "").strip()
                if not value:
                    continue
                # filename|hash composites: take the hash half.
                if "|" in misp_type and "|" in value:
                    value = value.split("|", 1)[-1]

                comment = (attr.get("comment") or "").strip()
                yield FeedEntry(
                    feed_name=self.name,
                    layer=self.layer,
                    entry_type=entry_type,
                    value=value,
                    label=f"CIRCL OSINT: {value}",
                    description=(
                        f"From CIRCL event '{info}' (threat_level={threat_level})."
                        + (f" {comment}" if comment else "")
                    ),
                    severity=severity,
                    confidence=0.85,
                    feed_metadata={
                        "source": "circl_osint",
                        "event_uuid": event_uuid,
                        "event_info": info,
                        "event_date": event_date or None,
                        "misp_type": misp_type,
                        "comment": comment or None,
                    },
                    first_seen=first_seen,
                    expires_hours=720,
                )
            events_processed += 1

        logger.info(
            "[%s] processed %d events (manifest had %d)",
            self.name, events_processed, len(manifest),
        )
