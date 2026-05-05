"""DigitalSide OSINT MISP feed.

DigitalSide (https://osint.digitalside.it) is an Italian-maintained
OSINT collection focused on malware analysis: compromised URLs, IPs,
domains, and file hashes derived from active malware studies. It's
been a MISP "default feed" since 2019-09-23 and is licensed for free
use including commercial deployments.

Strong complement to the existing CIRCL OSINT feed:

  * **CIRCL OSINT** — Iran-nexus / European-targeted campaigns.
  * **DigitalSide**  — malware-distribution infrastructure (URL/host
                       pivots from real-world sample analysis).

Same MISP feed format as CIRCL: a manifest.json catalogues events,
each event lives at ``<base>/<uuid>.json`` containing MISP attributes
we map to FeedEntry rows. We don't share code with circl_misp_feed.py
yet — the formats may diverge over time and a small parallel module
is cheaper than a generalised abstraction we'd have to keep in sync.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


# Primary source goes via the project's CDN-fronted host; the
# GitHub mirror is the same upstream repo (davidonzo/Threat-Intel)
# that the .it host serves out of, so it returns identical JSON
# bodies. We fail over to the mirror when the .it origin is
# unreachable — observed in practice during prolonged outages of
# osint.digitalside.it (DNS resolves but the manifest path hangs
# until the 600s scheduler timeout fires, and the operator sees a
# nondescript "network_error" with zero rows ingested).
_MANIFEST_URLS = (
    "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/manifest.json",
    "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/digitalside-misp-feed/manifest.json",
)
_EVENT_URL_TEMPLATES = (
    "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/{uuid}.json",
    "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/digitalside-misp-feed/{uuid}.json",
)
_MAX_EVENTS_PER_POLL = 25


_MISP_TYPE_MAP: dict[str, str] = {
    "ip-src": "ip", "ip-dst": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
    "filename|md5": "hash", "filename|sha1": "hash",
    "filename|sha256": "hash",
}


_MISP_SEVERITY_MAP: dict[str, str] = {
    "1": "critical", "2": "high", "3": "medium", "4": "low",
}


class DigitalSideMispFeed(BaseFeed):
    """DigitalSide OSINT MISP feed."""

    name = "digitalside_osint"
    layer = "threat_intel"
    default_interval_seconds = 21600  # 6 hours, same cadence as CIRCL

    async def poll(self) -> AsyncIterator[FeedEntry]:
        import asyncio

        # Try each source in turn; first that returns a dict wins.
        # Track which source succeeded so we hit the same one for
        # event payloads (avoids cross-mirror inconsistency).
        manifest: dict | None = None
        manifest_idx = 0
        for idx, url in enumerate(_MANIFEST_URLS):
            payload = await self._fetch_json(url)
            if isinstance(payload, dict):
                manifest = payload
                manifest_idx = idx
                if idx > 0:
                    logger.info(
                        "[%s] primary host failed; using mirror %s",
                        self.name, url,
                    )
                break
        if manifest is None:
            logger.warning("[%s] all manifest sources failed", self.name)
            return

        # The first source failure set ``last_failure_reason`` /
        # ``last_failure_classification`` on the base feed; clear
        # them here so the scheduler doesn't mark the whole run as
        # network_error when the mirror actually succeeded.
        if manifest_idx > 0:
            self.last_failure_reason = None
            self.last_failure_classification = None

        event_url_template = _EVENT_URL_TEMPLATES[manifest_idx]

        def _ts(meta: dict) -> int:
            try:
                return int(meta.get("timestamp") or 0)
            except (TypeError, ValueError):
                return 0

        sorted_entries = sorted(
            manifest.items(),
            key=lambda kv: _ts(kv[1] if isinstance(kv[1], dict) else {}),
            reverse=True,
        )

        # Concurrency-bounded fetch — same rationale as the CIRCL
        # feed: 25 sequential round-trips against an upstream that
        # may be slow easily blew the 600s scheduler timeout.
        sem = asyncio.Semaphore(4)
        async def _fetch_event(event_uuid: str) -> tuple[str, dict | None]:
            async with sem:
                payload = await self._fetch_json(event_url_template.format(uuid=event_uuid))
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
                        event_date, "%Y-%m-%d",
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            for attr in event.get("Attribute") or []:
                if not isinstance(attr, dict):
                    continue
                misp_type = (attr.get("type") or "").lower()
                entry_type = _MISP_TYPE_MAP.get(misp_type)
                if not entry_type:
                    continue
                value = (attr.get("value") or "").strip()
                if not value:
                    continue
                if "|" in misp_type and "|" in value:
                    value = value.split("|", 1)[-1]

                comment = (attr.get("comment") or "").strip()
                yield FeedEntry(
                    feed_name=self.name,
                    layer=self.layer,
                    entry_type=entry_type,
                    value=value,
                    label=f"DigitalSide OSINT: {value}",
                    description=(
                        f"From DigitalSide event '{info}' "
                        f"(threat_level={threat_level})."
                        + (f" {comment}" if comment else "")
                    ),
                    severity=severity,
                    confidence=0.85,
                    feed_metadata={
                        "source": "digitalside_osint",
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
