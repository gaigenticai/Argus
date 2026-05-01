"""BGP Hijack feed — real-time BGP route hijack detections via Cloudflare Radar.

Uses the Cloudflare Radar BGP Hijacks Events API to surface active prefix
hijacking events.  Each event is stored as a CIDR FeedEntry so downstream
triage can geo-locate the hijacker and correlate with other intelligence.

Configuration
-------------
    ARGUS_FEED_CF_RADAR_API_KEY   — Cloudflare API token with `radar:read`
                                    permission.  Without it the feed marks
                                    itself unconfigured (no entries, no error).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import AsyncIterator

from src.config.settings import settings
from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

CF_RADAR_BGP_URL = "https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events"

# Minimum peer-witness count to include an event — filters low-confidence noise.
_MIN_PEERS = 3


def _hijack_severity(peers: int, confidence: float) -> str:
    if confidence >= 0.85 and peers >= 20:
        return "critical"
    if confidence >= 0.70 or peers >= 10:
        return "high"
    if confidence >= 0.50:
        return "medium"
    return "low"


class BGPHijackFeed(BaseFeed):
    """Cloudflare Radar BGP hijack event intelligence.

    Polls for BGP prefix hijacking events detected in the last 24 hours.
    Each event maps to a CIDR FeedEntry carrying the hijacker/victim ASN
    metadata so analysts can investigate the source infrastructure.
    """

    name = "ripe_ris_live"
    layer = "bgp_hijack"
    default_interval_seconds = 3600  # 1 hour

    def _auth_headers(self) -> dict[str, str]:
        key = settings.feeds.cf_radar_api_key
        return {
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        }

    async def poll(self) -> AsyncIterator[FeedEntry]:
        api_key = settings.feeds.cf_radar_api_key
        if not api_key:
            self.last_unconfigured_reason = (
                "ARGUS_FEED_CF_RADAR_API_KEY is not set. "
                "Create a Cloudflare API token with radar:read scope and "
                "add it to your .env to enable BGP hijack detection."
            )
            return

        # Fetch events from the last 24 hours so each hourly poll gets fresh data
        # without gaps if the scheduler restarts.
        now = datetime.now(timezone.utc)
        date_start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        date_end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        params = {
            "dateStart": date_start,
            "dateEnd": date_end,
            "format": "JSON",
            "limit": "500",
        }

        data = await self._fetch_json(
            CF_RADAR_BGP_URL,
            headers=self._auth_headers(),
            params=params,
        )
        if not data or not isinstance(data, dict):
            return

        result = data.get("result", {})
        events = result.get("events", [])
        if not isinstance(events, list):
            return

        seen: set[str] = set()
        for event in events:
            prefix = (event.get("prefix") or "").strip()
            if not prefix or prefix in seen:
                continue

            peers = int(event.get("peersWitnessing") or 0)
            if peers < _MIN_PEERS:
                continue

            confidence = float(event.get("confidence") or 0.0)
            seen.add(prefix)

            hijacker_asn = event.get("hijackerAsn")
            hijacker_name = event.get("hijackerAsnName") or f"AS{hijacker_asn}"
            victim_asn = event.get("victimAsn")
            victim_name = event.get("victimAsnName") or f"AS{victim_asn}"
            country = (event.get("country") or "").upper() or None
            start_time = event.get("startTime") or ""
            event_type = event.get("eventType") or "BGPSTREAM"
            max_duration = int(event.get("maxDuration") or 0)

            severity = _hijack_severity(peers, confidence)

            first_seen: datetime | None = None
            if start_time:
                try:
                    first_seen = datetime.fromisoformat(
                        start_time.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="cidr",
                value=prefix,
                label=f"BGP Hijack: {prefix} by AS{hijacker_asn}",
                description=(
                    f"Prefix {prefix} (victim: {victim_name} / AS{victim_asn}) "
                    f"hijacked by {hijacker_name} / AS{hijacker_asn}. "
                    f"Witnessed by {peers} peers. Duration: {max_duration}s. "
                    f"Type: {event_type}."
                ),
                severity=severity,
                confidence=round(confidence, 3),
                country_code=country,
                feed_metadata={
                    "hijacker_asn": hijacker_asn,
                    "hijacker_name": hijacker_name,
                    "victim_asn": victim_asn,
                    "victim_name": victim_name,
                    "peers_witnessing": peers,
                    "event_type": event_type,
                    "max_duration_seconds": max_duration,
                    "confidence": confidence,
                },
                first_seen=first_seen,
                expires_hours=48,
            )

        logger.info("[bgp-hijack] yielded %d hijack events from Cloudflare Radar", len(seen))
