"""Feed scheduler — polls public threat intel feeds on configured intervals."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from src.feeds.base import BaseFeed
from src.feeds.geolocation import GeoLocator
from src.feeds.pipeline import FeedIngestionPipeline
from src.storage.database import get_session

# ---------------------------------------------------------------------------
# Feed imports — each maps to one public threat intelligence source
# ---------------------------------------------------------------------------
from src.feeds.botnet_feed import BotnetFeed
from src.feeds.honeypot_feed import HoneypotFeed
from src.feeds.ip_reputation_feed import IPReputationFeed
from src.feeds.kev_feed import KEVFeed
from src.feeds.malware_feed import MalwareFeed
from src.feeds.malwarebazaar_feed import MalwareBazaarFeed
from src.feeds.spamhaus_drop_feed import SpamhausDropFeed
from src.feeds.firehol_feed import FireHOLFeed
from src.feeds.plain_ip_list_feed import BlocklistDeFeed, CinsScoreFeed
from src.feeds.digitalside_feed import DigitalSideMispFeed
from src.feeds.phishing_feed import PhishingFeed
from src.feeds.ransomware_feed import RansomwareFeed
from src.feeds.ssl_feed import SSLFeed
from src.feeds.tor_nodes_feed import TorNodesFeed
from src.feeds.greynoise_feed import GreyNoiseFeed
from src.feeds.otx_feed import OTXFeed
from src.feeds.bgp_hijack_feed import BGPHijackFeed
# P1 #1.7 — five commercial-licensable feeds
from src.feeds.certstream_feed import CertStreamFeed
from src.feeds.circl_misp_feed import CIRCLMispFeed
from src.feeds.phishtank_certpl_feed import PhishTankCertPLFeed
from src.feeds.ghsa_exploitdb_feed import GHSAExploitDBFeed
from src.feeds.abusech_tls_feed import AbuseChTLSFeed
# OSS self-hosted inbound — pulls from operator's own MISP /
# OpenCTI / Wazuh when the URL+token are configured. Otherwise the
# feed marks itself ``unconfigured`` and the scheduler skips cleanly.
from src.feeds.oss_self_hosted_feeds import (
    MispOperatorFeed,
    OpenCTIOperatorFeed,
    WazuhFeed,
    CalderaProbeFeed,
    VelociraptorProbeFeed,
    CapeProbeFeed,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schedule definition
# ---------------------------------------------------------------------------


class FeedSchedule:
    """Pairs a feed class with its polling interval and optional constructor kwargs."""

    def __init__(
        self,
        feed_class: type[BaseFeed],
        interval_seconds: int,
        **kwargs,
    ):
        self.feed_class = feed_class
        self.interval = interval_seconds
        self.kwargs = kwargs
        self.last_run: datetime | None = None


# Ordered from fastest to slowest cadence.
DEFAULT_FEED_SCHEDULES: list[FeedSchedule] = [
    FeedSchedule(HoneypotFeed, interval_seconds=300),        # 5 min  — DShield infocon
    FeedSchedule(TorNodesFeed, interval_seconds=1800),       # 30 min
    FeedSchedule(BotnetFeed, interval_seconds=3600),         # 1 hour
    FeedSchedule(MalwareFeed, interval_seconds=3600),        # 1 hour — URLhaus + ThreatFox
    FeedSchedule(MalwareBazaarFeed, interval_seconds=3600),  # 1 hour — sample hashes
    FeedSchedule(SpamhausDropFeed, interval_seconds=3600),   # 1 hour — Spamhaus DROP netblocks
    FeedSchedule(FireHOLFeed, interval_seconds=3600),        # 1 hour — FireHOL aggregated IP lists
    FeedSchedule(BlocklistDeFeed, interval_seconds=3600),    # 1 hour — blocklist.de honeypot attackers
    FeedSchedule(CinsScoreFeed, interval_seconds=3600),      # 1 hour — CINS Army poor-rep IPs
    FeedSchedule(DigitalSideMispFeed, interval_seconds=21600),  # 6 hours — DigitalSide MISP feed
    FeedSchedule(IPReputationFeed, interval_seconds=3600),   # 1 hour
    FeedSchedule(SSLFeed, interval_seconds=3600),            # 1 hour
    FeedSchedule(PhishingFeed, interval_seconds=21600),      # 6 hours
    # 24h cadence — ransomware.live's free tier rate-limits at ~hourly,
    # AND we already hit the same upstream from
    # ``workers.maintenance.refresh_ransomware_targets`` on a daily
    # cadence. Polling every 6h here was tripping HTTP 429.
    FeedSchedule(RansomwareFeed, interval_seconds=86400),
    FeedSchedule(KEVFeed, interval_seconds=86400),           # 24 hours
    FeedSchedule(GreyNoiseFeed, interval_seconds=3600),      # 1 hour — GNQL scanner intel
    FeedSchedule(OTXFeed, interval_seconds=3600),            # 1 hour — OTX community pulses
    FeedSchedule(BGPHijackFeed, interval_seconds=3600),      # 1 hour — Cloudflare Radar BGP hijacks
    # P1 #1.7 — five commercial-licensable feeds (license verified
    # against each provider's published terms; all four below are CC0
    # / open-data / public, no operator API key required to bootstrap).
    # 4h cadence — crt.sh runs into HTTP 502 frequently when polled
    # aggressively. Brand-new certs aren't urgent (the dnstwist
    # scanner has a tighter loop for typo domains anyway), so a
    # slower interval keeps the OK ratio healthy and stops the
    # dashboard from flapping the source on every transient outage.
    FeedSchedule(CertStreamFeed, interval_seconds=14400),
    FeedSchedule(CIRCLMispFeed, interval_seconds=21600),     # 6 hours — CIRCL OSINT MISP
    FeedSchedule(PhishTankCertPLFeed, interval_seconds=21600),  # 6 hours
    FeedSchedule(GHSAExploitDBFeed, interval_seconds=86400),    # 24 hours
    FeedSchedule(AbuseChTLSFeed, interval_seconds=21600),    # 6 hours — SSLBL + JA3
    # OSS self-hosted inbound. Each feed bails with
    # ``last_unconfigured_reason`` when its URL+token aren't set, so
    # leaving them in the schedule is a no-op for operators who
    # haven't installed the upstream — the dashboard shows
    # ``unconfigured`` until the keys land, then data starts flowing
    # without code changes.
    FeedSchedule(MispOperatorFeed, interval_seconds=1800),     # 30 min
    FeedSchedule(OpenCTIOperatorFeed, interval_seconds=1800),  # 30 min
    FeedSchedule(WazuhFeed, interval_seconds=600),             # 10 min
    # On-demand integrations: probe hourly so the dashboard reflects
    # configured-and-reachable. Actual data flow is operator-triggered
    # via /threat-hunter (Caldera), /cases (Velociraptor),
    # /iocs sample submission (CAPE).
    FeedSchedule(CalderaProbeFeed, interval_seconds=3600),
    FeedSchedule(VelociraptorProbeFeed, interval_seconds=3600),
    FeedSchedule(CapeProbeFeed, interval_seconds=3600),
]


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class FeedScheduler:
    """Polls public threat intel feeds on their configured intervals.

    Usage::

        scheduler = FeedScheduler()
        await scheduler.start()   # blocks until stop() is called
    """

    def __init__(self, schedules: list[FeedSchedule] | None = None):
        self.schedules = schedules or DEFAULT_FEED_SCHEDULES
        self._running = False
        self._geolocator: GeoLocator | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch all feed loops concurrently.  Blocks until ``stop()``."""
        self._running = True
        self._geolocator = GeoLocator()
        logger.info(
            "[feed-scheduler] Starting with %d feeds",
            len(self.schedules),
        )
        tasks = [self._run_schedule(schedule) for schedule in self.schedules]
        try:
            await asyncio.gather(*tasks)
        finally:
            if self._geolocator:
                self._geolocator.close()

    async def stop(self) -> None:
        """Signal all feed loops to exit after their current iteration."""
        self._running = False
        logger.info("[feed-scheduler] Stop requested")

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _run_schedule(self, schedule: FeedSchedule) -> None:
        while self._running:
            await self._run_one(schedule)
            schedule.last_run = datetime.now(timezone.utc)
            if schedule.interval > 0:
                await asyncio.sleep(schedule.interval)
            else:
                # interval=0 means persistent connection (e.g. BGP WebSocket).
                # If it exits, back off 60 s before reconnecting.
                await asyncio.sleep(60)

    async def _run_one(self, schedule: FeedSchedule) -> None:
        """Execute one tick of a feed, recording a FeedHealth row.

        FeedHealth recording rules:
            * Feed sets ``last_unconfigured_reason`` (e.g. missing API
              key) → status=unconfigured, rows=0.
            * Feed raises → status=network_error (or whatever the
              subclass classified it as via ``last_failure_classification``).
            * Otherwise the count of ingested entries lands as
              status=ok, rows=N.
        """
        import time as _time

        from src.core import feed_health as _feed_health
        from src.models.admin import FeedHealthStatus

        feed = schedule.feed_class(**schedule.kwargs)
        logger.info("[feed-scheduler] Running %s", feed.name)
        t0 = _time.monotonic()
        new_count = 0
        crashed: BaseException | None = None
        try:
            async for session in get_session():
                pipeline = FeedIngestionPipeline(session, self._geolocator)
                # Hard timeout per feed run. Without this a hung
                # upstream (or a slow IngestionPipeline due to per-row
                # geo lookups against rate-limited ipwho.is) wedges
                # the feed forever — no FeedHealth row ever lands and
                # the dashboard shows ``unknown`` indefinitely. 600s
                # is generous enough for ~10k-row feeds while keeping
                # the slot bounded.
                new_count = await asyncio.wait_for(
                    pipeline.ingest_from_feed(feed),
                    timeout=600,
                )
                logger.info(
                    "[feed-scheduler] %s complete — %d new entries",
                    feed.name, new_count,
                )
        except asyncio.TimeoutError as exc:
            crashed = exc
            logger.error(
                "[feed-scheduler] %s timed out after 600s — marking feed_health network_error",
                schedule.feed_class.__name__,
            )
        except Exception as exc:  # noqa: BLE001
            crashed = exc
            logger.exception(
                "[feed-scheduler] %s failed", schedule.feed_class.__name__,
            )

        duration_ms = int((_time.monotonic() - t0) * 1000)
        async for session in get_session():
            try:
                if crashed is not None:
                    # asyncio.TimeoutError and a few other exceptions
                    # stringify to ``""`` — write a meaningful detail
                    # instead of dropping an empty row that the
                    # operator can't interpret.
                    if isinstance(crashed, asyncio.TimeoutError):
                        err_msg = (
                            f"feed run timed out after 600s — upstream may be slow "
                            f"or rate-limited; check worker logs for the last "
                            f"per-source error"
                        )
                    else:
                        err_msg = str(crashed) or f"{type(crashed).__name__}: (no message)"
                    await _feed_health.mark_failure(
                        session,
                        feed_name=feed.name,
                        error=err_msg,
                        duration_ms=duration_ms,
                        classify=(
                            feed.last_failure_classification
                            or FeedHealthStatus.NETWORK_ERROR.value
                        ),
                    )
                elif feed.last_unconfigured_reason:
                    await _feed_health.mark_unconfigured(
                        session,
                        feed_name=feed.name,
                        detail=feed.last_unconfigured_reason,
                    )
                elif feed.last_failure_reason and new_count == 0:
                    # Hard failure — feed yielded nothing AND set a
                    # failure flag. Multi-source feeds that succeeded
                    # on at least one leg fall through to mark_ok
                    # below with a partial-failure note in detail.
                    await _feed_health.mark_failure(
                        session,
                        feed_name=feed.name,
                        error=feed.last_failure_reason,
                        duration_ms=duration_ms,
                        classify=(
                            feed.last_failure_classification
                            or FeedHealthStatus.NETWORK_ERROR.value
                        ),
                    )
                else:
                    # When a multi-source feed had a partial failure
                    # (one leg failed, another yielded entries), fold
                    # that into the OK row's detail so the dashboard
                    # surfaces the warning without flipping to red.
                    detail = None
                    if feed.last_failure_reason:
                        detail = (
                            f"partial: ingested {new_count} entries; "
                            f"some sources failed: {feed.last_failure_reason[:200]}"
                        )
                    await _feed_health.mark_ok(
                        session,
                        feed_name=feed.name,
                        rows_ingested=int(new_count or 0),
                        duration_ms=duration_ms,
                        detail=detail,
                    )
                await session.commit()
            except Exception:  # noqa: BLE001
                logger.exception(
                    "[feed-scheduler] could not record FeedHealth for %s",
                    feed.name,
                )

    # ------------------------------------------------------------------
    # Manual / test helpers
    # ------------------------------------------------------------------

    async def run_once(self, feed_name: str | None = None) -> None:
        """Run feeds once (useful for testing or manual triggers).

        Args:
            feed_name: If provided, only the feed whose ``name`` matches
                       — OR which yields entries with that ``feed_name``
                       — will be executed. Otherwise every scheduled
                       feed runs.

        Several feed classes write entries under MULTIPLE ``feed_name``
        labels (BotnetFeed yields both ``feodo_tracker`` and
        ``c2_tracker``; PhishingFeed yields ``openphish`` and
        ``phishstats``; etc.). Those secondary labels show up in the
        UI's feed list with a Run button that previously matched
        nothing — so clicking "Run" on c2_tracker silently did
        nothing while feodo_tracker (same class) ran fine. We now
        resolve the alias to the owning class.
        """
        if not self._geolocator:
            self._geolocator = GeoLocator()
        try:
            target_schedule = None
            if feed_name:
                # First pass: exact class-name match (the common case).
                for schedule in self.schedules:
                    probe = schedule.feed_class(**schedule.kwargs)
                    if probe.name == feed_name:
                        target_schedule = schedule
                        break
                # Second pass: alias resolution. Some classes yield
                # entries under multiple feed_names; map those to the
                # owning class so the manual-trigger UX is honest.
                if target_schedule is None:
                    owner = _FEED_NAME_ALIASES.get(feed_name)
                    if owner is not None:
                        for schedule in self.schedules:
                            if schedule.feed_class.__name__ == owner:
                                logger.info(
                                    "[feed-scheduler] Manual trigger %r resolved "
                                    "to owning class %s via alias",
                                    feed_name,
                                    owner,
                                )
                                target_schedule = schedule
                                break
                if target_schedule is None:
                    logger.warning(
                        "[feed-scheduler] Manual trigger %r did not match any "
                        "scheduled feed class .name nor any alias entry. "
                        "Either the feed isn't enabled in this deployment "
                        "or the alias map needs updating.",
                        feed_name,
                    )
                    return
                logger.info(
                    "[feed-scheduler] Manual run: %s (requested as %r)",
                    target_schedule.feed_class.__name__,
                    feed_name,
                )
                await self._run_one(target_schedule)
                return

            # No filter — run them all.
            for schedule in self.schedules:
                logger.info(
                    "[feed-scheduler] Manual run: %s",
                    schedule.feed_class.__name__,
                )
                await self._run_one(schedule)
        finally:
            if self._geolocator:
                self._geolocator.close()
                self._geolocator = None


# ---------------------------------------------------------------------------
# Phantom-feed → owning-class alias map.
#
# Several feed classes emit entries under multiple ``feed_name``
# labels because their upstream sources are logically distinct
# (different blocklist URLs, different malware families, different
# providers under one parser). Those secondary labels are real feeds
# from the operator's perspective — they show up in /feeds with their
# own counts and a Run button — so they need to resolve to the class
# that produces them when manually triggered.
#
# Keep this list in sync with the ``feed_name="..."`` literals in
# ``src/feeds/*_feed.py``. A simpler design would be to introspect
# the class's poll() coroutine, but that requires running it; an
# explicit map is honest about the mapping and breaks loudly when an
# alias is missing.
# ---------------------------------------------------------------------------
_FEED_NAME_ALIASES: dict[str, str] = {
    "c2_tracker": "BotnetFeed",
    "phishstats": "PhishingFeed",
    "threatfox": "MalwareFeed",
    "ja3_fingerprints": "SSLFeed",
    "blocklist_de": "IPReputationFeed",
    "firehol_l1": "IPReputationFeed",
}
