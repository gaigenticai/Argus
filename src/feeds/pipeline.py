"""Feed ingestion pipeline — dedup, geolocate, store, emit."""

import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.activity import ActivityType, emit as activity_emit
from src.feeds.base import BaseFeed, FeedEntry
from src.feeds.geolocation import GeoLocator, GeoResult
from src.models.feeds import ThreatFeedEntry, ThreatLayer

logger = logging.getLogger(__name__)

# Batch size for geolocation
_GEO_BATCH_SIZE = 200


class FeedIngestionPipeline:
    """Processes feed entries: dedup → geolocate → store → activity."""

    def __init__(self, db_session: AsyncSession, geolocator: GeoLocator):
        self.db = db_session
        self.geo = geolocator

    async def ingest_from_feed(self, feed: BaseFeed) -> int:
        """Run a feed and process all entries. Returns count of new entries stored."""
        new_count = 0
        total_count = 0
        entries_pending_geo: list[tuple[FeedEntry, ThreatFeedEntry]] = []

        await activity_emit(
            ActivityType.FEED_START,
            feed.name,
            f"Starting feed poll: {feed.name}",
            {"feed": feed.name, "layer": feed.layer},
        )

        try:
            async with feed:
                async for entry in feed.poll():
                    total_count += 1
                    try:
                        # Dedup: check if (feed_name, value) exists
                        existing = await self.db.execute(
                            select(ThreatFeedEntry).where(
                                ThreatFeedEntry.feed_name == entry.feed_name,
                                ThreatFeedEntry.value == entry.value,
                            )
                        )
                        existing_row = existing.scalar_one_or_none()

                        now = datetime.now(timezone.utc)
                        expires_at = now + timedelta(hours=entry.expires_hours)

                        if existing_row:
                            # Update last_seen and refresh expiry
                            existing_row.last_seen = now
                            existing_row.expires_at = expires_at
                            if entry.severity and entry.severity != existing_row.severity:
                                existing_row.severity = entry.severity
                            if entry.confidence and entry.confidence > existing_row.confidence:
                                existing_row.confidence = entry.confidence
                            if entry.description and not existing_row.description:
                                existing_row.description = entry.description
                            continue

                        # New entry
                        feed_entry = ThreatFeedEntry(
                            feed_name=entry.feed_name,
                            layer=entry.layer,
                            entry_type=entry.entry_type,
                            value=entry.value,
                            label=entry.label,
                            description=entry.description,
                            severity=entry.severity,
                            confidence=entry.confidence,
                            latitude=entry.latitude,
                            longitude=entry.longitude,
                            country_code=entry.country_code,
                            feed_metadata=entry.feed_metadata,
                            first_seen=entry.first_seen or now,
                            last_seen=now,
                            expires_at=expires_at,
                        )
                        self.db.add(feed_entry)
                        new_count += 1

                        # Queue for geolocation if IP available and no coords yet
                        if entry.ip_for_geo and entry.latitude is None:
                            entries_pending_geo.append((entry, feed_entry))

                        # Batch geo every _GEO_BATCH_SIZE
                        if len(entries_pending_geo) >= _GEO_BATCH_SIZE:
                            await self._geolocate_batch(entries_pending_geo)
                            entries_pending_geo.clear()

                        # Periodic flush every 100 new entries
                        if new_count % 100 == 0:
                            await self.db.flush()

                    except Exception as e:
                        logger.error("[feed-pipeline] Error processing entry from %s: %s", feed.name, e)

            # Final geo batch
            if entries_pending_geo:
                await self._geolocate_batch(entries_pending_geo)

            await self.db.flush()

            # Update layer entry count
            await self._update_layer_count(feed.layer)

            await self.db.commit()

        except Exception as e:
            logger.error("[feed-pipeline] Feed %s failed: %s", feed.name, e)
            await self.db.rollback()

        await activity_emit(
            ActivityType.FEED_COMPLETE,
            feed.name,
            f"{feed.name} finished — {total_count} entries processed, {new_count} new",
            {"feed": feed.name, "layer": feed.layer, "total": total_count, "new": new_count},
        )

        return new_count

    async def _geolocate_batch(
        self, pending: list[tuple[FeedEntry, ThreatFeedEntry]]
    ) -> None:
        """Batch geolocate IPs and update the corresponding ThreatFeedEntry rows."""
        ips = [entry.ip_for_geo for entry, _ in pending if entry.ip_for_geo]
        if not ips:
            return

        geo_results = await self.geo.locate_batch(ips)

        for entry, feed_entry in pending:
            if entry.ip_for_geo and entry.ip_for_geo in geo_results:
                geo = geo_results[entry.ip_for_geo]
                feed_entry.latitude = geo.latitude
                feed_entry.longitude = geo.longitude
                feed_entry.country_code = geo.country_code
                feed_entry.city = geo.city
                feed_entry.asn = geo.asn

    async def _update_layer_count(self, layer_name: str) -> None:
        """Update the cached entry_count for a threat layer."""
        count_result = await self.db.execute(
            select(func.count()).select_from(ThreatFeedEntry).where(
                ThreatFeedEntry.layer == layer_name,
                ThreatFeedEntry.expires_at > datetime.now(timezone.utc),
            )
        )
        count = count_result.scalar() or 0

        await self.db.execute(
            update(ThreatLayer)
            .where(ThreatLayer.name == layer_name)
            .values(entry_count=count)
        )
