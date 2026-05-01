"""Feed ingestion pipeline — dedup, geolocate, store, emit."""

from __future__ import annotations


import asyncio
import logging
import socket
import uuid as _uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from sqlalchemy import select, func, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.activity import ActivityType, emit as activity_emit
from src.feeds.base import BaseFeed, FeedEntry
from src.feeds.geolocation import GeoLocator, GeoResult
from src.models.feeds import ThreatFeedEntry, ThreatLayer

logger = logging.getLogger(__name__)

# Batch size for geolocation
_GEO_BATCH_SIZE = 200

# DNS resolution concurrency limit
_DNS_SEMAPHORE = asyncio.Semaphore(50)
_DNS_CACHE: dict[str, str | None] = {}


async def resolve_domain_to_ip(domain: str) -> str | None:
    """Resolve a domain to its first IPv4 address via DNS. Cached and rate-limited."""
    if domain in _DNS_CACHE:
        return _DNS_CACHE[domain]

    async with _DNS_SEMAPHORE:
        try:
            result = await asyncio.to_thread(
                socket.getaddrinfo, domain, None, socket.AF_INET, socket.SOCK_STREAM,
            )
            ip = result[0][4][0] if result else None
            _DNS_CACHE[domain] = ip
            return ip
        except (socket.gaierror, OSError, TimeoutError):
            _DNS_CACHE[domain] = None
            return None


def extract_domain(value: str, entry_type: str) -> str | None:
    """Extract a domain name from a URL or domain entry value."""
    if entry_type == "domain":
        return value.strip().lower()
    if entry_type == "url":
        try:
            parsed = urlparse(value)
            host = parsed.hostname
            if host:
                return host.lower()
        except Exception:
            pass
    return None


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
                        now = datetime.now(timezone.utc)
                        expires_at = now + timedelta(hours=entry.expires_hours)

                        # Atomic upsert: INSERT ... ON CONFLICT DO UPDATE
                        stmt = pg_insert(ThreatFeedEntry).values(
                            id=_uuid.uuid4(),
                            created_at=now,
                            updated_at=now,
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
                        ).on_conflict_do_update(
                            constraint="uq_feed_name_value",
                            set_={
                                "last_seen": now,
                                "expires_at": expires_at,
                                "severity": entry.severity,
                                "confidence": entry.confidence,
                            },
                        ).returning(ThreatFeedEntry.id, ThreatFeedEntry.created_at)
                        result = await self.db.execute(stmt)
                        row = result.one()
                        is_new = (now - row.created_at).total_seconds() < 2

                        if not is_new:
                            continue

                        new_count += 1

                        # We need the ORM object for geo queue — fetch it
                        feed_entry_result = await self.db.execute(
                            select(ThreatFeedEntry).where(ThreatFeedEntry.id == row.id)
                        )
                        feed_entry = feed_entry_result.scalar_one()

                        # Resolve domain → IP for URL/domain entries missing ip_for_geo
                        if not entry.ip_for_geo and entry.latitude is None:
                            domain = extract_domain(entry.value, entry.entry_type)
                            if domain:
                                resolved_ip = await resolve_domain_to_ip(domain)
                                if resolved_ip:
                                    entry.ip_for_geo = resolved_ip

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


async def backfill_geolocation(db: AsyncSession, geolocator: GeoLocator, batch_size: int = 500) -> dict:
    """Retroactively resolve domains/URLs → IP → geo for entries missing lat/lng.

    Returns summary of how many entries were updated.
    """
    # Find entries with no lat/lng that are URL or domain type
    query = (
        select(ThreatFeedEntry)
        .where(
            ThreatFeedEntry.latitude.is_(None),
            ThreatFeedEntry.entry_type.in_(["url", "domain"]),
        )
        .limit(10000)  # Process in chunks to avoid memory issues
    )
    result = await db.execute(query)
    entries = result.scalars().all()

    if not entries:
        return {"total_checked": 0, "resolved": 0, "geolocated": 0}

    logger.info("[backfill] Found %d entries without geo data to process", len(entries))

    # Phase 1: DNS resolution — domain → IP
    resolved_count = 0
    entries_to_geo: list[tuple[str, ThreatFeedEntry]] = []

    for entry in entries:
        domain = extract_domain(entry.value, entry.entry_type)
        if not domain:
            continue

        ip = await resolve_domain_to_ip(domain)
        if ip:
            resolved_count += 1
            entries_to_geo.append((ip, entry))

    logger.info("[backfill] Resolved %d domains to IPs", resolved_count)

    # Phase 2: Batch geolocate all resolved IPs
    geolocated = 0
    for i in range(0, len(entries_to_geo), batch_size):
        batch = entries_to_geo[i:i + batch_size]
        ips = [ip for ip, _ in batch]
        geo_results = await geolocator.locate_batch(ips)

        for ip, entry in batch:
            if ip in geo_results:
                geo = geo_results[ip]
                if geo.latitude is not None:
                    entry.latitude = geo.latitude
                    entry.longitude = geo.longitude
                    entry.country_code = geo.country_code
                    entry.city = geo.city
                    entry.asn = geo.asn
                    geolocated += 1

        await db.flush()

    await db.commit()

    summary = {
        "total_checked": len(entries),
        "resolved": resolved_count,
        "geolocated": geolocated,
    }
    logger.info("[backfill] Geolocation backfill complete: %s", summary)
    return summary
