"""Threat feed management endpoints — list configured feeds, trigger manual polls."""

from __future__ import annotations


import asyncio
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import CurrentUser, AnalystUser
from src.models.feeds import ThreatFeedEntry, ThreatLayer
from src.storage.database import get_session
from src.feeds.seed_layers import DEFAULT_LAYERS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/feeds", tags=["Threat Intelligence"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class FeedInfo(BaseModel):
    """A configured feed with its current status."""
    feed_name: str
    layer: str
    display_name: str
    icon: str
    color: str
    enabled: bool
    refresh_interval_seconds: int
    description: str | None
    active_entry_count: int
    total_entry_count: int
    latest_entry_at: datetime | None


class FeedTriggerResponse(BaseModel):
    feed_name: str
    message: str
    status: str


class FeedSummary(BaseModel):
    total_feeds: int
    total_active_entries: int
    feeds: list[FeedInfo]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Build a lookup from layer name -> layer config for enrichment
_LAYER_BY_NAME = {layer["name"]: layer for layer in DEFAULT_LAYERS}

# Build a flat lookup from feed_name -> layer_name
_FEED_TO_LAYER: dict[str, str] = {}
for _layer_data in DEFAULT_LAYERS:
    for _fn in _layer_data.get("feed_names", []):
        _FEED_TO_LAYER[_fn] = _layer_data["name"]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/", response_model=FeedSummary)
async def list_feeds(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """List all configured feeds with their current entry counts.

    Combines static layer configuration with live entry counts from the database.
    """
    now = datetime.now(timezone.utc)

    # Fetch all ThreatLayer rows (which store the canonical enabled/feed_names)
    layers_result = await db.execute(
        select(ThreatLayer).order_by(ThreatLayer.name)
    )
    db_layers = {layer.name: layer for layer in layers_result.scalars().all()}

    # Per-feed counts (active = non-expired)
    active_count_query = (
        select(
            ThreatFeedEntry.feed_name,
            func.count().label("active_count"),
        )
        .where(
            or_(
                ThreatFeedEntry.expires_at.is_(None),
                ThreatFeedEntry.expires_at > now,
            )
        )
        .group_by(ThreatFeedEntry.feed_name)
    )
    active_rows = (await db.execute(active_count_query)).all()
    active_counts = {row[0]: row[1] for row in active_rows}

    # Total per-feed counts (including expired)
    total_count_query = (
        select(
            ThreatFeedEntry.feed_name,
            func.count().label("total_count"),
        )
        .group_by(ThreatFeedEntry.feed_name)
    )
    total_rows = (await db.execute(total_count_query)).all()
    total_counts = {row[0]: row[1] for row in total_rows}

    # Latest entry timestamp per feed
    latest_query = (
        select(
            ThreatFeedEntry.feed_name,
            func.max(ThreatFeedEntry.last_seen).label("latest"),
        )
        .group_by(ThreatFeedEntry.feed_name)
    )
    latest_rows = (await db.execute(latest_query)).all()
    latest_times = {row[0]: row[1] for row in latest_rows}

    feeds: list[FeedInfo] = []
    seen_feed_names: set[str] = set()

    # Walk through DB layers (source of truth). A feed_name can appear
    # in more than one layer's ``feed_names`` array (greynoise / otx_pulse
    # show up in several intel layers). The 2nd/3rd loops below already
    # dedupe via ``seen_feed_names``; this loop must do the same or the
    # client gets duplicate keys and React/dashboard-side renderers
    # bail with "two children with the same key".
    for layer_name, layer_obj in db_layers.items():
        layer_conf = _LAYER_BY_NAME.get(layer_name, {})
        for feed_name in (layer_obj.feed_names or []):
            if feed_name in seen_feed_names:
                continue
            seen_feed_names.add(feed_name)
            feeds.append(FeedInfo(
                feed_name=feed_name,
                layer=layer_name,
                display_name=layer_obj.display_name,
                icon=layer_obj.icon,
                color=layer_obj.color,
                enabled=layer_obj.enabled,
                refresh_interval_seconds=layer_obj.refresh_interval_seconds,
                description=layer_obj.description,
                active_entry_count=active_counts.get(feed_name, 0),
                total_entry_count=total_counts.get(feed_name, 0),
                latest_entry_at=latest_times.get(feed_name),
            ))

    # Fallback: include any DEFAULT_LAYERS feeds that aren't in DB yet
    for layer_data in DEFAULT_LAYERS:
        for feed_name in layer_data.get("feed_names", []):
            if feed_name in seen_feed_names:
                continue
            seen_feed_names.add(feed_name)
            feeds.append(FeedInfo(
                feed_name=feed_name,
                layer=layer_data["name"],
                display_name=layer_data["display_name"],
                icon=layer_data["icon"],
                color=layer_data["color"],
                enabled=True,
                refresh_interval_seconds=layer_data["refresh_interval_seconds"],
                description=layer_data.get("description"),
                active_entry_count=active_counts.get(feed_name, 0),
                total_entry_count=total_counts.get(feed_name, 0),
                latest_entry_at=latest_times.get(feed_name),
            ))

    # Include any orphan feeds present in DB entries but not in any layer config
    all_db_feeds_query = (
        select(ThreatFeedEntry.feed_name)
        .distinct()
    )
    all_db_feeds = (await db.execute(all_db_feeds_query)).scalars().all()
    for feed_name in all_db_feeds:
        if feed_name in seen_feed_names:
            continue
        seen_feed_names.add(feed_name)
        layer_name = _FEED_TO_LAYER.get(feed_name, "unknown")
        feeds.append(FeedInfo(
            feed_name=feed_name,
            layer=layer_name,
            display_name=feed_name.replace("_", " ").title(),
            icon="rss",
            color="#637381",
            enabled=True,
            refresh_interval_seconds=3600,
            description=None,
            active_entry_count=active_counts.get(feed_name, 0),
            total_entry_count=total_counts.get(feed_name, 0),
            latest_entry_at=latest_times.get(feed_name),
        ))

    total_active = sum(f.active_entry_count for f in feeds)

    return FeedSummary(
        total_feeds=len(feeds),
        total_active_entries=total_active,
        feeds=feeds,
    )


@router.get("/{feed_name}", response_model=FeedInfo)
async def get_feed(
    feed_name: str,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Get details for a single feed by name."""
    now = datetime.now(timezone.utc)

    # Find which layer this feed belongs to
    layer_query = select(ThreatLayer).where(
        ThreatLayer.feed_names.any(feed_name)
    )
    layer_result = await db.execute(layer_query)
    layer_obj = layer_result.scalars().first()

    # Active count
    active_count = (await db.execute(
        select(func.count()).select_from(ThreatFeedEntry).where(
            ThreatFeedEntry.feed_name == feed_name,
            or_(
                ThreatFeedEntry.expires_at.is_(None),
                ThreatFeedEntry.expires_at > now,
            ),
        )
    )).scalar() or 0

    # Total count
    total_count = (await db.execute(
        select(func.count()).select_from(ThreatFeedEntry).where(
            ThreatFeedEntry.feed_name == feed_name,
        )
    )).scalar() or 0

    if total_count == 0 and not layer_obj:
        raise HTTPException(404, f"Feed '{feed_name}' not found")

    # Latest entry
    latest = (await db.execute(
        select(func.max(ThreatFeedEntry.last_seen)).where(
            ThreatFeedEntry.feed_name == feed_name,
        )
    )).scalar()

    if layer_obj:
        return FeedInfo(
            feed_name=feed_name,
            layer=layer_obj.name,
            display_name=layer_obj.display_name,
            icon=layer_obj.icon,
            color=layer_obj.color,
            enabled=layer_obj.enabled,
            refresh_interval_seconds=layer_obj.refresh_interval_seconds,
            description=layer_obj.description,
            active_entry_count=active_count,
            total_entry_count=total_count,
            latest_entry_at=latest,
        )

    # Fallback for feeds not yet in a DB layer
    layer_name = _FEED_TO_LAYER.get(feed_name, "unknown")
    layer_conf = _LAYER_BY_NAME.get(layer_name, {})
    return FeedInfo(
        feed_name=feed_name,
        layer=layer_name,
        display_name=layer_conf.get("display_name", feed_name.replace("_", " ").title()),
        icon=layer_conf.get("icon", "rss"),
        color=layer_conf.get("color", "#637381"),
        enabled=True,
        refresh_interval_seconds=layer_conf.get("refresh_interval_seconds", 3600),
        description=layer_conf.get("description"),
        active_entry_count=active_count,
        total_entry_count=total_count,
        latest_entry_at=latest,
    )


async def _run_feed_in_background(feed_name: str) -> None:
    """Execute a single feed poll in the background, then run triage."""
    from src.feeds.scheduler import FeedScheduler
    try:
        scheduler = FeedScheduler()
        await scheduler.run_once(feed_name=feed_name)
        logger.info("Manual feed trigger completed: %s", feed_name)

        # Auto-run feed triage after ingestion
        try:
            from src.agents.feed_triage import FeedTriageService
            from src.storage.database import async_session_factory
            if async_session_factory:
                async with async_session_factory() as session:
                    triage_svc = FeedTriageService(session)
                    summary = await triage_svc.process_new_entries(hours=1, trigger="auto_post_feed")
                    logger.info("Post-feed triage: %s", summary)
        except Exception:
            logger.exception("Post-feed triage failed (non-fatal)")

    except Exception:
        logger.exception("Manual feed trigger failed: %s", feed_name)


# Track in-progress manual triggers to prevent concurrent runs of the same feed
_running_triggers: set[str] = set()


@router.post("/triage", status_code=202)
async def trigger_feed_triage(
    user: AnalystUser,
    hours: int = Query(default=6, ge=1, le=168),
    db: AsyncSession = Depends(get_session),
):
    """Run AI triage on recent feed entries — creates IOCs and alerts.

    This is the agentic brain: it analyzes feed data, extracts IOCs,
    correlates threats, and generates actionable alerts with LLM reasoning.
    """
    from src.agents.feed_triage import FeedTriageService

    async def _run_triage():
        from src.storage.database import async_session_factory
        if async_session_factory:
            async with async_session_factory() as session:
                svc = FeedTriageService(session)
                summary = await svc.process_new_entries(hours=hours, trigger="manual")
                logger.info("Manual feed triage: %s", summary)

    asyncio.get_running_loop().create_task(_run_triage())

    return {
        "message": f"Feed triage dispatched for last {hours}h of entries",
        "status": "running",
    }


@router.post("/backfill-geo", status_code=202)
async def backfill_geolocation_endpoint(
    user: AnalystUser,
):
    """Retroactively resolve domains/URLs → IP → lat/lng for entries missing geolocation.

    This resolves ~20K+ URL entries (URLhaus, OpenPhish, etc.) that were ingested
    without coordinates, putting thousands more dots on the threat map.
    """
    async def _run_backfill():
        from src.storage.database import async_session_factory
        from src.feeds.pipeline import backfill_geolocation
        from src.feeds.geolocation import GeoLocator
        if async_session_factory:
            geo = GeoLocator()
            try:
                async with async_session_factory() as session:
                    summary = await backfill_geolocation(session, geo)
                    logger.info("Geolocation backfill complete: %s", summary)
            finally:
                geo.close()

    asyncio.get_running_loop().create_task(_run_backfill())

    return {
        "message": "Geolocation backfill dispatched — resolving domains to IPs for map display",
        "status": "running",
    }


@router.post("/{feed_name}/trigger", response_model=FeedTriggerResponse, status_code=202)
async def trigger_feed(
    feed_name: str,
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Trigger a manual feed poll.

    Validates the feed exists, checks it isn't already running, then
    dispatches the poll as a background task and returns 202 Accepted.
    """
    # Validate feed exists in a known layer
    layer_query = select(ThreatLayer).where(
        ThreatLayer.feed_names.any(feed_name)
    )
    layer_result = await db.execute(layer_query)
    layer_obj = layer_result.scalars().first()

    # Also check if it's a known default feed
    if not layer_obj and feed_name not in _FEED_TO_LAYER:
        raise HTTPException(404, f"Feed '{feed_name}' is not a known feed")

    if layer_obj and not layer_obj.enabled:
        raise HTTPException(
            409,
            f"Feed '{feed_name}' belongs to disabled layer '{layer_obj.name}'. Enable the layer first.",
        )

    # Prevent concurrent manual triggers of the same feed
    if feed_name in _running_triggers:
        raise HTTPException(
            409,
            f"Feed '{feed_name}' is already being polled. Wait for it to complete.",
        )

    # Find which feed class handles this feed_name by checking the scheduler's
    # feed registry. The scheduler's run_once method matches by feed.name.
    # For multi-source feeds (e.g. BotnetFeed produces feodo_tracker + c2_tracker),
    # we need to find the parent feed class name.
    from src.feeds.scheduler import DEFAULT_FEED_SCHEDULES
    parent_feed_name: str | None = None
    for schedule in DEFAULT_FEED_SCHEDULES:
        feed_instance = schedule.feed_class()
        if feed_instance.name == feed_name:
            parent_feed_name = feed_name
            break
        # Check if this feed class's entries include the requested feed_name
        # by looking at the seed layer config
        layer_name = _FEED_TO_LAYER.get(feed_name)
        if layer_name and feed_instance.layer == layer_name:
            parent_feed_name = feed_instance.name
            break

    if not parent_feed_name:
        raise HTTPException(
            404,
            f"Feed '{feed_name}' has no registered feed class in the scheduler.",
        )

    async def _tracked_run() -> None:
        _running_triggers.add(feed_name)
        try:
            await _run_feed_in_background(parent_feed_name)
        finally:
            _running_triggers.discard(feed_name)

    # Dispatch as a true async background task
    asyncio.get_running_loop().create_task(_tracked_run())

    return FeedTriggerResponse(
        feed_name=feed_name,
        message=f"Manual poll for '{feed_name}' dispatched. Ingestion is running in the background.",
        status="running",
    )
