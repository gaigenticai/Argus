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


# ---------------------------------------------------------------------------
# Drill-down endpoints — feed/layer detail panels.
#
# The Feed Health card lists feeds and layers as flat read-only rows
# with only a "Run now" button. Operators (and customers in a demo)
# need to click through to "what's actually flowing through dshield"
# without leaving the dashboard. The endpoints below back the new
# per-feed drawer and per-layer detail page.
# ---------------------------------------------------------------------------


class FeedEntryRow(BaseModel):
    """Single feed entry row for the per-feed drawer table."""

    id: str
    entry_type: str
    value: str
    label: str | None
    severity: str
    confidence: float
    country_code: str | None
    asn: str | None
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None


class FeedEntriesResponse(BaseModel):
    feed_name: str
    layer: str
    total_returned: int
    entries: list[FeedEntryRow]


@router.get("/{feed_name}/entries", response_model=FeedEntriesResponse)
async def get_feed_entries(
    feed_name: str,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
    limit: int = Query(default=20, ge=1, le=100),
    severity: str | None = Query(default=None),
):
    """Return the latest entries ingested by this feed.

    Powers the per-feed drawer's sample table. Capped at 100 to
    keep the drawer snappy; the operator can deep-link to the full
    Threat Map / Intel views for exhaustive exploration.
    """
    q = select(ThreatFeedEntry).where(ThreatFeedEntry.feed_name == feed_name)
    if severity:
        q = q.where(ThreatFeedEntry.severity == severity)
    q = q.order_by(ThreatFeedEntry.last_seen.desc()).limit(limit)
    rows = (await db.execute(q)).scalars().all()

    layer_name = _FEED_TO_LAYER.get(feed_name) or (rows[0].layer if rows else "unknown")

    return FeedEntriesResponse(
        feed_name=feed_name,
        layer=layer_name,
        total_returned=len(rows),
        entries=[
            FeedEntryRow(
                id=str(r.id),
                entry_type=r.entry_type,
                value=r.value,
                label=r.label,
                severity=r.severity,
                confidence=r.confidence,
                country_code=r.country_code,
                asn=r.asn,
                first_seen=r.first_seen,
                last_seen=r.last_seen,
                expires_at=r.expires_at,
            )
            for r in rows
        ],
    )


class TypeCount(BaseModel):
    entry_type: str
    count: int


class CountryCount(BaseModel):
    country_code: str
    count: int


class FetchHealthRow(BaseModel):
    """One observed feed-poll attempt — what the upstream actually did."""

    status: str          # ok | unconfigured | auth_error | network_error | rate_limited | parse_error | disabled
    detail: str | None
    rows_ingested: int
    duration_ms: int | None
    observed_at: datetime


class FeedStatsResponse(BaseModel):
    """Per-feed analytics for the drawer header strip."""

    feed_name: str
    layer: str
    total_entries: int
    active_entries: int
    by_type: list[TypeCount]
    by_country: list[CountryCount]
    iocs_promoted: int
    alerts_referencing: int
    latest_entry_at: datetime | None
    last_fetch: FetchHealthRow | None
    recent_fetches: list[FetchHealthRow]


@router.get("/{feed_name}/stats", response_model=FeedStatsResponse)
async def get_feed_stats(
    feed_name: str,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Return drill-down analytics for one feed.

    Includes type/country breakdowns plus the operationally meaningful
    "what did this feed produce" — promoted IOCs and alerts that
    referenced its entries via IOC ``tags``.
    """
    from src.models.intel import IOC
    from src.models.threat import Alert

    now = datetime.now(timezone.utc)

    layer_name = _FEED_TO_LAYER.get(feed_name) or "unknown"

    total_q = await db.execute(
        select(func.count())
        .select_from(ThreatFeedEntry)
        .where(ThreatFeedEntry.feed_name == feed_name)
    )
    total = total_q.scalar() or 0

    active_q = await db.execute(
        select(func.count())
        .select_from(ThreatFeedEntry)
        .where(
            ThreatFeedEntry.feed_name == feed_name,
            or_(
                ThreatFeedEntry.expires_at.is_(None),
                ThreatFeedEntry.expires_at > now,
            ),
        )
    )
    active = active_q.scalar() or 0

    type_q = await db.execute(
        select(ThreatFeedEntry.entry_type, func.count())
        .where(ThreatFeedEntry.feed_name == feed_name)
        .group_by(ThreatFeedEntry.entry_type)
        .order_by(func.count().desc())
    )
    by_type = [TypeCount(entry_type=t, count=c) for t, c in type_q.all()]

    country_q = await db.execute(
        select(ThreatFeedEntry.country_code, func.count())
        .where(
            ThreatFeedEntry.feed_name == feed_name,
            ThreatFeedEntry.country_code.is_not(None),
        )
        .group_by(ThreatFeedEntry.country_code)
        .order_by(func.count().desc())
        .limit(10)
    )
    by_country = [CountryCount(country_code=cc, count=c) for cc, c in country_q.all() if cc]

    # IOCs carry the source feed_name in their ``tags`` array (see
    # FeedTriageService._create_iocs_from_feeds). Postgres ARRAY
    # contains operator gives us a feed-scoped IOC count without a
    # separate provenance table.
    iocs_q = await db.execute(
        select(func.count(IOC.id))
        .where(IOC.tags.contains([feed_name]))
    )
    iocs_promoted = iocs_q.scalar() or 0

    # Alerts that reference IOCs from this feed: join through
    # source_alert_id. (Distinct because one alert can have multiple
    # IOCs from the same feed.)
    alerts_q = await db.execute(
        select(func.count(Alert.id.distinct()))
        .join(IOC, IOC.source_alert_id == Alert.id)
        .where(IOC.tags.contains([feed_name]))
    )
    alerts_ref = alerts_q.scalar() or 0

    latest_q = await db.execute(
        select(func.max(ThreatFeedEntry.last_seen))
        .where(ThreatFeedEntry.feed_name == feed_name)
    )
    latest = latest_q.scalar()

    # Pull the last 10 poll attempts from feed_health so the operator
    # can SEE the upstream HTTP call land (status, detail, rows
    # ingested, duration). Without this, "active entries: 107k" looks
    # convincing but the operator can't distinguish a healthy live
    # feed from a one-time backfill of stale data.
    from src.models.admin import FeedHealth

    health_q = await db.execute(
        select(FeedHealth)
        .where(FeedHealth.feed_name == feed_name)
        .order_by(FeedHealth.observed_at.desc())
        .limit(10)
    )
    health_rows = list(health_q.scalars().all())
    recent_fetches = [
        FetchHealthRow(
            status=h.status,
            detail=h.detail,
            rows_ingested=h.rows_ingested,
            duration_ms=h.duration_ms,
            observed_at=h.observed_at,
        )
        for h in health_rows
    ]
    last_fetch = recent_fetches[0] if recent_fetches else None

    return FeedStatsResponse(
        feed_name=feed_name,
        layer=layer_name,
        total_entries=total,
        active_entries=active,
        by_type=by_type,
        by_country=by_country,
        iocs_promoted=iocs_promoted,
        alerts_referencing=alerts_ref,
        latest_entry_at=latest,
        last_fetch=last_fetch,
        recent_fetches=recent_fetches,
    )


class FeedInLayer(BaseModel):
    feed_name: str
    active_entry_count: int
    total_entry_count: int
    latest_entry_at: datetime | None
    enabled: bool


class LayerSummaryResponse(BaseModel):
    """Aggregate summary for one layer's detail page."""

    layer: str
    display_name: str
    description: str | None
    color: str
    icon: str
    total_entries: int
    active_entries: int
    by_severity: list[TypeCount]
    by_country: list[CountryCount]
    feeds: list[FeedInLayer]
    latest_entry_at: datetime | None


@router.get("/layers/{layer}/summary", response_model=LayerSummaryResponse)
async def get_layer_summary(
    layer: str,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Return the layer detail page's aggregate stats."""
    now = datetime.now(timezone.utc)

    layer_q = await db.execute(select(ThreatLayer).where(ThreatLayer.name == layer))
    layer_obj = layer_q.scalars().first()
    if layer_obj is None:
        # Fallback: layer name from seed config but no DB row yet.
        seed = _LAYER_BY_NAME.get(layer)
        if not seed:
            raise HTTPException(404, f"Layer '{layer}' not found")

        class _Fake:
            name = layer
            display_name = seed.get("display_name", layer)
            description = seed.get("description")
            color = seed.get("color", "#637381")
            icon = seed.get("icon", "rss")
            feed_names = seed.get("feed_names", [])
            enabled = True
        layer_obj = _Fake()  # type: ignore[assignment]

    total_q = await db.execute(
        select(func.count())
        .select_from(ThreatFeedEntry)
        .where(ThreatFeedEntry.layer == layer)
    )
    total = total_q.scalar() or 0

    active_q = await db.execute(
        select(func.count())
        .select_from(ThreatFeedEntry)
        .where(
            ThreatFeedEntry.layer == layer,
            or_(
                ThreatFeedEntry.expires_at.is_(None),
                ThreatFeedEntry.expires_at > now,
            ),
        )
    )
    active = active_q.scalar() or 0

    sev_q = await db.execute(
        select(ThreatFeedEntry.severity, func.count())
        .where(ThreatFeedEntry.layer == layer)
        .group_by(ThreatFeedEntry.severity)
        .order_by(func.count().desc())
    )
    by_severity = [TypeCount(entry_type=s, count=c) for s, c in sev_q.all()]

    country_q = await db.execute(
        select(ThreatFeedEntry.country_code, func.count())
        .where(
            ThreatFeedEntry.layer == layer,
            ThreatFeedEntry.country_code.is_not(None),
        )
        .group_by(ThreatFeedEntry.country_code)
        .order_by(func.count().desc())
        .limit(10)
    )
    by_country = [CountryCount(country_code=cc, count=c) for cc, c in country_q.all() if cc]

    # Per-feed rollup within this layer.
    feeds_out: list[FeedInLayer] = []
    for fn in (layer_obj.feed_names or []):
        f_active = (await db.execute(
            select(func.count()).select_from(ThreatFeedEntry).where(
                ThreatFeedEntry.feed_name == fn,
                or_(ThreatFeedEntry.expires_at.is_(None), ThreatFeedEntry.expires_at > now),
            )
        )).scalar() or 0
        f_total = (await db.execute(
            select(func.count()).select_from(ThreatFeedEntry).where(
                ThreatFeedEntry.feed_name == fn,
            )
        )).scalar() or 0
        f_latest = (await db.execute(
            select(func.max(ThreatFeedEntry.last_seen)).where(
                ThreatFeedEntry.feed_name == fn,
            )
        )).scalar()
        feeds_out.append(
            FeedInLayer(
                feed_name=fn,
                active_entry_count=f_active,
                total_entry_count=f_total,
                latest_entry_at=f_latest,
                enabled=getattr(layer_obj, "enabled", True),
            )
        )

    latest_q = await db.execute(
        select(func.max(ThreatFeedEntry.last_seen))
        .where(ThreatFeedEntry.layer == layer)
    )
    latest = latest_q.scalar()

    return LayerSummaryResponse(
        layer=layer_obj.name,
        display_name=layer_obj.display_name,
        description=layer_obj.description,
        color=layer_obj.color,
        icon=layer_obj.icon,
        total_entries=total,
        active_entries=active,
        by_severity=by_severity,
        by_country=by_country,
        feeds=feeds_out,
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

    Returns the previous run's id so the client can poll
    ``GET /feeds/triage/latest`` and detect when a NEW run has
    completed (id changes AND ``status != "running"``).
    """
    from src.agents.feed_triage import FeedTriageService
    from src.models.intel import TriageRun

    prev_q = await db.execute(
        select(TriageRun.id).order_by(TriageRun.created_at.desc()).limit(1)
    )
    prev_run_id = prev_q.scalar_one_or_none()

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
        "previous_run_id": str(prev_run_id) if prev_run_id else None,
    }


class TriageRunSummary(BaseModel):
    id: str
    status: str
    trigger: str
    hours_window: int
    entries_processed: int
    iocs_created: int
    alerts_generated: int
    duration_seconds: float
    error_message: str | None
    created_at: datetime


@router.get("/triage/latest", response_model=TriageRunSummary | None)
async def get_latest_triage_run(
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> TriageRunSummary | None:
    """Return the most recent TriageRun row, or null if none exist.

    Polled by the dashboard's AI Triage Agent card so the operator
    sees real progress (running → completed/error) and the resulting
    IOC + alert counts instead of a fake 3s spinner.
    """
    from src.models.intel import TriageRun

    q = await db.execute(
        select(TriageRun).order_by(TriageRun.created_at.desc()).limit(1)
    )
    run = q.scalar_one_or_none()
    if run is None:
        return None
    return TriageRunSummary(
        id=str(run.id),
        status=run.status,
        trigger=run.trigger,
        hours_window=run.hours_window,
        entries_processed=run.entries_processed,
        iocs_created=run.iocs_created,
        alerts_generated=run.alerts_generated,
        duration_seconds=run.duration_seconds,
        error_message=run.error_message,
        created_at=run.created_at,
    )


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
    # Validate the feed is reachable through SOME path:
    #   1. Belongs to an enabled ThreatLayer's ``feed_names`` array
    #      (the curated layer config), or
    #   2. Is in the ``_FEED_TO_LAYER`` static seed map, or
    #   3. Has a registered scheduler class with that ``.name``
    #      (orphan feeds that aren't yet wired into a layer config —
    #      e.g. circl_osint, phishtank_certpl, digitalside_osint —
    #      still expose themselves through the scheduler, the UI
    #      still lists them, and the operator must be able to
    #      trigger them), or
    #   4. Is a known multi-emit alias.
    layer_query = select(ThreatLayer).where(
        ThreatLayer.feed_names.any(feed_name)
    )
    layer_result = await db.execute(layer_query)
    layer_obj = layer_result.scalars().first()

    from src.feeds.scheduler import DEFAULT_FEED_SCHEDULES, _FEED_NAME_ALIASES
    scheduled_class_names = {sched.feed_class().name for sched in DEFAULT_FEED_SCHEDULES}

    if (
        not layer_obj
        and feed_name not in _FEED_TO_LAYER
        and feed_name not in scheduled_class_names
        and feed_name not in _FEED_NAME_ALIASES
    ):
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

    # The scheduler's ``run_once`` is the source of truth for
    # resolving a feed_name to its owning class:
    #   1. exact class .name match (the common case)
    #   2. ``_FEED_NAME_ALIASES`` for multi-emit classes
    #      (BotnetFeed → c2_tracker, PhishingFeed → phishstats, …)
    # Previous code here used "first class with matching layer" which
    # was wrong for ``greynoise`` (lives in 3 layers — picked KEVFeed
    # by accident → trigger ran a completely unrelated feed). Pass
    # the feed_name through verbatim and let the scheduler decide.
    from src.feeds.scheduler import DEFAULT_FEED_SCHEDULES, _FEED_NAME_ALIASES
    known_class_names = {schedule.feed_class().name for schedule in DEFAULT_FEED_SCHEDULES}
    if feed_name not in known_class_names and feed_name not in _FEED_NAME_ALIASES:
        raise HTTPException(
            404,
            f"Feed '{feed_name}' has no registered feed class in the scheduler.",
        )

    async def _tracked_run() -> None:
        _running_triggers.add(feed_name)
        try:
            await _run_feed_in_background(feed_name)
        finally:
            _running_triggers.discard(feed_name)

    # Dispatch as a true async background task
    asyncio.get_running_loop().create_task(_tracked_run())

    return FeedTriggerResponse(
        feed_name=feed_name,
        message=f"Manual poll for '{feed_name}' dispatched. Ingestion is running in the background.",
        status="running",
    )
