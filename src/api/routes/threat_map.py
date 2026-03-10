"""Threat map endpoints — layers, entries, stats, heatmap, timeline, live WebSocket."""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy import select, func, desc, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.activity import activity_bus, ActivityType
from src.core.auth import CurrentUser, AdminUser
from src.models.feeds import ThreatFeedEntry, ThreatLayer, GlobalThreatStatus
from src.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-map", tags=["threat-map"])

_MAX_HOURS = 168  # 7 days


# ---------------------------------------------------------------------------
# Pydantic response schemas
# ---------------------------------------------------------------------------


class ThreatLayerResponse(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str
    icon: str
    color: str
    enabled: bool
    feed_names: list[str]
    refresh_interval_seconds: int
    description: str | None
    entry_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ThreatEntryListItem(BaseModel):
    """Lightweight entry for list/map rendering — no description or feed_metadata."""
    id: uuid.UUID
    feed_name: str
    layer: str
    entry_type: str
    value: str
    label: str | None
    severity: str
    confidence: float
    latitude: float | None
    longitude: float | None
    country_code: str | None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class ThreatEntryDetail(BaseModel):
    """Full entry detail including heavy fields."""
    id: uuid.UUID
    feed_name: str
    layer: str
    entry_type: str
    value: str
    label: str | None
    description: str | None
    severity: str
    confidence: float
    latitude: float | None
    longitude: float | None
    country_code: str | None
    city: str | None
    asn: str | None
    feed_metadata: dict | None
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ThreatStatsResponse(BaseModel):
    infocon_level: str
    active_ransomware_groups: int
    active_c2_servers: int
    active_phishing_campaigns: int
    exploited_cves_count: int
    tor_exit_nodes_count: int
    malware_urls_count: int
    malicious_ips_count: int
    total_entries: int
    last_updated: datetime | None


class HeatmapCountry(BaseModel):
    country_code: str
    count: int
    layers: dict[str, int]


class TimelineBucket(BaseModel):
    hour: datetime
    count: int


class EntriesPage(BaseModel):
    items: list[ThreatEntryListItem]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _time_window(hours: int) -> datetime:
    """Return a UTC datetime `hours` ago, clamped to _MAX_HOURS."""
    clamped = min(max(hours, 1), _MAX_HOURS)
    return datetime.now(timezone.utc) - timedelta(hours=clamped)


_ENTRY_LIST_COLUMNS = [
    ThreatFeedEntry.id,
    ThreatFeedEntry.feed_name,
    ThreatFeedEntry.layer,
    ThreatFeedEntry.entry_type,
    ThreatFeedEntry.value,
    ThreatFeedEntry.label,
    ThreatFeedEntry.severity,
    ThreatFeedEntry.confidence,
    ThreatFeedEntry.latitude,
    ThreatFeedEntry.longitude,
    ThreatFeedEntry.country_code,
    ThreatFeedEntry.first_seen,
    ThreatFeedEntry.last_seen,
]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/layers", response_model=list[ThreatLayerResponse])
async def list_layers(
    user: CurrentUser,
    all: bool = Query(False, description="Include disabled layers (admin only)"),
    db: AsyncSession = Depends(get_session),
):
    """Return threat map layers. Only enabled layers by default."""
    query = select(ThreatLayer).order_by(ThreatLayer.name)

    if all:
        # Only admins may see disabled layers
        if user.role != "admin":
            raise HTTPException(403, "Only admins can view disabled layers")
    else:
        query = query.where(ThreatLayer.enabled == True)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/entries", response_model=EntriesPage)
async def list_entries(
    user: CurrentUser,
    layer: str | None = None,
    severity: str | None = None,
    min_lat: float | None = Query(None, ge=-90, le=90),
    max_lat: float | None = Query(None, ge=-90, le=90),
    min_lng: float | None = Query(None, ge=-180, le=180),
    max_lng: float | None = Query(None, ge=-180, le=180),
    hours: int = Query(24, ge=1, le=_MAX_HOURS),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
):
    """List threat feed entries with viewport, time, and layer filters.

    Returns lightweight objects (no description/feed_metadata) for map rendering.
    """
    now = datetime.now(timezone.utc)
    since = _time_window(hours)

    # Base conditions: non-expired and within time window
    conditions = [
        or_(
            ThreatFeedEntry.expires_at.is_(None),
            ThreatFeedEntry.expires_at > now,
        ),
        ThreatFeedEntry.created_at >= since,
    ]

    if layer:
        conditions.append(ThreatFeedEntry.layer == layer)
    if severity:
        conditions.append(ThreatFeedEntry.severity == severity)

    # Viewport bounds — only applied when all four corners are given
    if min_lat is not None and max_lat is not None and min_lng is not None and max_lng is not None:
        conditions.append(ThreatFeedEntry.latitude.is_not(None))
        conditions.append(ThreatFeedEntry.longitude.is_not(None))
        conditions.append(ThreatFeedEntry.latitude >= min_lat)
        conditions.append(ThreatFeedEntry.latitude <= max_lat)
        conditions.append(ThreatFeedEntry.longitude >= min_lng)
        conditions.append(ThreatFeedEntry.longitude <= max_lng)

    where_clause = and_(*conditions)

    # Total count for pagination
    count_query = select(func.count()).select_from(ThreatFeedEntry).where(where_clause)
    total = (await db.execute(count_query)).scalar() or 0

    # Fetch page
    data_query = (
        select(*_ENTRY_LIST_COLUMNS)
        .where(where_clause)
        .order_by(desc(ThreatFeedEntry.last_seen))
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(data_query)).all()

    items = [
        ThreatEntryListItem(
            id=row.id,
            feed_name=row.feed_name,
            layer=row.layer,
            entry_type=row.entry_type,
            value=row.value,
            label=row.label,
            severity=row.severity,
            confidence=row.confidence,
            latitude=row.latitude,
            longitude=row.longitude,
            country_code=row.country_code,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
        )
        for row in rows
    ]

    return EntriesPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/entry/{entry_id}", response_model=ThreatEntryDetail)
async def get_entry(
    entry_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Full detail of a single threat feed entry."""
    entry = await db.get(ThreatFeedEntry, entry_id)
    if not entry:
        raise HTTPException(404, "Threat feed entry not found")
    return entry


@router.get("/stats", response_model=ThreatStatsResponse)
async def threat_stats(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Global threat status dashboard data.

    Returns the latest GlobalThreatStatus row if it exists,
    otherwise computes counts from live ThreatFeedEntry data.
    """
    # Try stored global status first (most recent row)
    status_query = (
        select(GlobalThreatStatus)
        .order_by(desc(GlobalThreatStatus.updated_at))
        .limit(1)
    )
    result = await db.execute(status_query)
    status_row = result.scalar_one_or_none()

    # Total active (non-expired) entries
    now = datetime.now(timezone.utc)
    total_query = (
        select(func.count())
        .select_from(ThreatFeedEntry)
        .where(
            or_(
                ThreatFeedEntry.expires_at.is_(None),
                ThreatFeedEntry.expires_at > now,
            )
        )
    )
    total_entries = (await db.execute(total_query)).scalar() or 0

    if status_row:
        return ThreatStatsResponse(
            infocon_level=status_row.infocon_level,
            active_ransomware_groups=status_row.active_ransomware_groups,
            active_c2_servers=status_row.active_c2_servers,
            active_phishing_campaigns=status_row.active_phishing_campaigns,
            exploited_cves_count=status_row.exploited_cves_count,
            tor_exit_nodes_count=status_row.tor_exit_nodes_count,
            malware_urls_count=status_row.malware_urls_count,
            malicious_ips_count=status_row.malicious_ips_count,
            total_entries=total_entries,
            last_updated=status_row.updated_at,
        )

    # Fallback: compute from ThreatFeedEntry counts per layer
    layer_counts_query = (
        select(ThreatFeedEntry.layer, func.count())
        .where(
            or_(
                ThreatFeedEntry.expires_at.is_(None),
                ThreatFeedEntry.expires_at > now,
            )
        )
        .group_by(ThreatFeedEntry.layer)
    )
    layer_rows = (await db.execute(layer_counts_query)).all()
    lc = {row[0]: row[1] for row in layer_rows}

    return ThreatStatsResponse(
        infocon_level="green",
        active_ransomware_groups=lc.get("ransomware", 0),
        active_c2_servers=lc.get("botnet_c2", 0),
        active_phishing_campaigns=lc.get("phishing", 0),
        exploited_cves_count=lc.get("exploited_cve", 0),
        tor_exit_nodes_count=lc.get("tor_exit", 0),
        malware_urls_count=lc.get("malware", 0),
        malicious_ips_count=lc.get("ip_reputation", 0),
        total_entries=total_entries,
        last_updated=None,
    )


@router.get("/heatmap", response_model=list[HeatmapCountry])
async def heatmap(
    user: CurrentUser,
    layer: str | None = None,
    hours: int = Query(24, ge=1, le=_MAX_HOURS),
    db: AsyncSession = Depends(get_session),
):
    """Aggregated entry counts by country_code for choropleth rendering.

    Returns per-country totals and a breakdown by layer.
    """
    now = datetime.now(timezone.utc)
    since = _time_window(hours)

    # Base conditions
    conditions = [
        ThreatFeedEntry.country_code.is_not(None),
        ThreatFeedEntry.created_at >= since,
        or_(
            ThreatFeedEntry.expires_at.is_(None),
            ThreatFeedEntry.expires_at > now,
        ),
    ]
    if layer:
        conditions.append(ThreatFeedEntry.layer == layer)

    where_clause = and_(*conditions)

    # Country totals
    total_query = (
        select(ThreatFeedEntry.country_code, func.count().label("count"))
        .where(where_clause)
        .group_by(ThreatFeedEntry.country_code)
        .order_by(desc("count"))
    )
    total_rows = (await db.execute(total_query)).all()

    if not total_rows:
        return []

    country_codes = [row[0] for row in total_rows]
    country_totals = {row[0]: row[1] for row in total_rows}

    # Per-country per-layer breakdown
    breakdown_query = (
        select(
            ThreatFeedEntry.country_code,
            ThreatFeedEntry.layer,
            func.count().label("count"),
        )
        .where(
            and_(
                where_clause,
                ThreatFeedEntry.country_code.in_(country_codes),
            )
        )
        .group_by(ThreatFeedEntry.country_code, ThreatFeedEntry.layer)
    )
    breakdown_rows = (await db.execute(breakdown_query)).all()

    # Build nested dict: {country: {layer: count}}
    layers_by_country: dict[str, dict[str, int]] = {}
    for row in breakdown_rows:
        layers_by_country.setdefault(row[0], {})[row[1]] = row[2]

    return [
        HeatmapCountry(
            country_code=cc,
            count=country_totals[cc],
            layers=layers_by_country.get(cc, {}),
        )
        for cc in country_codes
    ]


@router.get("/timeline", response_model=list[TimelineBucket])
async def timeline(
    user: CurrentUser,
    layer: str | None = None,
    hours: int = Query(24, ge=1, le=_MAX_HOURS),
    db: AsyncSession = Depends(get_session),
):
    """Time-series entry counts per hour for charting."""
    now = datetime.now(timezone.utc)
    since = _time_window(hours)

    conditions = [
        ThreatFeedEntry.created_at >= since,
        or_(
            ThreatFeedEntry.expires_at.is_(None),
            ThreatFeedEntry.expires_at > now,
        ),
    ]
    if layer:
        conditions.append(ThreatFeedEntry.layer == layer)

    hour_trunc = func.date_trunc("hour", ThreatFeedEntry.created_at).label("hour")
    query = (
        select(hour_trunc, func.count().label("count"))
        .where(and_(*conditions))
        .group_by(hour_trunc)
        .order_by(hour_trunc)
    )
    rows = (await db.execute(query)).all()

    return [TimelineBucket(hour=row[0], count=row[1]) for row in rows]


# ---------------------------------------------------------------------------
# WebSocket — live threat feed events
# ---------------------------------------------------------------------------

_LIVE_EVENT_TYPES = {
    ActivityType.FEED_RESULT.value,
    ActivityType.FEED_COMPLETE.value,
    ActivityType.THREAT_STATUS_UPDATE.value,
}


@router.websocket("/live")
async def threat_map_live(ws: WebSocket):
    """WebSocket that streams live feed/threat activity events to the client.

    Subscribes to the global activity bus and filters for feed-related events.
    The client receives JSON messages with the same schema as the SSE activity
    stream, but filtered to threat-map-relevant event types only.
    """
    await ws.accept()
    queue = activity_bus.subscribe()

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                if event.event_type in _LIVE_EVENT_TYPES:
                    await ws.send_text(json.dumps(event.to_dict()))
            except asyncio.TimeoutError:
                # Keepalive ping to detect dead connections
                try:
                    await ws.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as exc:
        logger.warning("WebSocket /threat-map/live closed unexpectedly: %s", exc)
    finally:
        activity_bus.unsubscribe(queue)
