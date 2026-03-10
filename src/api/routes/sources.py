"""Crawler source management endpoints."""

import time
import uuid
from datetime import datetime, timezone

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.core.auth import AdminUser, AnalystUser, CurrentUser, audit_log
from src.models.auth import AuditAction
from src.models.intel import CrawlerSource, CrawlerSourceType, SourceHealthStatus
from src.storage.database import get_session

router = APIRouter(prefix="/sources", tags=["sources"])


# --- Schemas ---


class SourceCreate(BaseModel):
    name: str
    source_type: str
    url: str
    mirror_urls: list[str] | None = None
    selectors: dict | None = None
    fallback_selectors: dict | None = None
    auth_config: dict | None = None
    language: str = "en"
    enabled: bool = True
    priority: int = 50
    crawl_interval_minutes: int = 30
    max_pages: int = 5
    notes: str | None = None


class SourceUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    mirror_urls: list[str] | None = None
    selectors: dict | None = None
    fallback_selectors: dict | None = None
    auth_config: dict | None = None
    language: str | None = None
    enabled: bool | None = None
    priority: int | None = None
    crawl_interval_minutes: int | None = None
    max_pages: int | None = None
    notes: str | None = None


class SourceResponse(BaseModel):
    id: uuid.UUID
    name: str
    source_type: str
    url: str
    mirror_urls: list[str] | None
    selectors: dict | None
    fallback_selectors: dict | None
    auth_config: dict | None
    language: str
    enabled: bool
    priority: int
    crawl_interval_minutes: int
    max_pages: int
    last_crawled_at: datetime | None
    last_success_at: datetime | None
    health_status: str
    consecutive_failures: int
    total_items_collected: int
    notes: str | None
    last_structure_hash: str | None
    structure_changed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SourceTestResult(BaseModel):
    reachable: bool
    status_code: int | None
    response_time_ms: float | None
    content_preview: str | None
    error: str | None
    blocked: bool


class HealthSummary(BaseModel):
    total: int
    healthy: int
    degraded: int
    unreachable: int
    blocked: int
    unknown: int
    enabled: int
    disabled: int


# --- Helpers ---


def _is_onion(url: str) -> bool:
    return ".onion" in url


def _is_i2p(url: str) -> bool:
    return ".i2p" in url


async def _test_source_connectivity(source: CrawlerSource) -> SourceTestResult:
    """Actually fetch the source URL and report connectivity."""
    url = source.url
    timeout = aiohttp.ClientTimeout(total=settings.crawler.timeout)
    start = time.monotonic()
    connector = None
    proxy = None

    try:
        if _is_onion(url):
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(settings.tor.socks_proxy)
        elif _is_i2p(url):
            proxy = settings.i2p.proxy_url

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        ) as session:
            async with session.get(url, proxy=proxy, ssl=False) as resp:
                elapsed_ms = (time.monotonic() - start) * 1000
                body = await resp.text(errors="replace")
                preview = body[:500] if body else ""

                # Check for blocking patterns
                blocked = _check_blocking(body)

                return SourceTestResult(
                    reachable=True,
                    status_code=resp.status,
                    response_time_ms=round(elapsed_ms, 2),
                    content_preview=preview,
                    error=None,
                    blocked=blocked,
                )
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        return SourceTestResult(
            reachable=False,
            status_code=None,
            response_time_ms=round(elapsed_ms, 2),
            content_preview=None,
            error=str(exc),
            blocked=False,
        )


def _check_blocking(text: str) -> bool:
    """Detect common blocking patterns in response text."""
    if not text:
        return False
    lower = text.lower()
    patterns = [
        "access denied",
        "403 forbidden",
        "captcha",
        "cf-browser-verification",
        "cloudflare",
        "ddos-guard",
        "please enable javascript",
        "just a moment",
        "checking your browser",
        "attention required",
        "blocked",
        "rate limit",
        "too many requests",
    ]
    return any(p in lower for p in patterns)


# --- Routes ---


@router.get("/health", response_model=HealthSummary)
async def sources_health_summary(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Health summary across all crawler sources."""
    total_q = select(func.count()).select_from(CrawlerSource)
    total = (await db.execute(total_q)).scalar() or 0

    # Count by health status
    health_q = (
        select(CrawlerSource.health_status, func.count())
        .group_by(CrawlerSource.health_status)
    )
    health_rows = (await db.execute(health_q)).all()
    health_map = {row[0]: row[1] for row in health_rows}

    # Count enabled/disabled
    enabled_q = select(func.count()).select_from(CrawlerSource).where(CrawlerSource.enabled == True)
    enabled = (await db.execute(enabled_q)).scalar() or 0

    return HealthSummary(
        total=total,
        healthy=health_map.get(SourceHealthStatus.HEALTHY.value, 0),
        degraded=health_map.get(SourceHealthStatus.DEGRADED.value, 0),
        unreachable=health_map.get(SourceHealthStatus.UNREACHABLE.value, 0),
        blocked=health_map.get(SourceHealthStatus.BLOCKED.value, 0),
        unknown=health_map.get(SourceHealthStatus.UNKNOWN.value, 0),
        enabled=enabled,
        disabled=total - enabled,
    )


@router.get("/", response_model=list[SourceResponse])
async def list_sources(
    user: CurrentUser,
    source_type: str | None = None,
    enabled: bool | None = None,
    health_status: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List all crawler sources with optional filters."""
    query = select(CrawlerSource).order_by(CrawlerSource.priority, CrawlerSource.name)

    if source_type:
        query = query.where(CrawlerSource.source_type == source_type)
    if enabled is not None:
        query = query.where(CrawlerSource.enabled == enabled)
    if health_status:
        query = query.where(CrawlerSource.health_status == health_status)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/", response_model=SourceResponse, status_code=201)
async def create_source(
    body: SourceCreate,
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Create a new crawler source."""
    # Validate source type
    try:
        CrawlerSourceType(body.source_type)
    except ValueError:
        valid = [t.value for t in CrawlerSourceType]
        raise HTTPException(400, f"Invalid source_type. Valid: {valid}")

    source = CrawlerSource(
        name=body.name,
        source_type=body.source_type,
        url=body.url,
        mirror_urls=body.mirror_urls,
        selectors=body.selectors,
        fallback_selectors=body.fallback_selectors,
        auth_config=body.auth_config,
        language=body.language,
        enabled=body.enabled,
        priority=body.priority,
        crawl_interval_minutes=body.crawl_interval_minutes,
        max_pages=body.max_pages,
        notes=body.notes,
        health_status=SourceHealthStatus.UNKNOWN.value,
    )
    db.add(source)

    await audit_log(
        db,
        AuditAction.CRAWLER_SOURCE_CREATE,
        user=user,
        resource_type="crawler_source",
        resource_id=str(source.id),
        details={"name": body.name, "url": body.url, "source_type": body.source_type},
    )

    await db.commit()
    await db.refresh(source)
    return source


@router.get("/{source_id}", response_model=SourceResponse)
async def get_source(
    source_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Get a single crawler source by ID."""
    source = await db.get(CrawlerSource, source_id)
    if not source:
        raise HTTPException(404, "Crawler source not found")
    return source


@router.patch("/{source_id}", response_model=SourceResponse)
async def update_source(
    source_id: uuid.UUID,
    body: SourceUpdate,
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Update a crawler source configuration."""
    source = await db.get(CrawlerSource, source_id)
    if not source:
        raise HTTPException(404, "Crawler source not found")

    changes = {}
    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        old_value = getattr(source, field)
        if old_value != value:
            setattr(source, field, value)
            changes[field] = {"old": str(old_value), "new": str(value)}

    if changes:
        await audit_log(
            db,
            AuditAction.CRAWLER_SOURCE_UPDATE,
            user=user,
            resource_type="crawler_source",
            resource_id=str(source_id),
            details=changes,
        )

    await db.commit()
    await db.refresh(source)
    return source


@router.delete("/{source_id}", status_code=204)
async def delete_source(
    source_id: uuid.UUID,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Delete a crawler source."""
    source = await db.get(CrawlerSource, source_id)
    if not source:
        raise HTTPException(404, "Crawler source not found")

    source_name = source.name
    await db.delete(source)

    await audit_log(
        db,
        AuditAction.CRAWLER_SOURCE_DELETE,
        user=user,
        resource_type="crawler_source",
        resource_id=str(source_id),
        details={"name": source_name},
    )

    await db.commit()


@router.post("/{source_id}/test", response_model=SourceTestResult)
async def test_source(
    source_id: uuid.UUID,
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Test connectivity to a crawler source by actually fetching the URL."""
    source = await db.get(CrawlerSource, source_id)
    if not source:
        raise HTTPException(404, "Crawler source not found")

    result = await _test_source_connectivity(source)

    # Update health status based on test result
    now = datetime.now(timezone.utc)
    if result.reachable and not result.blocked and result.status_code and result.status_code < 400:
        source.health_status = SourceHealthStatus.HEALTHY.value
        source.consecutive_failures = 0
        source.last_success_at = now
    elif result.blocked:
        source.health_status = SourceHealthStatus.BLOCKED.value
        source.consecutive_failures += 1
    elif result.reachable and result.status_code and result.status_code >= 400:
        source.health_status = SourceHealthStatus.DEGRADED.value
        source.consecutive_failures += 1
    else:
        source.health_status = SourceHealthStatus.UNREACHABLE.value
        source.consecutive_failures += 1

    source.last_crawled_at = now
    await db.commit()
    await db.refresh(source)

    return result
