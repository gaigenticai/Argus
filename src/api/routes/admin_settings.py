"""Admin endpoints — runtime configuration tables.

Four routers in one module:

    /api/v1/admin/settings              AppSetting CRUD
    /api/v1/admin/crawler-targets       CrawlerTarget CRUD
    /api/v1/admin/feed-health           FeedHealth read-only
    /api/v1/admin/subsidiary-allowlist  SubsidiaryAllowlist CRUD

All endpoints are admin-only and audit-logged with full before/after
JSON. Org scope is derived from the system tenant context — clients
never supply ``org_id``.
"""

from __future__ import annotations


import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import app_settings as app_settings_helper
from src.core import feed_health as feed_health_helper
from src.core.auth import AdminUser, AnalystUser, audit_log
from src.core.tenant import get_system_org_id
from src.models.admin import (
    AllowlistKind,
    AppSetting,
    AppSettingCategory,
    AppSettingType,
    CrawlerKind,
    CrawlerTarget,
    FeedHealth,
    SubsidiaryAllowlist,
)
from src.models.auth import AuditAction
from src.storage.database import get_session


router = APIRouter(prefix="/admin", tags=["Operations"])


# --- helpers -----------------------------------------------------------


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


# --- AppSetting --------------------------------------------------------


class SettingResponse(BaseModel):
    id: uuid.UUID
    key: str
    category: str
    value_type: str
    value: Any
    description: str | None
    minimum: float | None
    maximum: float | None
    updated_at: datetime
    model_config = {"from_attributes": True}


class SettingUpsert(BaseModel):
    key: str = Field(..., min_length=1, max_length=160)
    category: str = AppSettingCategory.GENERAL.value
    value_type: str = AppSettingType.JSON.value
    value: Any
    description: str | None = None
    minimum: float | None = None
    maximum: float | None = None


@router.get("/settings", response_model=list[SettingResponse])
async def list_settings(
    category: str | None = Query(None),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    return await app_settings_helper.list_settings(db, org_id, category=category)


@router.put("/settings/{key}", response_model=SettingResponse)
async def upsert_setting(
    body: SettingUpsert,
    request: Request,
    admin: AdminUser,
    key: str = Path(..., min_length=1, max_length=160),
    db: AsyncSession = Depends(get_session),
):
    if body.key != key:
        raise HTTPException(400, "URL key must match body.key")
    org_id = await get_system_org_id(db)

    existing = (
        await db.execute(
            select(AppSetting).where(
                AppSetting.organization_id == org_id,
                AppSetting.key == key,
            )
        )
    ).scalar_one_or_none()
    before = (
        {
            "value": existing.value,
            "value_type": existing.value_type,
            "category": existing.category,
        }
        if existing else None
    )

    row = await app_settings_helper.set_setting(
        db,
        organization_id=org_id,
        key=key,
        value=body.value,
        value_type=body.value_type,
        category=body.category,
        description=body.description,
        minimum=body.minimum,
        maximum=body.maximum,
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type="app_setting",
        resource_id=str(row.id),
        details={
            "key": key,
            "before": before,
            "after": {
                "value": body.value,
                "value_type": body.value_type,
                "category": body.category,
            },
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(row)
    # Hot-reload integration keys so a saved API key takes effect on
    # the next provider instantiation rather than waiting for the
    # 60s background refresh.
    if (body.category or "") == AppSettingCategory.INTEGRATIONS.value:
        from src.core import integration_keys as _ikeys
        _ikeys.invalidate()
    return row


@router.delete("/settings/{key}")
async def delete_setting(
    request: Request,
    admin: AdminUser,
    key: str = Path(..., min_length=1, max_length=160),
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    row = (
        await db.execute(
            select(AppSetting).where(
                AppSetting.organization_id == org_id,
                AppSetting.key == key,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Setting not found")
    before = {"value": row.value, "value_type": row.value_type, "category": row.category}
    await db.delete(row)
    app_settings_helper.invalidate_cache(org_id)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type="app_setting",
        resource_id=str(row.id),
        details={"key": key, "before": before, "after": None, "deleted": True},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {"deleted": True, "key": key}


# --- CrawlerTarget ----------------------------------------------------


class CrawlerTargetResponse(BaseModel):
    id: uuid.UUID
    kind: str
    identifier: str
    display_name: str | None
    config: dict
    is_active: bool
    last_run_at: datetime | None
    last_run_status: str | None
    last_run_summary: dict | None
    consecutive_failures: int
    updated_at: datetime
    model_config = {"from_attributes": True}


class CrawlerTargetCreate(BaseModel):
    kind: str = Field(..., min_length=1, max_length=40)
    identifier: str = Field(..., min_length=1, max_length=512)
    display_name: str | None = Field(None, max_length=255)
    config: dict = Field(default_factory=dict)
    is_active: bool = True


class CrawlerTargetUpdate(BaseModel):
    display_name: str | None = None
    config: dict | None = None
    is_active: bool | None = None


def _validate_kind(kind: str) -> None:
    try:
        CrawlerKind(kind)
    except ValueError:
        raise HTTPException(
            400,
            f"Unknown crawler kind {kind!r}. Allowed: "
            + ", ".join(k.value for k in CrawlerKind),
        )


@router.get("/crawler-targets", response_model=list[CrawlerTargetResponse])
async def list_crawler_targets(
    kind: str | None = Query(None),
    is_active: bool | None = Query(None),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    query = select(CrawlerTarget).where(CrawlerTarget.organization_id == org_id)
    if kind:
        query = query.where(CrawlerTarget.kind == kind)
    if is_active is not None:
        query = query.where(CrawlerTarget.is_active == is_active)
    query = query.order_by(CrawlerTarget.kind, CrawlerTarget.identifier)
    return list((await db.execute(query)).scalars().all())


@router.post("/crawler-targets", response_model=CrawlerTargetResponse)
async def create_crawler_target(
    body: CrawlerTargetCreate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    _validate_kind(body.kind)
    org_id = await get_system_org_id(db)

    duplicate = (
        await db.execute(
            select(CrawlerTarget).where(
                CrawlerTarget.organization_id == org_id,
                CrawlerTarget.kind == body.kind,
                CrawlerTarget.identifier == body.identifier,
            )
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise HTTPException(
            409, f"{body.kind} target {body.identifier!r} already registered"
        )

    target = CrawlerTarget(
        organization_id=org_id,
        kind=body.kind,
        identifier=body.identifier,
        display_name=body.display_name,
        config=body.config,
        is_active=body.is_active,
    )
    db.add(target)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type="crawler_target",
        resource_id=str(target.id),
        details={"after": body.model_dump()},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(target)
    return target


@router.patch("/crawler-targets/{target_id}", response_model=CrawlerTargetResponse)
async def update_crawler_target(
    body: CrawlerTargetUpdate,
    request: Request,
    admin: AdminUser,
    target_id: uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    target = await db.get(CrawlerTarget, target_id)
    if target is None or target.organization_id != org_id:
        raise HTTPException(404, "Crawler target not found")

    before = {
        "display_name": target.display_name,
        "config": target.config,
        "is_active": target.is_active,
    }
    after: dict = {}
    if body.display_name is not None:
        after["display_name"] = body.display_name
        target.display_name = body.display_name
    if body.config is not None:
        after["config"] = body.config
        target.config = body.config
    if body.is_active is not None:
        after["is_active"] = body.is_active
        target.is_active = body.is_active

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type="crawler_target",
        resource_id=str(target.id),
        details={"before": {k: before[k] for k in after}, "after": after},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/crawler-targets/{target_id}")
async def delete_crawler_target(
    request: Request,
    admin: AdminUser,
    target_id: uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    target = await db.get(CrawlerTarget, target_id)
    if target is None or target.organization_id != org_id:
        raise HTTPException(404, "Crawler target not found")
    before = {
        "kind": target.kind,
        "identifier": target.identifier,
        "display_name": target.display_name,
        "config": target.config,
        "is_active": target.is_active,
    }
    await db.delete(target)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type="crawler_target",
        resource_id=str(target.id),
        details={"before": before, "after": None, "deleted": True},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {"deleted": True, "id": str(target_id)}


# --- FeedHealth (read-only) --------------------------------------------


class FeedHealthResponse(BaseModel):
    id: uuid.UUID
    feed_name: str
    status: str
    detail: str | None
    rows_ingested: int
    duration_ms: int | None
    observed_at: datetime
    model_config = {"from_attributes": True}


@router.get("/feed-health", response_model=list[FeedHealthResponse])
async def list_feed_health(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """Latest FeedHealth row per feed_name. Drives the dashboard's
    feed-health panel — replaces the silent-zero pattern."""
    org_id = await get_system_org_id(db)
    return await feed_health_helper.latest_per_feed(db, organization_id=org_id)


@router.get("/feed-health/{feed_name}", response_model=list[FeedHealthResponse])
async def feed_health_history(
    feed_name: str = Path(..., min_length=1, max_length=80),
    limit: int = Query(100, ge=1, le=1000),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    return await feed_health_helper.history(
        db, feed_name=feed_name, organization_id=org_id, limit=limit
    )


# --- SubsidiaryAllowlist ----------------------------------------------


class AllowlistResponse(BaseModel):
    id: uuid.UUID
    kind: str
    value: str
    note: str | None
    created_at: datetime
    model_config = {"from_attributes": True}


class AllowlistCreate(BaseModel):
    kind: str = Field(..., min_length=1, max_length=20)
    value: str = Field(..., min_length=1, max_length=512)
    note: str | None = Field(None, max_length=1024)


def _validate_allowlist_kind(kind: str) -> None:
    try:
        AllowlistKind(kind)
    except ValueError:
        raise HTTPException(
            400,
            f"Unknown allowlist kind {kind!r}. Allowed: "
            + ", ".join(k.value for k in AllowlistKind),
        )


@router.get("/subsidiary-allowlist", response_model=list[AllowlistResponse])
async def list_allowlist(
    kind: str | None = Query(None),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    query = select(SubsidiaryAllowlist).where(
        SubsidiaryAllowlist.organization_id == org_id
    )
    if kind:
        query = query.where(SubsidiaryAllowlist.kind == kind)
    query = query.order_by(SubsidiaryAllowlist.kind, SubsidiaryAllowlist.value)
    return list((await db.execute(query)).scalars().all())


@router.post("/subsidiary-allowlist", response_model=AllowlistResponse)
async def add_allowlist_entry(
    body: AllowlistCreate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    _validate_allowlist_kind(body.kind)
    org_id = await get_system_org_id(db)

    normalised_value = body.value.strip().lower()
    duplicate = (
        await db.execute(
            select(SubsidiaryAllowlist).where(
                SubsidiaryAllowlist.organization_id == org_id,
                SubsidiaryAllowlist.kind == body.kind,
                SubsidiaryAllowlist.value == normalised_value,
            )
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise HTTPException(
            409, f"{body.kind} {normalised_value!r} already on allowlist"
        )

    row = SubsidiaryAllowlist(
        organization_id=org_id,
        kind=body.kind,
        value=normalised_value,
        note=body.note,
        added_by_user_id=admin.id,
    )
    db.add(row)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type="subsidiary_allowlist",
        resource_id=str(row.id),
        details={"after": {"kind": body.kind, "value": normalised_value, "note": body.note}},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.delete("/subsidiary-allowlist/{entry_id}")
async def remove_allowlist_entry(
    request: Request,
    admin: AdminUser,
    entry_id: uuid.UUID = Path(...),
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    row = await db.get(SubsidiaryAllowlist, entry_id)
    if row is None or row.organization_id != org_id:
        raise HTTPException(404, "Allowlist entry not found")
    before = {"kind": row.kind, "value": row.value, "note": row.note}
    await db.delete(row)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type="subsidiary_allowlist",
        resource_id=str(row.id),
        details={"before": before, "after": None, "deleted": True},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {"deleted": True, "id": str(entry_id)}


# --- Platform Readiness ------------------------------------------------
#
# Composite "is the platform actually working?" view, aggregated from
# every signal that tells us whether the operator's deployment is
# producing real intel or sitting silent. Without this surface, an
# operator stares at a green dashboard while the harvesters run dry —
# the per-feed Feed Health page tells you *which* feed is broken but
# not whether the platform as a whole has reached steady-state.
#
# Categories (each scored 0–100):
#
#   IDENTITY     primary domain verified, has brand terms, has assets
#   SCOPE        crawler_targets configured, monitored emails, channels
#   INGESTION    feed_health rows ok, recent raw_intel + iocs
#   INTEGRATIONS optional API keys set (HIBP, urlscan, Shodan, etc.)
#   AGENTS       triage/investigation/case-copilot tick activity
#   SELF_HEAL    maintenance jobs running, target rotation healthy
#
# Each category returns a 0..100 score + a list of remediation items
# the dashboard renders as a punch list. The composite is the simple
# average — heavily-weighted categories are out of scope here; the
# punch list itself is the prescriptive guidance.


class PlatformReadinessItem(BaseModel):
    severity: str  # "blocker" | "warning" | "info"
    category: str
    title: str
    detail: str
    href: str | None = None  # dashboard route to fix it


class PlatformReadinessCategory(BaseModel):
    key: str
    label: str
    score: int  # 0..100
    summary: str
    items: list[PlatformReadinessItem]


class PlatformReadinessResponse(BaseModel):
    overall_score: int  # 0..100
    categories: list[PlatformReadinessCategory]
    blockers: list[PlatformReadinessItem]
    generated_at: datetime


# --- Service Inventory ------------------------------------------------
#
# A live, dashboard-renderable inventory of every external service
# Argus integrates with: feeds, enrichment APIs, dark-web crawlers,
# LLM providers, EDR/SIEM/SOAR connectors, OSS tools, infrastructure.
# Each entry resolves its own status from authoritative sources
# (feed_health rows, integration_keys cache, env presence, binary
# probes). The dashboard renders this as Settings → Service Inventory
# so operators can answer "what's actually working in my deployment?"
# without grepping the codebase.


@router.get("/service-inventory")
async def get_service_inventory(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Return every catalogued external service with its live status."""
    from src.core.service_inventory import CATEGORIES, resolve_inventory

    entries = await resolve_inventory(db)
    by_status: dict[str, int] = {}
    for e in entries:
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1
    return {
        "categories": CATEGORIES,
        "services": entries,
        "summary": by_status,
        "total": len(entries),
    }


@router.get("/service-inventory/page/{page_key}")
async def get_services_for_page(
    page_key: str,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Subset of the inventory feeding the named page. Backs the
    ``<SourcesStrip>`` component so any data page can render a live
    "what's powering this view" header. Analyst-readable; the inventory
    itself is admin-only."""
    from src.core.service_inventory import resolve_for_page

    entries = await resolve_for_page(db, page_key)
    by_status: dict[str, int] = {}
    for e in entries:
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1
    return {
        "page_key": page_key,
        "services": entries,
        "summary": by_status,
        "total": len(entries),
    }


@router.get("/service-coverage")
async def get_service_coverage(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Single source of truth for "is at least one configured source
    producing data type X?" — used by the dashboard to auto-hide
    pages, sidebar entries, and inline panels whose backing services
    are all unconfigured (``needs_key`` / ``not_installed``).

    Returns a coverage map keyed two ways:

      ``pages``      → ``{page_slug: bool}``  any OK service produces this page?
      ``categories`` → ``{category: bool}``   any OK service in this category?

    Plus a flat ``count`` of OK rows. The dashboard's sidebar consults
    ``pages`` to decide whether to render each nav entry; data pages
    consult ``pages[<their slug>]`` to swap in an empty-state CTA
    instead of a blank panel. Reactive: as soon as the operator pastes
    a key in Settings → Services, the next probe flips ``status='ok'``
    and the UI surfaces appear.

    Analyst-readable so the strip on every page (which renders for
    non-admin users too) can hydrate it. Returning bools only — no
    leaking of which specific services produce what."""
    from src.core.service_inventory import CATEGORIES, resolve_inventory

    entries = await resolve_inventory(db)
    pages: dict[str, bool] = {}
    categories: dict[str, bool] = {c: False for c in CATEGORIES}
    ok_count = 0

    for e in entries:
        is_ok = e["status"] == "ok"
        if is_ok:
            ok_count += 1
            if e.get("category") in categories:
                categories[e["category"]] = True
        for slug in e.get("produces_pages", []) or []:
            slug_norm = (slug or "").lower().lstrip("/")
            if not slug_norm:
                continue
            # `*` means infrastructure (powers every page) — only
            # mark it true once and project onto every other page key.
            if slug_norm == "*":
                pages.setdefault(slug_norm, is_ok)
                if is_ok:
                    pages[slug_norm] = True
                continue
            pages[slug_norm] = pages.get(slug_norm, False) or is_ok

    return {
        "pages": pages,
        "categories": categories,
        "ok_count": ok_count,
        "total": len(entries),
    }


# --- Integrations state -----------------------------------------------
#
# Why a dedicated endpoint instead of just reading the app_settings
# listing: API keys can live in two places and the UI needs to be
# honest about both.
#
#   1. ``app_settings`` row (DB) — set via Settings → Integrations.
#      Overrides env when present.
#   2. ``os.environ[ARGUS_*]`` (env) — legacy ``.env`` deployments.
#      Still serves traffic; ``integration_keys.get()`` falls back to
#      it when no DB row exists.
#
# Without env awareness the dashboard shows "0 of 8 configured" for
# any deployment that wires keys via .env, which is the most common
# state. The state endpoint resolves both sources and reports the
# truth: ``source: "db" | "env" | "unset"`` per known field, plus a
# masked tail of the value when set so operators can confirm rotation
# without revealing the secret.


class IntegrationField(BaseModel):
    key: str             # short name used in app_settings (``hibp``)
    env_var: str         # legacy env fallback name
    label: str
    type: str            # "password" | "text"
    source: str          # "db" | "env" | "unset"
    masked_value: str | None  # last 4 chars when set, else None


class IntegrationDef(BaseModel):
    name: str            # canonical short name (``hibp``)
    label: str
    purpose: str
    cost_note: str | None
    help_url: str | None
    fields: list[IntegrationField]
    is_configured: bool  # any field has a value (db OR env)


_INTEGRATION_CATALOG: list[dict[str, Any]] = [
    {
        "name": "hudsonrock",
        "label": "HudsonRock Cavalier",
        "purpose": "Stealer-log breach corpus (OSS-default — no key required for first-pass).",
        "cost_note": "Free tier works without a key; key unlocks higher quota + paid corpus.",
        "help_url": "https://www.hudsonrock.com/free-tools",
        "fields": [
            {"key": "hudsonrock", "env_var": "ARGUS_HUDSONROCK_API_KEY", "label": "API key (optional)", "type": "password"},
        ],
    },
    {
        "name": "hibp",
        "label": "Have I Been Pwned",
        "purpose": "Breach-credential lookup for your monitored email list",
        "cost_note": "$3.95/mo Enterprise tier required",
        "help_url": "https://haveibeenpwned.com/api/key",
        "fields": [
            {"key": "hibp", "env_var": "ARGUS_HIBP_API_KEY", "label": "API key", "type": "password"},
        ],
    },
    {
        "name": "urlscan",
        "label": "urlscan.io",
        "purpose": "Historical scan lookup + new-URL submission",
        "cost_note": "Free tier 100/day",
        "help_url": "https://urlscan.io/user/signup/",
        "fields": [
            {"key": "urlscan", "env_var": "ARGUS_URLSCAN_API_KEY", "label": "API key", "type": "password"},
        ],
    },
    {
        "name": "intelx",
        "label": "Intelligence X",
        "purpose": "Breach-corpus search across leaked databases",
        "cost_note": "Free trial then paid",
        "help_url": "https://intelx.io/account?tab=developer",
        "fields": [
            {"key": "intelx", "env_var": "ARGUS_INTELX_API_KEY", "label": "API key", "type": "password"},
        ],
    },
    {
        "name": "dehashed",
        "label": "DeHashed",
        "purpose": "Email + username breach corpus lookup",
        "cost_note": "~$5/mo entry tier",
        "help_url": "https://dehashed.com/account",
        "fields": [
            {"key": "dehashed_user", "env_var": "ARGUS_DEHASHED_USERNAME", "label": "Username", "type": "text"},
            {"key": "dehashed", "env_var": "ARGUS_DEHASHED_API_KEY", "label": "API key", "type": "password"},
        ],
    },
    {
        "name": "phishtank",
        "label": "PhishTank",
        "purpose": "Phishing URL feed (bypasses unauthenticated rate limits)",
        "cost_note": "Free with registration",
        "help_url": "https://www.phishtank.com/api_register.php",
        "fields": [
            {"key": "phishtank", "env_var": "ARGUS_PHISHTANK_API_KEY", "label": "Application key", "type": "password"},
        ],
    },
    {
        "name": "otx",
        "label": "AlienVault OTX",
        "purpose": "Open Threat Exchange IOC pulses",
        "cost_note": "Free with registration",
        "help_url": "https://otx.alienvault.com/api",
        "fields": [
            # Canonical env name comes from ``settings.feeds.otx_api_key``
            # → pydantic nested-config maps it to ``ARGUS_FEED_OTX_API_KEY``.
            {"key": "otx", "env_var": "ARGUS_FEED_OTX_API_KEY", "label": "API key", "type": "password"},
        ],
    },
    {
        "name": "greynoise",
        "label": "GreyNoise",
        "purpose": "IP-noise filtering — separates targeted scans from internet background radiation",
        "cost_note": "Free community tier",
        "help_url": "https://www.greynoise.io/get-api-key",
        "fields": [
            {"key": "greynoise", "env_var": "ARGUS_FEED_GREYNOISE_API_KEY", "label": "API key", "type": "password"},
        ],
    },
]


def _mask_tail(value: str) -> str:
    """Show last 4 chars so operators can confirm rotation without
    revealing the secret. Short values get fully masked."""
    if not value:
        return ""
    if len(value) <= 4:
        return "•" * len(value)
    return "••••" + value[-4:]


@router.get("/integrations", response_model=list[IntegrationDef])
async def list_integrations(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Return every known integration with its current resolution
    state. UI uses this to render Settings → Integrations honestly —
    keys set via env appear as ``source="env"`` rather than the
    misleading ``Not set`` we'd otherwise show."""
    import os as _os

    org_id = await get_system_org_id(db)
    db_rows = (
        await db.execute(
            select(AppSetting).where(
                AppSetting.organization_id == org_id,
                AppSetting.category == AppSettingCategory.INTEGRATIONS.value,
            )
        )
    ).scalars().all()
    db_by_key = {r.key: r.value for r in db_rows}

    out: list[IntegrationDef] = []
    for entry in _INTEGRATION_CATALOG:
        fields: list[IntegrationField] = []
        for f in entry["fields"]:
            db_value = db_by_key.get(f"integration.{f['key']}.api_key")
            env_value = (_os.environ.get(f["env_var"]) or "").strip()
            if isinstance(db_value, str) and db_value.strip():
                source = "db"
                masked = _mask_tail(db_value.strip())
            elif env_value:
                source = "env"
                masked = _mask_tail(env_value)
            else:
                source = "unset"
                masked = None
            fields.append(IntegrationField(
                key=f["key"],
                env_var=f["env_var"],
                label=f["label"],
                type=f["type"],
                source=source,
                masked_value=masked,
            ))
        out.append(IntegrationDef(
            name=entry["name"],
            label=entry["label"],
            purpose=entry["purpose"],
            cost_note=entry.get("cost_note"),
            help_url=entry.get("help_url"),
            fields=fields,
            is_configured=any(f.source != "unset" for f in fields),
        ))
    return out


@router.get("/platform-readiness", response_model=PlatformReadinessResponse)
async def platform_readiness(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Composite readiness for the operator's deployment.

    Aggregates real signals (DB rows, FeedHealth states, recent agent
    activity) into a per-category score plus a prescriptive punch list.
    Renders as ``/admin → Platform Readiness`` in the dashboard."""
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    from sqlalchemy import func as _func

    from src.core.domain_verification import is_domain_verified
    from src.models.brand import BrandTerm
    from src.models.intel import IOC
    from src.models.threat import (
        Alert,
        Asset,
        Organization,
        RawIntel,
    )

    org = (
        await db.execute(select(Organization).limit(1))
    ).scalar_one_or_none()
    if org is None:
        # Brand-new deploy — everything is a blocker.
        empty_cat = lambda key, label: PlatformReadinessCategory(  # noqa: E731
            key=key, label=label, score=0,
            summary="No organisation provisioned yet.",
            items=[
                PlatformReadinessItem(
                    severity="blocker", category=label,
                    title="No organisation exists",
                    detail="Run the onboarding wizard to provision the tenant.",
                    href="/onboarding",
                )
            ],
        )
        return PlatformReadinessResponse(
            overall_score=0,
            categories=[
                empty_cat(k, l) for (k, l) in [
                    ("identity", "Identity"),
                    ("scope", "Scope"),
                    ("ingestion", "Ingestion"),
                    ("integrations", "Integrations"),
                    ("agents", "Agents"),
                    ("self_heal", "Self-healing"),
                ]
            ],
            blockers=[],
            generated_at=_dt.now(_tz.utc),
        )

    now = _dt.now(_tz.utc)
    last_24h = now - _td(hours=24)
    last_7d = now - _td(days=7)
    org_settings = org.settings or {}

    categories: list[PlatformReadinessCategory] = []

    # ── IDENTITY ────────────────────────────────────────────────────
    domains = list(org.domains or [])
    primary = domains[0] if domains else None
    primary_verified = bool(
        primary and is_domain_verified(org_settings, primary)
    )
    asset_count = (
        await db.execute(
            select(_func.count(Asset.id)).where(Asset.organization_id == org.id)
        )
    ).scalar_one() or 0
    brand_term_count = (
        await db.execute(
            select(_func.count(BrandTerm.id)).where(
                BrandTerm.organization_id == org.id,
                BrandTerm.is_active.is_(True),
            )
        )
    ).scalar_one() or 0

    identity_items: list[PlatformReadinessItem] = []
    identity_score = 0
    if not primary:
        identity_items.append(PlatformReadinessItem(
            severity="blocker", category="Identity",
            title="No primary domain set",
            detail="Add the apex domain you operate. It anchors every alert and IOC.",
            href="/settings?tab=domains",
        ))
    elif not primary_verified:
        identity_items.append(PlatformReadinessItem(
            severity="blocker", category="Identity",
            title=f"Primary domain {primary!r} not verified",
            detail="Publish the DNS TXT challenge to prove you operate this domain. Until then findings are blurred.",
            href="/settings?tab=domains",
        ))
        identity_score += 25
    else:
        identity_score += 50
    if brand_term_count == 0:
        identity_items.append(PlatformReadinessItem(
            severity="warning", category="Identity",
            title="No brand terms",
            detail="Add brand names + slogans so name-based matchers (dark web, news, impersonation) can fire.",
            href="/brand",
        ))
    else:
        identity_score += 30
    if asset_count == 0:
        identity_items.append(PlatformReadinessItem(
            severity="warning", category="Identity",
            title="No assets registered",
            detail="Add at least your apex domains as assets so EASM and CT log ingest can target them.",
            href="/surface",
        ))
    else:
        identity_score += 20
    categories.append(PlatformReadinessCategory(
        key="identity", label="Identity",
        score=min(100, identity_score),
        summary=(
            f"{len(domains)} domain(s), "
            f"{'1 verified' if primary_verified else '0 verified'}, "
            f"{brand_term_count} brand term(s), "
            f"{asset_count} asset(s)"
        ),
        items=identity_items,
    ))

    # ── SCOPE ───────────────────────────────────────────────────────
    crawler_target_rows = (
        await db.execute(
            select(CrawlerTarget.kind, _func.count(CrawlerTarget.id))
            .where(
                CrawlerTarget.organization_id == org.id,
                CrawlerTarget.is_active.is_(True),
            )
            .group_by(CrawlerTarget.kind)
        )
    ).all()
    targets_by_kind = {k: int(c) for k, c in crawler_target_rows}
    breach_emails = list(org_settings.get("breach_check_emails") or [])
    tg_handles = list(org_settings.get("telegram_monitor_channels") or [])

    scope_items: list[PlatformReadinessItem] = []
    scope_score = 0
    total_targets = sum(targets_by_kind.values())
    if total_targets == 0:
        scope_items.append(PlatformReadinessItem(
            severity="blocker", category="Scope",
            title="No crawler targets configured",
            detail="Dark-web crawlers have nothing to crawl. Seed defaults via load_real_target or add manually.",
            href="/admin",
        ))
    else:
        scope_score += min(40, total_targets * 5)
    if not breach_emails:
        scope_items.append(PlatformReadinessItem(
            severity="warning", category="Scope",
            title="No breach-check emails",
            detail="HIBP / DeHashed / IntelX have no email list to query for this org.",
            href="/settings?tab=monitoring",
        ))
    else:
        scope_score += 20
    if not tg_handles:
        scope_items.append(PlatformReadinessItem(
            severity="warning", category="Scope",
            title="No Telegram channels",
            detail="Telegram fraud / impersonation monitor will run no-ops every tick.",
            href="/settings?tab=monitoring",
        ))
    else:
        scope_score += 20
    if "ransomware_leak_group" not in targets_by_kind:
        scope_items.append(PlatformReadinessItem(
            severity="warning", category="Scope",
            title="No ransomware leak-site targets",
            detail="No groups will be polled for victim listings. Self-healing job will populate this if upstream is reachable.",
            href="/admin",
        ))
    else:
        scope_score += 20
    categories.append(PlatformReadinessCategory(
        key="scope", label="Scope",
        score=min(100, scope_score),
        summary=(
            f"{total_targets} target(s) across "
            f"{len(targets_by_kind)} kind(s); "
            f"{len(breach_emails)} email(s); "
            f"{len(tg_handles)} channel(s)"
        ),
        items=scope_items,
    ))

    # ── INGESTION ───────────────────────────────────────────────────
    raw_intel_24h = (
        await db.execute(
            select(_func.count(RawIntel.id)).where(RawIntel.created_at >= last_24h)
        )
    ).scalar_one() or 0
    iocs_24h = (
        await db.execute(
            select(_func.count(IOC.id)).where(IOC.first_seen >= last_24h)
        )
    ).scalar_one() or 0
    alerts_7d = (
        await db.execute(
            select(_func.count(Alert.id)).where(
                Alert.organization_id == org.id,
                Alert.created_at >= last_7d,
            )
        )
    ).scalar_one() or 0

    feed_health_breakdown_rows = (
        await db.execute(
            select(FeedHealth.status, _func.count(FeedHealth.id))
            .where(FeedHealth.observed_at >= last_24h)
            .group_by(FeedHealth.status)
        )
    ).all()
    fh_breakdown = {s: int(c) for s, c in feed_health_breakdown_rows}
    fh_total = sum(fh_breakdown.values())
    fh_ok = fh_breakdown.get("ok", 0)

    ingestion_items: list[PlatformReadinessItem] = []
    ingestion_score = 0
    if fh_total == 0:
        ingestion_items.append(PlatformReadinessItem(
            severity="blocker", category="Ingestion",
            title="No feed activity in last 24h",
            detail="Worker may not be running. Check the argus-worker container.",
            href="/admin",
        ))
    else:
        ingestion_score += min(40, int(40 * fh_ok / max(1, fh_total)))
    if raw_intel_24h == 0:
        ingestion_items.append(PlatformReadinessItem(
            severity="warning", category="Ingestion",
            title="No raw intel collected in last 24h",
            detail="Crawlers ran but produced 0 rows. Check Feed Health for per-source detail.",
            href="/admin",
        ))
    else:
        ingestion_score += min(30, raw_intel_24h)
    if alerts_7d == 0 and raw_intel_24h > 0:
        ingestion_items.append(PlatformReadinessItem(
            severity="info", category="Ingestion",
            title="Raw intel ingesting but no alerts fired",
            detail="Either: triage threshold too high, brand terms too narrow, or genuinely no relevant signal.",
            href="/feeds",
        ))
    else:
        ingestion_score += 30
    categories.append(PlatformReadinessCategory(
        key="ingestion", label="Ingestion",
        score=min(100, ingestion_score),
        summary=(
            f"24h: {raw_intel_24h} raw, {iocs_24h} IOCs; "
            f"7d: {alerts_7d} alerts; "
            f"feed_health: {fh_ok}/{fh_total} ok"
        ),
        items=ingestion_items,
    ))

    # ── INTEGRATIONS ────────────────────────────────────────────────
    import os as _os
    integrations = [
        ("ARGUS_HIBP_API_KEY", "HIBP", "breach search (paid)"),
        ("ARGUS_URLSCAN_API_KEY", "urlscan.io", "URL recon"),
        ("ARGUS_INTELX_API_KEY", "IntelX", "breach search"),
        ("ARGUS_DEHASHED_API_KEY", "DeHashed", "breach search"),
        ("ARGUS_PHISHTANK_API_KEY", "PhishTank", "phishing feed (rate-limit)"),
        # Canonical env names use the ``ARGUS_FEED_`` prefix because
        # they're owned by ``settings.feeds.*`` (pydantic nested config),
        # not the top-level settings.
        ("ARGUS_FEED_OTX_API_KEY", "AlienVault OTX", "IOC feed"),
        ("ARGUS_FEED_GREYNOISE_API_KEY", "GreyNoise", "noise filtering"),
    ]
    integ_items: list[PlatformReadinessItem] = []
    set_count = 0
    for env_var, name, purpose in integrations:
        if (_os.environ.get(env_var) or "").strip():
            set_count += 1
        else:
            integ_items.append(PlatformReadinessItem(
                severity="info", category="Integrations",
                title=f"{name} not configured",
                detail=f"Set {env_var} to enable {purpose}.",
                href="/settings?tab=integrations",
            ))
    integ_score = int(100 * set_count / len(integrations))
    categories.append(PlatformReadinessCategory(
        key="integrations", label="Integrations",
        score=integ_score,
        summary=f"{set_count} of {len(integrations)} third-party keys configured",
        items=integ_items,
    ))

    # ── AGENTS ──────────────────────────────────────────────────────
    from src.models.case_copilot import CaseCopilotRun
    from src.models.investigations import Investigation
    from src.models.intel import TriageRun
    investigations_24h = (
        await db.execute(
            select(_func.count(Investigation.id)).where(
                Investigation.created_at >= last_24h
            )
        )
    ).scalar_one() or 0
    triage_runs_24h = (
        await db.execute(
            select(_func.count(TriageRun.id)).where(
                TriageRun.created_at >= last_24h
            )
        )
    ).scalar_one() or 0
    case_copilot_24h = (
        await db.execute(
            select(_func.count(CaseCopilotRun.id)).where(
                CaseCopilotRun.created_at >= last_24h
            )
        )
    ).scalar_one() or 0

    agent_items: list[PlatformReadinessItem] = []
    agent_score = 0
    if triage_runs_24h > 0:
        agent_score += 50
    else:
        agent_items.append(PlatformReadinessItem(
            severity="warning", category="Agents",
            title="Triage agent silent for 24h",
            detail="No alert triage runs. Either no incoming raw intel, or LLM provider unreachable.",
            href="/agent-activity",
        ))
    if investigations_24h > 0 or case_copilot_24h > 0:
        agent_score += 50
    else:
        agent_items.append(PlatformReadinessItem(
            severity="info", category="Agents",
            title="Investigation / case-copilot quiet",
            detail="No agentic runs. Expected on a fresh deploy until alerts arrive.",
            href="/agent-activity",
        ))
    categories.append(PlatformReadinessCategory(
        key="agents", label="Agents",
        score=min(100, agent_score),
        summary=(
            f"24h: {triage_runs_24h} triage, "
            f"{investigations_24h} investigation, "
            f"{case_copilot_24h} case-copilot"
        ),
        items=agent_items,
    ))

    # ── SELF-HEALING ────────────────────────────────────────────────
    maint_rows = (
        await db.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name.like("maintenance.%"))
            .where(FeedHealth.observed_at >= last_7d)
            .order_by(desc(FeedHealth.observed_at))
        )
    ).scalars().all()
    seen_jobs: dict[str, FeedHealth] = {}
    for r in maint_rows:
        if r.feed_name not in seen_jobs:
            seen_jobs[r.feed_name] = r
    expected = {
        "maintenance.refresh_ransomware_targets": "Ransomware-target auto-refresh",
        "maintenance.prune_dead_telegram_channels": "Telegram channel auto-prune",
    }
    self_heal_items: list[PlatformReadinessItem] = []
    self_heal_score = 0
    for feed_name, label in expected.items():
        latest = seen_jobs.get(feed_name)
        if latest is None:
            self_heal_items.append(PlatformReadinessItem(
                severity="warning", category="Self-healing",
                title=f"{label} hasn't run",
                detail="Worker hasn't ticked this maintenance job in the last 7 days. Expected: daily/weekly.",
                href="/admin",
            ))
        elif latest.status == "ok":
            self_heal_score += 50
        else:
            self_heal_items.append(PlatformReadinessItem(
                severity="warning", category="Self-healing",
                title=f"{label} failing ({latest.status})",
                detail=(latest.detail or "")[:200],
                href="/admin",
            ))
    categories.append(PlatformReadinessCategory(
        key="self_heal", label="Self-healing",
        score=min(100, self_heal_score),
        summary=f"{len([j for j in seen_jobs if seen_jobs[j].status == 'ok'])} of {len(expected)} maintenance jobs healthy",
        items=self_heal_items,
    ))

    # ── Composite + blockers ────────────────────────────────────────
    overall = sum(c.score for c in categories) // max(1, len(categories))
    blockers = [
        item
        for cat in categories
        for item in cat.items
        if item.severity == "blocker"
    ]
    return PlatformReadinessResponse(
        overall_score=overall,
        categories=categories,
        blockers=blockers,
        generated_at=now,
    )
