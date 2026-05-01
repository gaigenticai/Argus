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
