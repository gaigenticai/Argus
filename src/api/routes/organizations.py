"""Organisation endpoints — single-tenant.

Argus is single-tenant on-prem: one customer per docker install, one
``Organization`` row, end of story. The endpoints in this module
exist because the schema FKs every domain table to ``organizations.id``,
not because the API is supposed to grow into a multi-tenant SaaS.
``GET /`` returns the one row; ``{org_id}`` accepts either ``current``
or the matching UUID — anything else is a 404.

All mutations write before/after JSON to the audit log.
"""

from __future__ import annotations


import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.core.tenant import (
    SystemOrganizationMissing,
    get_system_org_id,
    invalidate as invalidate_tenant_cache,
)
from src.models.auth import AuditAction
from src.models.threat import Asset, Organization, VIPTarget
from src.storage.database import get_session

router = APIRouter(prefix="/organizations", tags=["Auth & Identity"])


# --- Schemas -------------------------------------------------------------


class VIPCreate(BaseModel):
    name: str
    title: str | None = None
    emails: list[str] = []
    usernames: list[str] = []
    phone_numbers: list[str] = []
    keywords: list[str] = []
    social_profiles: dict[str, str] | None = None


class AssetCreate(BaseModel):
    asset_type: str
    value: str
    details: dict[str, Any] | None = None


class OrgCreate(BaseModel):
    name: str
    domains: list[str] = []
    keywords: list[str] = []
    industry: str | None = None
    tech_stack: dict[str, Any] | None = None


class OrgUpdate(BaseModel):
    name: str | None = None
    domains: list[str] | None = None
    keywords: list[str] | None = None
    industry: str | None = None
    tech_stack: dict[str, Any] | None = None


class OrgResponse(BaseModel):
    id: uuid.UUID
    name: str
    domains: list[str]
    keywords: list[str]
    industry: str | None
    tech_stack: dict | None

    model_config = {"from_attributes": True}


# --- Helpers -------------------------------------------------------------


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


async def _resolve(db: AsyncSession, org_id_or_current: str) -> Organization:
    """Accept ``current`` or the system org's UUID; reject anything else."""
    sys_id = None
    try:
        sys_id = await get_system_org_id(db)
    except SystemOrganizationMissing:
        pass

    if org_id_or_current == "current":
        if sys_id is None:
            raise HTTPException(
                404,
                "No organisation provisioned. POST /organizations/ once to bootstrap.",
            )
        org = await db.get(Organization, sys_id)
        if org is None:
            invalidate_tenant_cache()
            raise HTTPException(404, "Organisation not found")
        return org

    try:
        candidate = uuid.UUID(org_id_or_current)
    except ValueError:
        raise HTTPException(404, "Organisation not found")

    if sys_id is not None and candidate != sys_id:
        # Single-tenant: only one org is addressable.
        raise HTTPException(404, "Organisation not found")

    org = await db.get(Organization, candidate)
    if org is None:
        raise HTTPException(404, "Organisation not found")
    return org


# --- Endpoints -----------------------------------------------------------


@router.post("/", response_model=OrgResponse)
async def create_organization(
    body: OrgCreate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Bootstrap the (one and only) Organisation row.

    Subsequent calls fail with 409 — single-tenant deploys never need
    more than one. To rename or otherwise edit, use ``PATCH /current``.
    """
    existing = (await db.execute(select(Organization))).scalars().first()
    if existing is not None:
        raise HTTPException(
            409,
            "Organisation already provisioned. PATCH /organizations/current to update.",
        )

    org = Organization(
        name=body.name,
        domains=body.domains,
        keywords=body.keywords,
        industry=body.industry,
        tech_stack=body.tech_stack,
    )
    db.add(org)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_CREATE,
        user=admin,
        resource_type="organization",
        resource_id=str(org.id),
        details={"after": body.model_dump()},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(org)
    invalidate_tenant_cache()
    return org


@router.get("/", response_model=list[OrgResponse])
async def list_organizations(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """Return the (single) organisation. Always either zero or one row."""
    rows = (await db.execute(select(Organization))).scalars().all()
    return list(rows)


@router.get("/current", response_model=OrgResponse)
async def get_current_organization(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    return await _resolve(db, "current")


@router.patch("/current", response_model=OrgResponse)
async def update_current_organization(
    body: OrgUpdate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, "current")
    before = {
        "name": org.name,
        "domains": list(org.domains or []),
        "keywords": list(org.keywords or []),
        "industry": org.industry,
        "tech_stack": dict(org.tech_stack or {}),
    }
    after: dict = {}
    if body.name is not None and body.name != org.name:
        after["name"] = body.name
        org.name = body.name
    if body.domains is not None and list(body.domains) != list(org.domains or []):
        after["domains"] = body.domains
        org.domains = body.domains
    if body.keywords is not None and list(body.keywords) != list(org.keywords or []):
        after["keywords"] = body.keywords
        org.keywords = body.keywords
    if body.industry is not None and body.industry != org.industry:
        after["industry"] = body.industry
        org.industry = body.industry
    if body.tech_stack is not None and dict(body.tech_stack) != dict(org.tech_stack or {}):
        after["tech_stack"] = body.tech_stack
        org.tech_stack = body.tech_stack

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=admin,
        resource_type="organization",
        resource_id=str(org.id),
        details={"before": {k: before[k] for k in after}, "after": after} if after else {"no_change": True},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(org)
    invalidate_tenant_cache()
    return org


@router.get("/{org_id}", response_model=OrgResponse)
async def get_organization(
    org_id: str = Path(...),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    return await _resolve(db, org_id)


@router.post("/{org_id}/vips")
async def add_vip(
    body: VIPCreate,
    request: Request,
    analyst: AnalystUser,
    org_id: str = Path(...),
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    vip = VIPTarget(
        organization_id=org.id,
        name=body.name,
        title=body.title,
        emails=body.emails,
        usernames=body.usernames,
        phone_numbers=body.phone_numbers,
        keywords=body.keywords,
        social_profiles=body.social_profiles,
    )
    db.add(vip)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="vip_target",
        resource_id=str(vip.id),
        details={"after": body.model_dump()},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(vip)
    return {
        "id": str(vip.id),
        "name": vip.name,
        "title": vip.title,
        "emails": vip.emails,
    }


@router.get("/{org_id}/vips")
async def list_vips(
    org_id: str = Path(...),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    result = await db.execute(
        select(VIPTarget).where(VIPTarget.organization_id == org.id)
    )
    return [
        {
            "id": str(v.id),
            "name": v.name,
            "title": v.title,
            "emails": v.emails,
            "usernames": v.usernames,
            "phone_numbers": v.phone_numbers,
        }
        for v in result.scalars().all()
    ]


@router.get("/{org_id}/assets")
async def list_assets(
    org_id: str = Path(...),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    result = await db.execute(
        select(Asset).where(Asset.organization_id == org.id)
    )
    return [
        {
            "id": str(a.id),
            "type": a.asset_type,
            "value": a.value,
            "details": a.details,
        }
        for a in result.scalars().all()
    ]


@router.post("/{org_id}/assets")
async def add_asset(
    body: AssetCreate,
    request: Request,
    analyst: AnalystUser,
    org_id: str = Path(...),
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    asset = Asset(
        organization_id=org.id,
        asset_type=body.asset_type,
        value=body.value,
        details=body.details,
    )
    db.add(asset)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="asset",
        resource_id=str(asset.id),
        details={"after": body.model_dump()},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(asset)
    return {"id": str(asset.id), "type": asset.asset_type, "value": asset.value}
