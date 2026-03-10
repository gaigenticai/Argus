"""Organization management endpoints."""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.threat import Organization, VIPTarget, Asset
from src.storage.database import get_session

router = APIRouter(prefix="/organizations", tags=["organizations"])


# --- Schemas ---


class VIPCreate(BaseModel):
    name: str
    title: str | None = None
    emails: list[str] = []
    usernames: list[str] = []
    phone_numbers: list[str] = []
    keywords: list[str] = []
    social_profiles: dict[str, str] | None = None


class AssetCreate(BaseModel):
    asset_type: str  # domain, subdomain, ip, service
    value: str
    details: dict[str, Any] | None = None


class OrgCreate(BaseModel):
    name: str
    domains: list[str] = []
    keywords: list[str] = []
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


# --- Endpoints ---


@router.post("/", response_model=OrgResponse)
async def create_organization(
    body: OrgCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = Organization(
        name=body.name,
        domains=body.domains,
        keywords=body.keywords,
        industry=body.industry,
        tech_stack=body.tech_stack,
    )
    db.add(org)
    await db.flush()

    forwarded = request.headers.get("X-Forwarded-For")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    await audit_log(
        db,
        AuditAction.ORG_CREATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(org.id),
        details={"name": body.name},
        ip_address=ip,
        user_agent=request.headers.get("User-Agent", "unknown")[:500],
    )
    await db.commit()
    await db.refresh(org)
    return org


@router.get("/", response_model=list[OrgResponse])
async def list_organizations(db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(Organization))
    return result.scalars().all()


@router.get("/search", response_model=list[OrgResponse])
async def search_organizations(
    q: str = "",
    db: AsyncSession = Depends(get_session),
):
    """Search organizations by name or domain."""
    from sqlalchemy import or_, any_

    if not q.strip():
        result = await db.execute(select(Organization))
        return result.scalars().all()

    pattern = f"%{q}%"
    query = select(Organization).where(
        or_(
            Organization.name.ilike(pattern),
            Organization.industry.ilike(pattern),
        )
    )
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{org_id}", response_model=OrgResponse)
async def get_organization(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


@router.post("/{org_id}/vips")
async def add_vip(
    org_id: uuid.UUID,
    body: VIPCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    vip = VIPTarget(
        organization_id=org_id,
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

    forwarded = request.headers.get("X-Forwarded-For")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="vip_target",
        resource_id=str(vip.id),
        details={"org_id": str(org_id), "vip_name": body.name},
        ip_address=ip,
        user_agent=request.headers.get("User-Agent", "unknown")[:500],
    )
    await db.commit()
    await db.refresh(vip)
    return {"id": str(vip.id), "name": vip.name}


@router.get("/{org_id}/vips")
async def list_vips(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(VIPTarget).where(VIPTarget.organization_id == org_id)
    )
    return [
        {"id": str(v.id), "name": v.name, "title": v.title, "emails": v.emails}
        for v in result.scalars().all()
    ]


@router.get("/{org_id}/assets")
async def list_assets(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
):
    result = await db.execute(
        select(Asset).where(Asset.organization_id == org_id)
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
    org_id: uuid.UUID,
    body: AssetCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    asset = Asset(
        organization_id=org_id,
        asset_type=body.asset_type,
        value=body.value,
        details=body.details,
    )
    db.add(asset)
    await db.flush()

    forwarded = request.headers.get("X-Forwarded-For")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="asset",
        resource_id=str(asset.id),
        details={"org_id": str(org_id), "asset_type": body.asset_type, "value": body.value},
        ip_address=ip,
        user_agent=request.headers.get("User-Agent", "unknown")[:500],
    )
    await db.commit()
    await db.refresh(asset)
    return {"id": str(asset.id), "type": asset.asset_type, "value": asset.value}
