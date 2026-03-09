"""Organization management endpoints."""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
    await db.commit()
    await db.refresh(org)
    return org


@router.get("/", response_model=list[OrgResponse])
async def list_organizations(db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(Organization))
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


@router.post("/{org_id}/assets")
async def add_asset(
    org_id: uuid.UUID,
    body: AssetCreate,
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
    await db.commit()
    await db.refresh(asset)
    return {"id": str(asset.id), "type": asset.asset_type, "value": asset.value}
