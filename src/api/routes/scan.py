"""On-demand scanning endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.enrichment.surface_scanner import SurfaceScanner
from src.models.threat import Organization, Asset
from src.storage.database import get_session

router = APIRouter(prefix="/scan", tags=["scanning"])


class ScanRequest(BaseModel):
    domain: str | None = None  # scan specific domain
    full: bool = False  # run all scans


class SubdomainResult(BaseModel):
    subdomain: str
    ip: str | None


@router.post("/{org_id}/subdomains")
async def scan_subdomains(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
):
    """Discover subdomains for an organization's domains."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    scanner = SurfaceScanner()
    all_results = []

    try:
        for domain in (org.domains or []):
            subdomains = await scanner.discover_subdomains(domain)
            all_results.extend(subdomains)

            # Store as assets
            for sub in subdomains:
                existing = await db.execute(
                    select(Asset).where(
                        Asset.organization_id == org_id,
                        Asset.value == sub["subdomain"],
                    )
                )
                if not existing.scalar_one_or_none():
                    asset = Asset(
                        organization_id=org_id,
                        asset_type="subdomain",
                        value=sub["subdomain"],
                        details=sub,
                    )
                    db.add(asset)

        await db.commit()
    finally:
        await scanner.close()

    return {"discovered": len(all_results), "subdomains": all_results}


@router.post("/{org_id}/exposures")
async def scan_exposures(
    org_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
):
    """Check for common misconfigurations and exposures."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    # Run in background since this can take a while
    background_tasks.add_task(_run_exposure_scan, org_id, org.domains or [])

    return {"status": "scan_started", "domains": org.domains}


async def _run_exposure_scan(org_id: uuid.UUID, domains: list[str]):
    """Background task for exposure scanning."""
    scanner = SurfaceScanner()
    try:
        for domain in domains:
            results = await scanner.check_common_exposures(domain)
            # Results would be fed into the ingestion pipeline
            # For now just log them
            for r in results:
                import logging
                logging.getLogger("argus").warning(
                    f"Exposure found for {domain}: {r.title}"
                )
    finally:
        await scanner.close()
