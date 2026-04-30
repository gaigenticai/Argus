"""On-demand scanning endpoints."""

from __future__ import annotations


import uuid

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, CurrentUser
from src.enrichment.surface_scanner import SurfaceScanner
from src.models.threat import Organization, Asset
from src.storage.database import get_session

router = APIRouter(prefix="/scan", tags=["External Surface"])


class ScanRequest(BaseModel):
    domain: str | None = None  # scan specific domain
    full: bool = False  # run all scans


class SubdomainResult(BaseModel):
    subdomain: str
    ip: str | None


@router.post("/{org_id}/subdomains")
async def scan_subdomains(
    org_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Discover subdomains for an organization's domains.

    Returns ``scan_status``:

    * ``ok`` — every passive source completed cleanly. Empty
      ``subdomains`` means the org genuinely has no public subdomain
      footprint.
    * ``partial`` — at least one passive source failed (rate-limit,
      DNS, network). The ``errors`` array enumerates which. The
      analyst is told the result is incomplete so an empty list is
      not mis-read as "we're clean".
    * ``failed`` — every passive source failed. No usable signal.
    """
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    scanner = SurfaceScanner()
    scanner.reset_errors()
    all_results = []
    domains = list(org.domains or [])

    try:
        for domain in domains:
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

    errors = list(scanner.last_errors)
    if not errors:
        scan_status = "ok"
    elif all_results:
        scan_status = "partial"
    else:
        scan_status = "failed"

    return {
        "discovered": len(all_results),
        "subdomains": all_results,
        "scan_status": scan_status,
        "errors": errors,
        "domains_scanned": domains,
    }


@router.post("/{org_id}/exposures")
async def scan_exposures(
    org_id: uuid.UUID,
    analyst: AnalystUser,
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
    """Background task for exposure scanning — stores findings as alerts."""
    import logging
    from src.models.threat import Alert, AlertStatus, ThreatCategory, ThreatSeverity
    from src.storage.database import get_session

    log = logging.getLogger("argus.scan")
    scanner = SurfaceScanner()
    try:
        async for session in get_session():
            for domain in domains:
                results = await scanner.check_common_exposures(domain)
                for r in results:
                    raw_data = r.raw_data or {}
                    alert = Alert(
                        organization_id=org_id,
                        category=ThreatCategory.VULNERABILITY.value,
                        severity=ThreatSeverity.HIGH.value,
                        status=AlertStatus.NEW.value,
                        title=f"Exposure: {r.title} on {domain}",
                        summary=(
                            f"An exposed resource was discovered at {r.source_url}. "
                            f"This may leak sensitive configuration, credentials, or internal service details."
                        ),
                        confidence=0.90,
                        details={
                            "url": r.source_url,
                            "exposure_type": r.title,
                            "domain": domain,
                            "status_code": raw_data.get("status_code"),
                            "response_size": raw_data.get("response_size"),
                            "check_path": raw_data.get("check"),
                        },
                        matched_entities={"domain": domain, "exposure": r.title},
                        recommended_actions=[
                            f"Verify the exposure at {r.source_url}",
                            "Restrict access or remove the exposed resource",
                            "Review server configuration for similar issues",
                        ],
                        agent_reasoning=(
                            f"Surface scanner detected an exposed {r.title} on {domain}. "
                            f"This may leak sensitive configuration, source code, or internal paths."
                        ),
                    )
                    session.add(alert)
                    log.warning(
                        "[scan] Exposure alert created: %s on %s", r.title, domain
                    )
            await session.commit()
    finally:
        await scanner.close()
