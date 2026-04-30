"""Report generation and listing endpoints."""

from __future__ import annotations


import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.models.threat import Alert, Asset, Organization, Report, VIPTarget
from src.storage.database import get_session
from src.core.report_generator import ArgusReportGenerator

router = APIRouter(prefix="/reports", tags=["Compliance & DLP"])

# Directory where generated reports are stored
REPORTS_DIR = Path(os.getenv("ARGUS_REPORTS_DIR", "data/reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ReportGenerateRequest(BaseModel):
    org_id: uuid.UUID
    date_from: datetime
    date_to: datetime
    classification: str = "CONFIDENTIAL"


class ReportResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    date_from: datetime
    date_to: datetime
    file_path: str
    summary: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/generate", response_class=StreamingResponse)
async def generate_report(
    body: ReportGenerateRequest,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Generate a threat intelligence PDF report for the given organization and date range."""

    # Fetch organization
    org = await db.get(Organization, body.org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    # Fetch alerts in date range
    alerts_q = (
        select(Alert)
        .where(Alert.organization_id == body.org_id)
        .where(Alert.created_at >= body.date_from)
        .where(Alert.created_at <= body.date_to)
        .order_by(desc(Alert.created_at))
    )
    result = await db.execute(alerts_q)
    alert_rows = result.scalars().all()

    # Convert ORM objects to dicts for the report generator
    alerts_data = []
    for a in alert_rows:
        alerts_data.append({
            "id": str(a.id),
            "severity": a.severity,
            "category": a.category,
            "status": a.status,
            "title": a.title,
            "summary": a.summary,
            "confidence": a.confidence,
            "agent_reasoning": a.agent_reasoning,
            "recommended_actions": a.recommended_actions,
            "matched_entities": a.matched_entities,
            "created_at": a.created_at,
        })

    # Fetch assets
    assets_q = select(Asset).where(Asset.organization_id == body.org_id)
    assets_result = await db.execute(assets_q)
    asset_rows = assets_result.scalars().all()
    assets_data = [
        {
            "asset_type": a.asset_type,
            "value": a.value,
            "is_active": a.is_active,
            "last_scanned_at": a.last_scanned_at,
            "details": a.details,
        }
        for a in asset_rows
    ]

    # Fetch VIPs
    vips_q = select(VIPTarget).where(VIPTarget.organization_id == body.org_id)
    vips_result = await db.execute(vips_q)
    vip_rows = vips_result.scalars().all()
    vips_data = [
        {
            "name": v.name,
            "title": v.title,
            "emails": v.emails,
            "usernames": v.usernames,
            "phone_numbers": v.phone_numbers,
        }
        for v in vip_rows
    ]

    # Generate PDF
    generator = ArgusReportGenerator(
        organization_name=org.name,
        date_from=body.date_from,
        date_to=body.date_to,
        classification=body.classification,
    )
    pdf_bytes = generator.generate(
        alerts=alerts_data,
        assets=assets_data,
        vips=vips_data,
    )

    # Persist to disk
    report_id = uuid.uuid4()
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"argus_report_{org.name.lower().replace(' ', '_')}_{date_str}_{report_id.hex[:8]}.pdf"
    filepath = REPORTS_DIR / filename
    filepath.write_bytes(pdf_bytes)

    # Build summary for DB record
    total = len(alerts_data)
    crit_count = sum(1 for a in alerts_data if a["severity"] == "critical")
    high_count = sum(1 for a in alerts_data if a["severity"] == "high")
    summary_text = (
        f"{total} alerts ({crit_count} critical, {high_count} high) "
        f"from {body.date_from.strftime('%Y-%m-%d')} to {body.date_to.strftime('%Y-%m-%d')}"
    )

    title = (
        f"Threat Intelligence Report — {org.name} — "
        f"{body.date_from.strftime('%b %d')} to {body.date_to.strftime('%b %d, %Y')}"
    )

    # Save report metadata
    report = Report(
        id=report_id,
        organization_id=body.org_id,
        title=title,
        date_from=body.date_from,
        date_to=body.date_to,
        file_path=str(filepath),
        summary=summary_text,
    )
    db.add(report)
    await db.commit()

    # Stream the PDF back
    import io
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-Id": str(report_id),
        },
    )


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    analyst: AnalystUser,
    org_id: uuid.UUID | None = None,
    limit: int = Query(20, le=100),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List previously generated reports."""
    query = select(Report).order_by(desc(Report.created_at))

    if org_id:
        query = query.where(Report.organization_id == org_id)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{report_id}", response_class=StreamingResponse)
async def download_report(
    report_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Download a previously generated report PDF."""
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found")

    filepath = Path(report.file_path)
    if not filepath.exists():
        raise HTTPException(404, "Report file not found on disk")

    import io
    return StreamingResponse(
        io.BytesIO(filepath.read_bytes()),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filepath.name}"',
        },
    )
