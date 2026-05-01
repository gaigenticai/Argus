"""DMARC360 API.

Endpoints
---------
    POST /dmarc/reports/aggregate   ingest raw RUA XML (or .gz / .zip)
    GET  /dmarc/reports             list ingested reports
    GET  /dmarc/reports/{id}        report detail
    GET  /dmarc/reports/{id}/records sources breakdown
    POST /dmarc/wizard/{domain}     produce recommended SPF/DKIM/DMARC records
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.dmarc.ingest import ingest_aggregate
from src.dmarc.wizard import generate_records
from src.models.auth import AuditAction
from src.models.dmarc import DmarcReport, DmarcReportRecord
from src.models.threat import Organization
from src.storage.database import get_session

router = APIRouter(prefix="/dmarc", tags=["Brand Protection"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- Schemas ------------------------------------------------------------


class DmarcReportResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    kind: str
    domain: str
    org_name: str | None
    report_id: str
    date_begin: datetime
    date_end: datetime
    policy_p: str | None
    policy_pct: int | None
    total_messages: int
    pass_count: int
    fail_count: int
    quarantine_count: int
    reject_count: int
    parsed: dict
    raw_xml_sha256: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DmarcRecordResponse(BaseModel):
    id: uuid.UUID
    report_id: uuid.UUID
    domain: str
    source_ip: str
    count: int
    disposition: str | None
    spf_result: str | None
    dkim_result: str | None
    spf_aligned: bool | None
    dkim_aligned: bool | None
    header_from: str | None
    envelope_from: str | None

    model_config = {"from_attributes": True}


class WizardRequest(BaseModel):
    sending_ips: list[str] = Field(default_factory=list)
    sending_includes: list[str] = Field(default_factory=list)
    dkim_selectors: list[str] = Field(default_factory=list)
    rua_endpoint: str | None = None
    ruf_endpoint: str | None = None


class WizardResponse(BaseModel):
    domain: str
    spf_record: str
    dkim_records: list[dict[str, str]]
    dmarc_records_progression: list[dict[str, str]]
    rua_endpoint: str
    ruf_endpoint: str | None
    rationale: str


# --- Endpoints ----------------------------------------------------------


@router.post("/reports/aggregate", response_model=DmarcReportResponse, status_code=201)
async def ingest_report(
    request: Request,
    analyst: AnalystUser,
    organization_id: Annotated[uuid.UUID, Form()],
    file: Annotated[UploadFile, File()],
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    blob = await file.read()
    if not blob:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "empty upload")
    import defusedxml.ElementTree as _ET  # Audit B7

    try:
        report, _ = await ingest_aggregate(db, organization_id, blob)
    except (ValueError, _ET.ParseError) as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DMARC_REPORT_INGEST,
        user=analyst,
        resource_type="dmarc_report",
        resource_id=str(report.id),
        details={
            "domain": report.domain,
            "report_id": report.report_id,
            "messages": report.total_messages,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/reports", response_model=list[DmarcReportResponse])
async def list_reports(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    domain: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(DmarcReport).where(DmarcReport.organization_id == organization_id)
    if domain:
        q = q.where(DmarcReport.domain == domain.lower())
    q = q.order_by(DmarcReport.date_begin.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.get("/reports/{report_id}", response_model=DmarcReportResponse)
async def get_report(
    report_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    r = await db.get(DmarcReport, report_id)
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    return r


@router.get("/reports/{report_id}/records", response_model=list[DmarcRecordResponse])
async def report_records(
    report_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
):
    r = await db.get(DmarcReport, report_id)
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    rows = (
        await db.execute(
            select(DmarcReportRecord)
            .where(DmarcReportRecord.report_id == report_id)
            .order_by(DmarcReportRecord.count.desc())
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


@router.post("/wizard/{domain}", response_model=WizardResponse)
async def wizard(
    domain: str,
    body: WizardRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    try:
        out = generate_records(
            domain,
            sending_ips=body.sending_ips,
            sending_includes=body.sending_includes,
            dkim_selectors=body.dkim_selectors or None,
            rua_endpoint=body.rua_endpoint or "rua@dmarc-report.argus.local",
            ruf_endpoint=body.ruf_endpoint,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DMARC_WIZARD_GENERATE,
        user=analyst,
        resource_type="dmarc_wizard",
        resource_id=domain.lower(),
        details={"sending_ips": body.sending_ips, "selectors": body.dkim_selectors},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return WizardResponse(
        domain=out.domain,
        spf_record=out.spf_record,
        dkim_records=out.dkim_records,
        dmarc_records_progression=out.dmarc_records_progression,
        rua_endpoint=out.rua_endpoint,
        ruf_endpoint=out.ruf_endpoint,
        rationale=out.rationale,
    )
