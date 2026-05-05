"""DMARC360 API.

Endpoints
---------
    POST /dmarc/reports/aggregate           ingest raw RUA XML (or .gz / .zip)
    POST /dmarc/reports/forensic            ingest raw RUF (XML / AFRF / .gz / .zip)
    GET  /dmarc/reports                     list ingested aggregate reports
    GET  /dmarc/reports/{id}                report detail
    GET  /dmarc/reports/{id}/records        sources breakdown
    GET  /dmarc/forensic                    list forensic reports
    GET  /dmarc/forensic/{id}               forensic detail
    POST /dmarc/wizard/{domain}             SPF/DKIM/DMARC progression
    GET  /dmarc/check                       live DNS health (DMARC/BIMI/MTA-STS/TLS-RPT)
    GET  /dmarc/posture/{org_id}            blended 0-100 posture score per domain
    GET  /dmarc/trends/{domain}             pass-% per day for sparkline
    POST /dmarc/plan-rollout                fire the rollout-plan agent

    GET    /dmarc/mailbox-config            list IMAP poller configs (admin)
    POST   /dmarc/mailbox-config            create / upsert (admin)
    DELETE /dmarc/mailbox-config/{id}       delete (admin)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.core.crypto import encrypt
from src.dmarc.dns_check import check_dmarc
from src.dmarc.ingest import ingest_aggregate, ingest_forensic
from src.dmarc.wizard import generate_records
from src.llm.agent_queue import enqueue
from src.models.agent_task import AgentTask
from src.models.auth import AuditAction
from src.models.dmarc import DmarcReport, DmarcReportRecord
from src.models.dmarc_forensic import DmarcForensicReport, DmarcMailboxConfig
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
    posture_score: dict | None = None
    rca: dict | None = None
    agent_summary: dict | None = None
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


class DmarcForensicResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    domain: str
    feedback_type: str | None
    arrival_date: datetime | None
    source_ip: str | None
    reported_domain: str | None
    original_envelope_from: str | None
    original_envelope_to: str | None
    original_mail_from: str | None
    original_rcpt_to: str | None
    auth_failure: str | None
    delivery_result: str | None
    dkim_domain: str | None
    dkim_selector: str | None
    spf_domain: str | None
    raw_headers: str | None
    extras: dict
    agent_summary: dict | None = None
    received_at: datetime

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


class DnsCheckResponse(BaseModel):
    domain: str
    record_present: bool
    raw_record: str | None
    parsed_tags: dict[str, str]
    warnings: list[str]
    bimi_present: bool
    mta_sts_present: bool
    tls_rpt_present: bool
    age_unknown_or_seconds: int | None
    recommendations: list[str]


class PostureScoreEntry(BaseModel):
    domain: str
    score: int
    components: dict[str, Any]
    computed_at: datetime


class TrendPoint(BaseModel):
    day: str  # ISO date
    total: int
    passed: int
    pass_pct: float


class PlanRolloutResponse(BaseModel):
    task_id: uuid.UUID
    status: str
    markdown: str | None
    alignment_pct: float | None
    current_policy: str | None
    ruf_count: int | None


class MailboxConfigCreate(BaseModel):
    organization_id: uuid.UUID
    host: str
    port: int = 993
    username: str
    password: str
    folder: str = "INBOX"
    enabled: bool = True


class MailboxConfigResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    host: str
    port: int
    username: str
    folder: str
    enabled: bool
    last_seen_uid: int | None
    last_polled_at: datetime | None
    last_error: str | None

    model_config = {"from_attributes": True}


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


@router.post("/reports/forensic", response_model=list[DmarcForensicResponse], status_code=201)
async def ingest_forensic_report(
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

    try:
        rows, inserted = await ingest_forensic(db, organization_id, blob)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DMARC_REPORT_INGEST,
        user=analyst,
        resource_type="dmarc_forensic_report",
        resource_id=str(rows[0].id) if rows else "",
        details={"inserted": inserted, "received": len(rows)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    for r in rows:
        await db.refresh(r)
    return rows


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


@router.get("/forensic", response_model=list[DmarcForensicResponse])
async def list_forensic(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    domain: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
):
    q = select(DmarcForensicReport).where(
        DmarcForensicReport.organization_id == organization_id
    )
    if domain:
        q = q.where(DmarcForensicReport.domain == domain.lower())
    q = q.order_by(DmarcForensicReport.received_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.get("/forensic/{forensic_id}", response_model=DmarcForensicResponse)
async def get_forensic(
    forensic_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    r = await db.get(DmarcForensicReport, forensic_id)
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Forensic report not found")
    return r


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


# --- DNS health ---------------------------------------------------------


@router.get("/check", response_model=DnsCheckResponse)
async def dns_check(
    analyst: AnalystUser,
    domain: str = Query(..., min_length=3, max_length=255),
):
    res = await check_dmarc(domain)
    return res


# --- Posture score ------------------------------------------------------


def _policy_strength_pts(p: str | None) -> int:
    p = (p or "").lower()
    if p == "reject":
        return 40
    if p == "quarantine":
        return 20
    if p == "none":
        return 0
    return 0


async def _compute_posture(
    db: AsyncSession, organization_id: uuid.UUID
) -> list[PostureScoreEntry]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    # Latest report per domain (subquery: max(date_begin)).
    latest_dt_q = (
        select(
            DmarcReport.domain,
            func.max(DmarcReport.date_begin).label("max_dt"),
        )
        .where(DmarcReport.organization_id == organization_id)
        .group_by(DmarcReport.domain)
    ).subquery()

    latest_q = select(DmarcReport).join(
        latest_dt_q,
        and_(
            DmarcReport.domain == latest_dt_q.c.domain,
            DmarcReport.date_begin == latest_dt_q.c.max_dt,
            DmarcReport.organization_id == organization_id,
        ),
    )
    latest_reports = list((await db.execute(latest_q)).scalars().all())

    out: list[PostureScoreEntry] = []
    now = datetime.now(timezone.utc)
    for r in latest_reports:
        # 30d coverage
        agg = (
            await db.execute(
                select(
                    func.coalesce(func.sum(DmarcReportRecord.count), 0),
                    func.coalesce(
                        func.sum(
                            case(
                                (
                                    (DmarcReportRecord.spf_aligned.is_(True))
                                    | (DmarcReportRecord.dkim_aligned.is_(True)),
                                    DmarcReportRecord.count,
                                ),
                                else_=0,
                            )
                        ),
                        0,
                    ),
                ).where(
                    and_(
                        DmarcReportRecord.organization_id == organization_id,
                        DmarcReportRecord.domain == r.domain,
                        DmarcReportRecord.created_at >= cutoff,
                    )
                )
            )
        ).one()
        total = int(agg[0] or 0)
        passed = int(agg[1] or 0)
        pct = (passed / total) if total else 0.0
        coverage_pts = int(round(pct * 30))

        ruf_count = (
            await db.execute(
                select(func.count(DmarcForensicReport.id)).where(
                    and_(
                        DmarcForensicReport.organization_id == organization_id,
                        DmarcForensicReport.domain == r.domain,
                        DmarcForensicReport.received_at >= cutoff,
                    )
                )
            )
        ).scalar_one() or 0
        ruf_pts = 10 if ruf_count > 0 else 0

        # alignment trend — compare last-7d vs prior-7d pass%.
        seven = now - timedelta(days=7)
        prior = now - timedelta(days=14)
        trend_q_recent = select(
            func.coalesce(func.sum(DmarcReportRecord.count), 0),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (DmarcReportRecord.spf_aligned.is_(True))
                            | (DmarcReportRecord.dkim_aligned.is_(True)),
                            DmarcReportRecord.count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ),
        ).where(
            and_(
                DmarcReportRecord.organization_id == organization_id,
                DmarcReportRecord.domain == r.domain,
                DmarcReportRecord.created_at >= seven,
            )
        )
        trend_q_prior = select(
            func.coalesce(func.sum(DmarcReportRecord.count), 0),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (DmarcReportRecord.spf_aligned.is_(True))
                            | (DmarcReportRecord.dkim_aligned.is_(True)),
                            DmarcReportRecord.count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ),
        ).where(
            and_(
                DmarcReportRecord.organization_id == organization_id,
                DmarcReportRecord.domain == r.domain,
                DmarcReportRecord.created_at >= prior,
                DmarcReportRecord.created_at < seven,
            )
        )
        rt, rp = (await db.execute(trend_q_recent)).one()
        pt, pp = (await db.execute(trend_q_prior)).one()
        recent_pct = (float(rp or 0) / float(rt)) if rt else 0.0
        prior_pct = (float(pp or 0) / float(pt)) if pt else 0.0
        delta = recent_pct - prior_pct
        trend_pts = max(0, min(20, int(round((delta + 0.2) * 50))))

        policy_pts = _policy_strength_pts(r.policy_p)
        score = max(0, min(100, policy_pts + coverage_pts + ruf_pts + trend_pts))
        components = {
            "policy_strength": policy_pts,
            "coverage_pts": coverage_pts,
            "ruf_presence": ruf_pts,
            "alignment_trend": trend_pts,
            "alignment_30d_pct": round(pct * 100, 2),
            "ruf_count_30d": int(ruf_count),
            "recent_pct": round(recent_pct * 100, 2),
            "prior_pct": round(prior_pct * 100, 2),
        }
        # Persist into the latest report so historical posture exists.
        r.posture_score = {
            "score": score,
            "components": components,
            "computed_at": now.isoformat(),
        }
        out.append(
            PostureScoreEntry(
                domain=r.domain,
                score=score,
                components=components,
                computed_at=now,
            )
        )
    return out


@router.get("/posture/{org_id}", response_model=list[PostureScoreEntry])
async def posture(
    org_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    res = await _compute_posture(db, org_id)
    await db.commit()
    return res


# --- Trends -------------------------------------------------------------


@router.get("/trends/{domain}", response_model=list[TrendPoint])
async def trends(
    domain: str,
    analyst: AnalystUser,
    organization_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    days: Annotated[int, Query(ge=1, le=180)] = 30,
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    day = func.date_trunc("day", DmarcReportRecord.created_at).label("day")
    pass_expr = case(
        (
            (DmarcReportRecord.spf_aligned.is_(True))
            | (DmarcReportRecord.dkim_aligned.is_(True)),
            DmarcReportRecord.count,
        ),
        else_=0,
    )
    q = (
        select(
            day,
            func.coalesce(func.sum(DmarcReportRecord.count), 0),
            func.coalesce(func.sum(pass_expr), 0),
        )
        .where(
            and_(
                DmarcReportRecord.organization_id == organization_id,
                DmarcReportRecord.domain == domain.lower(),
                DmarcReportRecord.created_at >= cutoff,
            )
        )
        .group_by(day)
        .order_by(day)
    )
    rows = (await db.execute(q)).all()
    out: list[TrendPoint] = []
    for d, total, passed in rows:
        total_i = int(total or 0)
        passed_i = int(passed or 0)
        pct = (100.0 * passed_i / total_i) if total_i else 0.0
        out.append(
            TrendPoint(
                day=d.date().isoformat() if hasattr(d, "date") else str(d),
                total=total_i,
                passed=passed_i,
                pass_pct=round(pct, 2),
            )
        )
    return out


# --- Plan rollout -------------------------------------------------------


@router.post("/plan-rollout", response_model=PlanRolloutResponse)
async def plan_rollout(
    request: Request,
    analyst: AnalystUser,
    domain: str = Query(..., min_length=3, max_length=255),
    organization_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_session),
):
    """Synchronously enqueue + (best-effort) wait for the rollout plan."""
    task = await enqueue(
        db,
        kind="dmarc_policy_rollout_plan",
        payload={"domain": domain.lower(), "organization_id": str(organization_id)},
        organization_id=organization_id,
        dedup_key=f"rollout:{organization_id}:{domain.lower()}:{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
        priority=4,
    )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DMARC_WIZARD_GENERATE,
        user=analyst,
        resource_type="dmarc_rollout_plan",
        resource_id=domain.lower(),
        details={"task_id": str(task.id)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()

    # Return the most recent completed plan if available; the worker
    # may still be processing this exact task.
    refreshed = await db.get(AgentTask, task.id)
    md: str | None = None
    align: float | None = None
    cur: str | None = None
    ruf: int | None = None
    if refreshed and refreshed.result:
        md = refreshed.result.get("markdown")
        align = refreshed.result.get("alignment_pct")
        cur = refreshed.result.get("current_policy")
        ruf = refreshed.result.get("ruf_count")
    return PlanRolloutResponse(
        task_id=task.id,
        status=refreshed.status if refreshed else task.status,
        markdown=md,
        alignment_pct=align,
        current_policy=cur,
        ruf_count=ruf,
    )


# --- Mailbox config (admin) --------------------------------------------


@router.get("/mailbox-config", response_model=list[MailboxConfigResponse])
async def list_mailbox_configs(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
):
    q = select(DmarcMailboxConfig)
    if organization_id is not None:
        q = q.where(DmarcMailboxConfig.organization_id == organization_id)
    return list((await db.execute(q)).scalars().all())


@router.post("/mailbox-config", response_model=MailboxConfigResponse, status_code=201)
async def upsert_mailbox_config(
    body: MailboxConfigCreate,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    existing = (
        await db.execute(
            select(DmarcMailboxConfig).where(
                DmarcMailboxConfig.organization_id == body.organization_id
            )
        )
    ).scalar_one_or_none()
    enc = encrypt(body.password)
    if existing is None:
        row = DmarcMailboxConfig(
            organization_id=body.organization_id,
            host=body.host,
            port=body.port,
            username=body.username,
            password_encrypted=enc,
            folder=body.folder,
            enabled=body.enabled,
        )
        db.add(row)
        await db.flush()
    else:
        existing.host = body.host
        existing.port = body.port
        existing.username = body.username
        existing.password_encrypted = enc
        existing.folder = body.folder
        existing.enabled = body.enabled
        await db.flush()
        row = existing
    await db.commit()
    await db.refresh(row)
    return row


@router.delete("/mailbox-config/{config_id}", status_code=204)
async def delete_mailbox_config(
    config_id: uuid.UUID,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    row = await db.get(DmarcMailboxConfig, config_id)
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mailbox config not found")
    await db.delete(row)
    await db.commit()
    return None
