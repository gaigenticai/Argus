"""Phase 6 — TI Polish API.

Endpoints
---------
    POST   /intel/actor-playbooks                   create
    GET    /intel/actor-playbooks                   list
    PATCH  /intel/actor-playbooks/{id}              update

    POST   /intel/hardening/generate                generate recs for one or all open exposures
    GET    /intel/hardening                         list recommendations
    POST   /intel/hardening/{id}/state              transition

    POST   /intel/sync/nvd                          import NVD CVE bundle (admin)
    POST   /intel/sync/epss                         import EPSS scores (admin)
    POST   /intel/sync/kev                          import CISA KEV (admin)
    GET    /intel/syncs                             history
    GET    /intel/cves/{cve_id}                     detail (joined NVD + EPSS + KEV)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.intel.hardening import (
    generate_for_finding,
    generate_for_organization,
)
from src.intel.nvd_epss import sync_epss, sync_kev, sync_nvd
from src.models.auth import AuditAction
from src.models.exposures import ExposureFinding
from src.models.intel_polish import (
    ActorPlaybook,
    CveRecord,
    HardeningRecommendation,
    HardeningStatus,
    IntelSync,
)
from src.models.threat import Organization
from src.storage.database import get_session

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# --- Actor playbooks ---------------------------------------------------


class ActorPlaybookCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    actor_alias: str = Field(min_length=1, max_length=255)
    description: str | None = None
    aliases: list[str] = Field(default_factory=list)
    targeted_sectors: list[str] = Field(default_factory=list)
    targeted_geos: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    associated_malware: list[str] = Field(default_factory=list)
    infra_iocs: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ActorPlaybookResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    actor_alias: str
    description: str | None
    aliases: list[str]
    targeted_sectors: list[str]
    targeted_geos: list[str]
    attack_techniques: list[str]
    associated_malware: list[str]
    infra_iocs: list[str]
    references: list[str]
    risk_score: float
    last_observed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ActorPlaybookUpdate(BaseModel):
    description: str | None = None
    aliases: list[str] | None = None
    targeted_sectors: list[str] | None = None
    targeted_geos: list[str] | None = None
    attack_techniques: list[str] | None = None
    associated_malware: list[str] | None = None
    infra_iocs: list[str] | None = None
    references: list[str] | None = None
    risk_score: float | None = Field(default=None, ge=0, le=100)
    last_observed_at: datetime | None = None


@router.post(
    "/actor-playbooks", response_model=ActorPlaybookResponse, status_code=201
)
async def create_actor_playbook(
    body: ActorPlaybookCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    if body.organization_id is not None:
        org = await db.get(Organization, body.organization_id)
        if not org:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    pb = ActorPlaybook(
        organization_id=body.organization_id,
        actor_alias=body.actor_alias.strip(),
        description=body.description,
        aliases=body.aliases,
        targeted_sectors=body.targeted_sectors,
        targeted_geos=body.targeted_geos,
        attack_techniques=body.attack_techniques,
        associated_malware=body.associated_malware,
        infra_iocs=body.infra_iocs,
        references=body.references,
        risk_score=body.risk_score,
    )
    db.add(pb)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Playbook for this actor already exists in scope"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ACTOR_PLAYBOOK_CREATE,
        user=analyst,
        resource_type="actor_playbook",
        resource_id=str(pb.id),
        details={"actor_alias": pb.actor_alias},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(pb)
    return pb


@router.get("/actor-playbooks", response_model=list[ActorPlaybookResponse])
async def list_actor_playbooks(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    q: str | None = None,
):
    query = select(ActorPlaybook)
    if organization_id is not None:
        query = query.where(
            or_(
                ActorPlaybook.organization_id == organization_id,
                ActorPlaybook.organization_id.is_(None),
            )
        )
    if q:
        like = f"%{q}%"
        query = query.where(
            or_(
                ActorPlaybook.actor_alias.ilike(like),
                ActorPlaybook.description.ilike(like),
            )
        )
    query = query.order_by(ActorPlaybook.risk_score.desc(), ActorPlaybook.actor_alias)
    return list((await db.execute(query)).scalars().all())


@router.patch(
    "/actor-playbooks/{playbook_id}", response_model=ActorPlaybookResponse
)
async def update_actor_playbook(
    playbook_id: uuid.UUID,
    body: ActorPlaybookUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    pb = await db.get(ActorPlaybook, playbook_id)
    if not pb:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    for field_name in (
        "description",
        "aliases",
        "targeted_sectors",
        "targeted_geos",
        "attack_techniques",
        "associated_malware",
        "infra_iocs",
        "references",
        "risk_score",
        "last_observed_at",
    ):
        v = getattr(body, field_name)
        if v is not None:
            setattr(pb, field_name, v)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ACTOR_PLAYBOOK_UPDATE,
        user=analyst,
        resource_type="actor_playbook",
        resource_id=str(pb.id),
        details={},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(pb)
    return pb


# --- Hardening ---------------------------------------------------------


class HardeningGenerateRequest(BaseModel):
    organization_id: uuid.UUID
    exposure_finding_id: uuid.UUID | None = None  # if absent, generate for all open


class HardeningRecommendationResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    exposure_finding_id: uuid.UUID | None
    title: str
    summary: str
    cis_control_ids: list[str]
    d3fend_techniques: list[str]
    nist_csf_subcats: list[str]
    priority: str
    estimated_effort_hours: float | None
    status: str
    status_reason: str | None
    status_changed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class HardeningGenerateResponse(BaseModel):
    organization_id: uuid.UUID
    generated_count: int
    recommendation_ids: list[uuid.UUID]


@router.post(
    "/hardening/generate", response_model=HardeningGenerateResponse
)
async def generate_hardening(
    body: HardeningGenerateRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if body.exposure_finding_id is not None:
        f = await db.get(ExposureFinding, body.exposure_finding_id)
        if not f or f.organization_id != body.organization_id:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "Exposure finding not found in this organization",
            )
        gen = await generate_for_finding(db, f)
        ids = [gen.rec_id]
    else:
        recs = await generate_for_organization(db, body.organization_id)
        ids = [r.rec_id for r in recs]
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.HARDENING_GENERATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(body.organization_id),
        details={"recommendations": len(ids)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return HardeningGenerateResponse(
        organization_id=body.organization_id,
        generated_count=len(ids),
        recommendation_ids=ids,
    )


@router.get(
    "/hardening", response_model=list[HardeningRecommendationResponse]
)
async def list_hardening(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    status_filter: Annotated[HardeningStatus | None, Query(alias="status")] = None,
    priority: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(HardeningRecommendation).where(
        HardeningRecommendation.organization_id == organization_id
    )
    if status_filter is not None:
        q = q.where(HardeningRecommendation.status == status_filter.value)
    if priority is not None:
        q = q.where(HardeningRecommendation.priority == priority)
    q = q.order_by(HardeningRecommendation.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


class HardeningStateChange(BaseModel):
    to_state: HardeningStatus
    reason: str | None = None


@router.post(
    "/hardening/{rec_id}/state", response_model=HardeningRecommendationResponse
)
async def change_hardening_state(
    rec_id: uuid.UUID,
    body: HardeningStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rec = await db.get(HardeningRecommendation, rec_id)
    if not rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recommendation not found")
    if body.to_state.value == rec.status:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already {rec.status}")
    if body.to_state in (HardeningStatus.DEFERRED, HardeningStatus.DONE):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required for this state",
            )
    from_state = rec.status
    rec.status = body.to_state.value
    rec.status_changed_at = datetime.now(timezone.utc)
    rec.status_reason = body.reason
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.HARDENING_STATE_CHANGE,
        user=analyst,
        resource_type="hardening_recommendation",
        resource_id=str(rec.id),
        details={"from": from_state, "to": body.to_state.value, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(rec)
    return rec


# --- NVD/EPSS/KEV sync -------------------------------------------------


class IntelSyncRequest(BaseModel):
    source: str  # URL or local path


class IntelSyncResponse(BaseModel):
    source: str
    source_url: str | None
    rows_ingested: int
    rows_updated: int
    succeeded: bool
    error: str | None


@router.post("/sync/nvd", response_model=IntelSyncResponse)
async def trigger_nvd_sync(
    body: IntelSyncRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    report = await sync_nvd(db, source=body.source, triggered_by_user_id=admin.id)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.INTEL_SYNC,
        user=admin,
        resource_type="intel_source",
        resource_id="nvd",
        details={
            "succeeded": report.succeeded,
            "ingested": report.rows_ingested,
            "updated": report.rows_updated,
            "error": report.error,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return IntelSyncResponse(**report.__dict__)


@router.post("/sync/epss", response_model=IntelSyncResponse)
async def trigger_epss_sync(
    body: IntelSyncRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    report = await sync_epss(db, source=body.source, triggered_by_user_id=admin.id)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.INTEL_SYNC,
        user=admin,
        resource_type="intel_source",
        resource_id="epss",
        details={
            "succeeded": report.succeeded,
            "ingested": report.rows_ingested,
            "updated": report.rows_updated,
            "error": report.error,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return IntelSyncResponse(**report.__dict__)


@router.post("/sync/kev", response_model=IntelSyncResponse)
async def trigger_kev_sync(
    body: IntelSyncRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    report = await sync_kev(db, source=body.source, triggered_by_user_id=admin.id)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.INTEL_SYNC,
        user=admin,
        resource_type="intel_source",
        resource_id="kev",
        details={
            "succeeded": report.succeeded,
            "ingested": report.rows_ingested,
            "updated": report.rows_updated,
            "error": report.error,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return IntelSyncResponse(**report.__dict__)


class IntelSyncRow(BaseModel):
    id: uuid.UUID
    source: str
    source_url: str | None
    rows_ingested: int
    rows_updated: int
    succeeded: bool
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/syncs", response_model=list[IntelSyncRow])
async def list_intel_syncs(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    source: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
):
    q = select(IntelSync)
    if source:
        q = q.where(IntelSync.source == source)
    q = q.order_by(IntelSync.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


class CveResponse(BaseModel):
    id: uuid.UUID
    cve_id: str
    title: str | None
    description: str | None
    cvss3_score: float | None
    cvss3_vector: str | None
    cvss_severity: str | None
    cwe_ids: list[str]
    references: list[str]
    cpes: list[str]
    is_kev: bool
    kev_added_at: datetime | None
    epss_score: float | None
    epss_percentile: float | None
    published_at: datetime | None
    last_modified_at: datetime | None

    model_config = {"from_attributes": True}


@router.get("/cves/{cve_id}", response_model=CveResponse)
async def get_cve(
    cve_id: str,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rec = (
        await db.execute(
            select(CveRecord).where(CveRecord.cve_id == cve_id.upper())
        )
    ).scalar_one_or_none()
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE not found")
    return rec


@router.get("/cves", response_model=list[CveResponse])
async def list_cves(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    is_kev: bool | None = None,
    min_epss: Annotated[float, Query(ge=0, le=1)] = 0.0,
    severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(CveRecord)
    if is_kev is not None:
        q = q.where(CveRecord.is_kev == is_kev)
    if min_epss > 0:
        q = q.where(CveRecord.epss_score >= min_epss)
    if severity is not None:
        q = q.where(CveRecord.cvss_severity == severity.lower())
    q = q.order_by(CveRecord.epss_score.desc().nulls_last(), CveRecord.cve_id).limit(limit)
    return list((await db.execute(q)).scalars().all())


# ─── Arabic phishing analyzer (P1 #1.6) ───────────────────────────────


class PhishingAnalyzeRequest(BaseModel):
    """Free-form message scoring — no DB lookups, no auth-context
    mutation. Pass whatever you have; missing fields contribute 0
    confidence to the result."""
    subject: str = ""
    body: str = ""
    sender: str = ""
    urls: list[str] = []


class CIRCLLookupRequest(BaseModel):
    """IOC enrichment via CIRCL public APIs (P2 #2.8). Provide one of
    ``hash`` / ``domain`` / ``ip`` per request — multiple ignored."""
    hash: str | None = None
    domain: str | None = None
    ip: str | None = None


@router.post("/circl/enrich")
async def circl_enrich(
    body: CIRCLLookupRequest,
    analyst: AnalystUser,
):
    """Run CIRCL hashlookup / Passive DNS / Passive SSL on the supplied
    IOC and return the classification + records. pDNS and Passive SSL
    require ARGUS_CIRCL_USERNAME / _PASSWORD; the wrappers no-op
    silently when creds are absent so the route remains usable for
    hash lookups against the anonymous endpoint."""
    from src.enrichment import circl as circl_mod

    if body.hash:
        result = await circl_mod.hashlookup(body.hash)
        return {"kind": "hash", "result":
                result.to_dict() if result else None}
    if body.domain:
        records = await circl_mod.pdns_query(body.domain)
        return {"kind": "pdns", "records": [r.to_dict() for r in records]}
    if body.ip:
        certs = await circl_mod.passive_ssl_query(body.ip)
        return {"kind": "passive_ssl", "certs": [c.to_dict() for c in certs]}
    raise HTTPException(400, "supply one of hash / domain / ip")


class DeciderClassifyRequest(BaseModel):
    """Free-text → MITRE technique mapping. Pure compute."""
    text: str
    top_n: int = 5


@router.post("/decider/classify")
async def decider_classify(
    body: DeciderClassifyRequest,
    analyst: AnalystUser,
):
    """Run the curated CISA-Decider-style classifier (P2 #2.2) against
    arbitrary text and return ranked technique hits with confidence
    scores and the keywords that matched. Pure compute, analyst-gated."""
    from src.intel.decider import classify_text, corpus_version, rule_count

    hits = classify_text(body.text or "", top_n=body.top_n or 5)
    return {
        "corpus_version": corpus_version(),
        "rule_count": rule_count(),
        "hits": [h.to_dict() for h in hits],
    }


@router.post("/phishing/analyze")
async def analyze_phishing(
    body: PhishingAnalyzeRequest,
    analyst: AnalystUser,
):
    """Score an email/message against the Arabic-phishing analyzer.

    Returns the full scoreboard (homoglyphs, bidi-overrides,
    mixed-script domains, GCC pretexts, impersonated brands) so the
    dashboard can render each signal individually. Pure compute — no
    DB or external calls — so admin gating is intentionally not required.
    """
    from src.intel.arabic_phishing import analyze_message

    score = analyze_message(
        subject=body.subject, body=body.body,
        sender=body.sender, urls=body.urls,
    )
    return score.to_dict()
