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


class SigmaFromIocRequest(BaseModel):
    """Generate + translate a Sigma rule from a single IOC (P2 #2.3)."""
    ioc_value: str
    ioc_type: str
    technique_id: str | None = None
    title: str | None = None
    description: str | None = None
    rule_id: str | None = None


class SigmaFromTechniqueRequest(BaseModel):
    technique_id: str
    selection: dict[str, str] | None = None
    title: str | None = None
    description: str | None = None
    rule_id: str | None = None


class SigmaTranslateRequest(BaseModel):
    sigma_yaml: str


@router.get("/sigma/backends")
async def sigma_backends(analyst: AnalystUser):
    """List the SIEM-dialect backends available in this deployment."""
    from src.intel.sigma_rules import available_backends
    return {"backends": available_backends()}


@router.post("/sigma/from-ioc")
async def sigma_from_ioc(
    body: SigmaFromIocRequest,
    analyst: AnalystUser,
):
    """Build a Sigma rule from an IOC and translate to every backend."""
    from src.intel.sigma_rules import translate_for_ioc

    yaml, results = translate_for_ioc(
        ioc_value=body.ioc_value, ioc_type=body.ioc_type,
        technique_id=body.technique_id,
        title=body.title, description=body.description,
        rule_id=body.rule_id,
    )
    return {
        "sigma_yaml": yaml,
        "translations": [r.to_dict() for r in results],
    }


@router.post("/sigma/from-technique")
async def sigma_from_technique(
    body: SigmaFromTechniqueRequest,
    analyst: AnalystUser,
):
    """Build a Sigma rule from a MITRE technique and translate."""
    from src.intel.sigma_rules import translate_for_technique

    yaml, results = translate_for_technique(
        technique_id=body.technique_id, selection=body.selection,
        title=body.title, description=body.description,
        rule_id=body.rule_id,
    )
    return {
        "sigma_yaml": yaml,
        "translations": [r.to_dict() for r in results],
    }


@router.post("/sigma/translate")
async def sigma_translate(
    body: SigmaTranslateRequest,
    analyst: AnalystUser,
):
    """Translate an arbitrary Sigma YAML rule to every backend."""
    from src.intel.sigma_rules import translate_rule

    return {
        "translations": [r.to_dict() for r in translate_rule(body.sigma_yaml)],
    }


@router.get("/forensics/availability")
async def forensics_availability(analyst: AnalystUser):
    """Report which IR-workbench tools are available in this deployment
    (P3 #3.11)."""
    from src.integrations.forensics import (
        velociraptor_configured,
        volatility_available,
    )
    return {
        "volatility": volatility_available(),
        "velociraptor": {"configured": velociraptor_configured()},
    }


class VolatilityRunRequest(BaseModel):
    plugin: str
    image_path: str  # absolute path to the memory image on the host
    extra_args: list[str] | None = None
    timeout_seconds: int = 1800


@router.post("/forensics/volatility/run")
async def forensics_volatility_run(
    body: VolatilityRunRequest,
    analyst: AnalystUser,
):
    """Run a Volatility 3 plugin against a memory image."""
    from src.integrations.forensics import volatility_run_plugin

    result = await volatility_run_plugin(
        plugin=body.plugin, image_path=body.image_path,
        extra_args=body.extra_args, timeout_seconds=body.timeout_seconds,
    )
    return result.to_dict()


@router.get("/forensics/velociraptor/clients")
async def forensics_velociraptor_clients(
    analyst: AnalystUser,
    search: str = "",
    limit: int = Query(default=50, ge=1, le=500),
):
    from src.integrations.forensics import velociraptor_list_clients

    result = await velociraptor_list_clients(search=search, limit=limit)
    return result.to_dict()


class VelociraptorScheduleRequest(BaseModel):
    client_id: str
    artifact: str
    parameters: dict[str, str] | None = None


@router.post("/forensics/velociraptor/schedule")
async def forensics_velociraptor_schedule(
    body: VelociraptorScheduleRequest,
    analyst: AnalystUser,
):
    from src.integrations.forensics import velociraptor_schedule_collection

    result = await velociraptor_schedule_collection(
        client_id=body.client_id,
        artifact=body.artifact,
        parameters=body.parameters,
    )
    return result.to_dict()


@router.get("/breach/providers")
async def breach_providers(analyst: AnalystUser):
    """List every breach-credential provider + config state (P3 #3.9)."""
    from src.integrations.breach import list_available
    return {"providers": list_available()}


class BreachSearchEmailRequest(BaseModel):
    email: str
    providers: list[str] | None = None


@router.post("/breach/search/email")
async def breach_search_email(
    body: BreachSearchEmailRequest,
    analyst: AnalystUser,
):
    """Fan-out email lookup across configured breach providers."""
    from src.integrations.breach import search_email_unified

    results = await search_email_unified(
        body.email, providers=body.providers,
    )
    return {
        "email": body.email,
        "results": [r.to_dict() for r in results],
    }


class BreachSearchPasswordRequest(BaseModel):
    sha1_hash: str  # 40-char hex SHA-1 of the candidate password


@router.post("/breach/search/password")
async def breach_search_password(
    body: BreachSearchPasswordRequest,
    analyst: AnalystUser,
):
    """HIBP k-anonymity password lookup. Only the first 5 chars of the
    SHA-1 leave Argus."""
    from src.integrations.breach.hibp import HibpProvider

    result = await HibpProvider().search_password_hash(body.sha1_hash)
    return result.to_dict()


@router.get("/soar/connectors")
async def soar_connectors(analyst: AnalystUser):
    """List every SOAR connector + its configuration state (P3 #3.7)."""
    from src.integrations.soar import list_available
    return {"connectors": list_available()}


@router.get("/soar/{name}/health")
async def soar_health(name: str, analyst: AnalystUser):
    from src.integrations.soar import get_connector

    conn = get_connector(name)
    if conn is None:
        raise HTTPException(404, f"unknown SOAR connector {name!r}")
    result = await conn.health_check()
    return result.to_dict()


class SoarPushEventsRequest(BaseModel):
    events: list[dict]


@router.post("/soar/{name}/push")
async def soar_push(
    name: str,
    body: SoarPushEventsRequest,
    analyst: AnalystUser,
):
    from src.integrations.soar import get_connector

    conn = get_connector(name)
    if conn is None:
        raise HTTPException(404, f"unknown SOAR connector {name!r}")
    result = await conn.push_events(body.events)
    return result.to_dict()


@router.get("/siem/connectors")
async def siem_connectors(analyst: AnalystUser):
    """List every SIEM connector + its configuration state (P2 #2.7)."""
    from src.integrations.siem import list_available
    return {"connectors": list_available()}


@router.get("/siem/{name}/health")
async def siem_health(name: str, analyst: AnalystUser):
    from src.integrations.siem import get_connector

    conn = get_connector(name)
    if conn is None:
        raise HTTPException(404, f"unknown connector {name!r}")
    result = await conn.health_check()
    return result.to_dict()


class SiemPushEventsRequest(BaseModel):
    """Push a batch of pre-shaped events to a SIEM connector. The dict
    shape is the connector's responsibility to translate."""
    events: list[dict]


@router.post("/siem/{name}/push")
async def siem_push(
    name: str,
    body: SiemPushEventsRequest,
    analyst: AnalystUser,
):
    from src.integrations.siem import get_connector

    conn = get_connector(name)
    if conn is None:
        raise HTTPException(404, f"unknown connector {name!r}")
    result = await conn.push_events(body.events)
    return result.to_dict()


@router.get("/opencti/availability")
async def opencti_availability(analyst: AnalystUser):
    from src.integrations import opencti as opencti_mod
    return {"configured": opencti_mod.is_configured()}


class OpenCTIProjectIocRequest(BaseModel):
    ioc_type: str
    value: str
    confidence: int = 75
    actor_alias: str | None = None


@router.post("/opencti/project/ioc")
async def opencti_project_ioc(
    body: OpenCTIProjectIocRequest,
    analyst: AnalystUser,
):
    """Project an IOC into the co-deployed OpenCTI as a STIX Indicator."""
    import asyncio
    from src.integrations import opencti as opencti_mod

    result = await asyncio.to_thread(
        opencti_mod.project_ioc,
        ioc_type=body.ioc_type, value=body.value,
        confidence=body.confidence, actor_alias=body.actor_alias,
    )
    return result.to_dict()


@router.get("/opencti/graph/{stix_id:path}")
async def opencti_graph(
    stix_id: str,
    analyst: AnalystUser,
    depth: int = Query(default=1, ge=1, le=3),
    limit: int = Query(default=50, ge=1, le=200),
):
    """Fetch a STIX entity's neighbourhood from OpenCTI for the graph
    view. Returns ``{root, nodes, edges, note}`` even when OpenCTI is
    unavailable so the dashboard renders an explanatory empty state."""
    import asyncio
    from src.integrations import opencti as opencti_mod

    n = await asyncio.to_thread(
        opencti_mod.fetch_neighbourhood,
        stix_id=stix_id, depth=depth, limit=limit,
    )
    return n.to_dict()


@router.get("/misp/availability")
async def misp_availability(analyst: AnalystUser):
    from src.integrations import misp as misp_mod
    return {"configured": misp_mod.is_configured()}


@router.get("/misp/events")
async def misp_events(
    analyst: AnalystUser,
    days: int = Query(default=7, ge=1, le=90),
    tag: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
):
    """List MISP events updated in the last N days. Optional tag filter."""
    import asyncio
    from src.integrations import misp as misp_mod

    events = await asyncio.to_thread(
        misp_mod.fetch_recent_events, days, tag=tag, limit=limit,
    )
    return {"events": [e.to_dict() for e in events]}


@router.get("/misp/events/{event_uuid}/attributes")
async def misp_event_attributes(
    event_uuid: str,
    analyst: AnalystUser,
    to_ids_only: bool = Query(default=True),
):
    import asyncio
    from src.integrations import misp as misp_mod

    attrs = await asyncio.to_thread(
        misp_mod.fetch_event_attributes, event_uuid, to_ids_only=to_ids_only,
    )
    return {"attributes": [a.to_dict() for a in attrs]}


@router.get("/misp/galaxies/{galaxy_type}")
async def misp_galaxy_clusters(
    galaxy_type: str,
    analyst: AnalystUser,
    limit: int = Query(default=100, ge=1, le=500),
):
    import asyncio
    from src.integrations import misp as misp_mod

    clusters = await asyncio.to_thread(
        misp_mod.fetch_galaxy_clusters, galaxy_type, limit=limit,
    )
    return {"clusters": [c.to_dict() for c in clusters]}


class YaraScanRequest(BaseModel):
    """yara-x scan over a base64-encoded blob (P2 #2.10)."""
    rules_text: str
    sample_b64: str


@router.get("/yara/availability")
async def yara_availability(analyst: AnalystUser):
    from src.intel.yarax_capa import is_available
    return is_available()


@router.post("/yara/scan")
async def yara_scan(
    body: YaraScanRequest,
    analyst: AnalystUser,
):
    """Compile + scan once. For repeated scans against the same rules
    use the in-process scanner — this route is for ad-hoc analyst use."""
    import asyncio
    import base64
    from src.intel.yarax_capa import scan_bytes

    try:
        sample = base64.b64decode(body.sample_b64, validate=False)
    except Exception:
        raise HTTPException(400, "sample_b64 is not valid base64")
    matches = await asyncio.to_thread(scan_bytes, sample, rules_text=body.rules_text)
    return {"matches": [m.to_dict() for m in matches]}


class CapaExtractRequest(BaseModel):
    """Submit a base64-encoded PE / ELF / Mach-O for capa analysis."""
    sample_b64: str


@router.post("/capa/extract")
async def capa_extract(
    body: CapaExtractRequest,
    analyst: AnalystUser,
):
    import asyncio
    import base64
    from src.intel.yarax_capa import extract_capabilities

    try:
        sample = base64.b64decode(body.sample_b64, validate=False)
    except Exception:
        raise HTTPException(400, "sample_b64 is not valid base64")
    result = await asyncio.to_thread(extract_capabilities, sample)
    return result.to_dict()


class KestrelRenderRequest(BaseModel):
    title: str
    source_name: str  # stixshifter module name (splunk, elastic_ecs, …)
    iocs: list[dict[str, str]]  # [{type, value}, …]
    technique_id: str | None = None


class KestrelExecuteRequest(BaseModel):
    script: str
    timeout_seconds: int = 120


@router.get("/kestrel/availability")
async def kestrel_availability(analyst: AnalystUser):
    """Report whether the Kestrel CLI / module is available in this
    deployment so the dashboard can grey out the "Run hunt" button
    when only the script-rendering path is usable."""
    from src.intel.kestrel_hunt import is_available
    return is_available()


@router.post("/kestrel/render")
async def kestrel_render(
    body: KestrelRenderRequest,
    analyst: AnalystUser,
):
    """Compose a Kestrel hunt script — pure function, works regardless
    of whether Kestrel is installed. The output script is the durable
    case artefact."""
    from src.intel.kestrel_hunt import render_hunt

    iocs = [(d.get("type", ""), d.get("value", "")) for d in body.iocs
            if d.get("value")]
    if not iocs:
        raise HTTPException(400, "at least one IOC required")
    hunt = render_hunt(
        title=body.title, source_name=body.source_name,
        iocs=iocs, technique_id=body.technique_id,
    )
    return hunt.to_dict()


@router.post("/kestrel/execute")
async def kestrel_execute(
    body: KestrelExecuteRequest,
    analyst: AnalystUser,
):
    """Run a Kestrel hunt script. Returns ``available=False`` when
    Kestrel is not installed; the analyst can still copy the script."""
    from src.intel.kestrel_hunt import execute_hunt

    result = await execute_hunt(
        body.script, timeout_seconds=body.timeout_seconds,
    )
    return result.to_dict()


class StixTranslateRequest(BaseModel):
    stix_pattern: str
    modules: list[str] | None = None


class StixFromIocRequest(BaseModel):
    ioc_type: str
    ioc_value: str
    modules: list[str] | None = None


@router.get("/stix-shifter/modules")
async def stix_shifter_modules(analyst: AnalystUser):
    """List the stix-shifter data-source modules importable in this deployment."""
    from src.intel.stix_shifter import available_modules
    return {"modules": available_modules()}


@router.post("/stix-shifter/translate")
async def stix_shifter_translate(
    body: StixTranslateRequest,
    analyst: AnalystUser,
):
    """Translate a STIX 2.x pattern into native query language for every
    available data-source module.

    stix-shifter spawns its own event loop internally, so we run the
    sync entry point inside ``asyncio.to_thread`` to avoid clashing
    with FastAPI's running loop ("event loop is already running").
    """
    import asyncio
    from src.intel.stix_shifter import translate_pattern

    results = await asyncio.to_thread(
        translate_pattern, body.stix_pattern, modules=body.modules,
    )
    return {
        "stix_pattern": body.stix_pattern,
        "translations": [t.to_dict() for t in results],
    }


@router.post("/stix-shifter/from-ioc")
async def stix_shifter_from_ioc(
    body: StixFromIocRequest,
    analyst: AnalystUser,
):
    """One-shot IOC → STIX pattern → per-module translations."""
    import asyncio
    from src.intel.stix_shifter import translate_for_ioc

    pattern, results = await asyncio.to_thread(
        translate_for_ioc, body.ioc_type, body.ioc_value,
        modules=body.modules,
    )
    return {
        "stix_pattern": pattern,
        "translations": [r.to_dict() for r in results],
    }


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
