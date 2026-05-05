"""EASM API.

Endpoints
---------
    POST /easm/scan                              enqueue a one-off discovery job
    POST /easm/worker/tick                       run worker N times (admin-only)
    GET  /easm/changes?organization_id=…         list AssetChange entries
    GET  /easm/findings?organization_id=…        list DiscoveryFinding rows (state filterable)
    POST /easm/findings/{id}/promote             promote a NEW finding into the Asset Registry
    POST /easm/findings/{id}/dismiss             dismiss a finding
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.easm.worker import tick
from src.models.asset_schemas import (
    AssetCriticality,
    AssetType,
    DiscoveryMethod,
    canonicalize_asset_value,
    validate_asset_details,
)
from src.models.auth import AuditAction
from src.models.easm import (
    AssetChange,
    ChangeKind,
    ChangeSeverity,
    DiscoveryFinding,
    FindingState,
)
from src.models.exposures import (
    ExposureCategory,
    ExposureFinding,
    ExposureSeverity,
    ExposureSource,
    ExposureState,
    is_state_transition_allowed,
)
from src.models.onboarding import (
    DiscoveryJob,
    DiscoveryJobKind,
    DiscoveryJobStatus,
)
from src.models.threat import Asset, Organization
from src.agents.exposure_triage_agent import triage_exposures
from src.intel.exposure_enrichment import enrich_findings
from src.storage.database import get_session

router = APIRouter(prefix="/easm", tags=["External Surface"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


# --- Schemas ------------------------------------------------------------


class ScanRequest(BaseModel):
    organization_id: uuid.UUID
    kind: DiscoveryJobKind
    target: str = Field(min_length=1, max_length=500)
    asset_id: uuid.UUID | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    job_id: uuid.UUID
    status: str
    kind: str
    target: str


class TickRequest(BaseModel):
    max_jobs: int = Field(default=10, ge=1, le=500)


class ChangeResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    discovery_job_id: uuid.UUID | None
    kind: str
    severity: str
    summary: str
    before: dict | None
    after: dict | None
    detected_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    discovery_job_id: uuid.UUID | None
    parent_asset_id: uuid.UUID | None
    asset_type: str
    value: str
    details: dict | None
    state: str
    confidence: float
    promoted_asset_id: uuid.UUID | None
    discovered_via: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PromoteRequest(BaseModel):
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: list[str] = Field(default_factory=list)
    extra_details: dict[str, Any] | None = None


# --- Endpoints ----------------------------------------------------------


@router.post("/scan", response_model=ScanResponse, status_code=201)
async def trigger_scan(
    body: ScanRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if body.asset_id is not None:
        asset = await db.get(Asset, body.asset_id)
        if not asset or asset.organization_id != body.organization_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "asset_id is in a different organization",
            )

    job = DiscoveryJob(
        organization_id=body.organization_id,
        asset_id=body.asset_id,
        kind=body.kind.value,
        status=DiscoveryJobStatus.QUEUED.value,
        target=body.target.strip(),
        parameters=body.parameters,
        requested_by_user_id=analyst.id,
    )
    db.add(job)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.DISCOVERY_JOB_ENQUEUE,
        user=analyst,
        resource_type="discovery_job",
        resource_id=str(job.id),
        details={
            "organization_id": str(body.organization_id),
            "kind": body.kind.value,
            "target": body.target,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return ScanResponse(
        job_id=job.id, status=job.status, kind=job.kind, target=job.target
    )


@router.post("/worker/tick")
async def worker_tick(
    body: TickRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Manually run the worker loop (admin only).  Returns per-job results.

    In production, the worker runs as a long-lived process. This endpoint
    is for ops + tests.
    """
    results = await tick(db, max_jobs=body.max_jobs)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EASM_JOB_RUN,
        user=admin,
        resource_type="discovery_worker",
        resource_id="manual",
        details={"jobs_processed": len(results)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {"jobs_processed": len(results), "results": results}


@router.get("/changes", response_model=list[ChangeResponse])
async def list_changes(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    asset_id: uuid.UUID | None = None,
    kind: ChangeKind | None = None,
    severity: ChangeSeverity | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    q = select(AssetChange).where(AssetChange.organization_id == organization_id)
    if asset_id is not None:
        q = q.where(AssetChange.asset_id == asset_id)
    if kind is not None:
        q = q.where(AssetChange.kind == kind.value)
    if severity is not None:
        q = q.where(AssetChange.severity == severity.value)
    q = q.order_by(AssetChange.detected_at.desc()).limit(limit).offset(offset)
    return list((await db.execute(q)).scalars().all())


@router.get("/findings", response_model=list[FindingResponse])
async def list_findings(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: FindingState | None = None,
    asset_type: AssetType | None = None,
    parent_asset_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    q = select(DiscoveryFinding).where(
        DiscoveryFinding.organization_id == organization_id
    )
    if state is not None:
        q = q.where(DiscoveryFinding.state == state.value)
    if asset_type is not None:
        q = q.where(DiscoveryFinding.asset_type == asset_type.value)
    if parent_asset_id is not None:
        q = q.where(DiscoveryFinding.parent_asset_id == parent_asset_id)
    q = q.order_by(DiscoveryFinding.created_at.desc()).limit(limit).offset(offset)
    return list((await db.execute(q)).scalars().all())


@router.post("/findings/{finding_id}/promote", response_model=FindingResponse)
async def promote_finding(
    finding_id: uuid.UUID,
    body: PromoteRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    finding = await db.get(DiscoveryFinding, finding_id)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if finding.state != FindingState.NEW.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Finding is already in state {finding.state}; cannot promote",
        )

    asset_type = AssetType(finding.asset_type)
    canonical_value = canonicalize_asset_value(asset_type, finding.value)
    details = {**(finding.details or {}), **(body.extra_details or {})}
    validated_details = validate_asset_details(asset_type, details)

    asset = Asset(
        organization_id=finding.organization_id,
        asset_type=asset_type.value,
        value=canonical_value,
        details=validated_details,
        criticality=body.criticality.value,
        tags=body.tags,
        owner_user_id=analyst.id,
        parent_asset_id=finding.parent_asset_id,
        discovery_method=DiscoveryMethod.EASM_DISCOVERY.value,
        discovered_at=datetime.now(timezone.utc),
    )
    db.add(asset)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "An asset with that value already exists for this organization",
        )

    finding.state = FindingState.PROMOTED.value
    finding.promoted_asset_id = asset.id

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EASM_FINDING_PROMOTE,
        user=analyst,
        resource_type="discovery_finding",
        resource_id=str(finding.id),
        details={
            "asset_id": str(asset.id),
            "asset_type": asset_type.value,
            "value": canonical_value,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding


class ExposureResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    asset_value: str | None = None
    asset_criticality: str | None = None
    discovery_job_id: uuid.UUID | None
    severity: str
    category: str
    state: str
    source: str
    rule_id: str
    title: str
    description: str | None
    target: str
    matched_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    cvss_score: float | None
    cve_ids: list[str]
    cwe_ids: list[str]
    references: list[str]
    matcher_data: dict | None
    state_changed_by_user_id: uuid.UUID | None
    state_changed_at: datetime | None
    state_reason: str | None
    # Enrichment from CveRecord (NVD/EPSS/KEV).
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_added_at: datetime | None = None
    # Structured remediation captured on terminal-state transitions.
    remediation_action: str | None = None
    remediation_patch_version: str | None = None
    remediation_owner: str | None = None
    remediation_notes: str | None = None
    # AI agent outputs.
    ai_priority: float | None = None
    ai_rationale: str | None = None
    ai_triaged_at: datetime | None = None
    ai_suggest_dismiss: bool = False
    ai_dismiss_reason: str | None = None
    # Computed at read time — not stored.
    age_days: int | None = None
    blast_radius: int | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ExposureStateChange(BaseModel):
    to_state: ExposureState
    reason: str | None = None
    # Structured remediation context — optional but encouraged for terminal
    # states. ``remediation_action`` is one of:
    #   patched | mitigated | waived | blocked | false_positive | other
    remediation_action: str | None = Field(default=None, max_length=64)
    remediation_patch_version: str | None = Field(default=None, max_length=128)
    remediation_owner: str | None = Field(default=None, max_length=255)
    remediation_notes: str | None = None


_REMEDIATION_ACTIONS = {
    "patched", "mitigated", "waived", "blocked", "false_positive", "other"
}


def _normalise_target(s: str) -> str:
    """Strip scheme + trailing slash so a target like ``https://x.com/`` and
    an asset value like ``x.com`` collapse onto each other for fuzzy
    orphan-target → asset matching."""
    if not s:
        return ""
    s = s.strip().lower()
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    s = s.split("/", 1)[0]  # drop path
    s = s.split(":", 1)[0]  # drop port for matching purposes
    return s


async def _resolve_assets_for_findings(
    db: AsyncSession, findings: list[ExposureFinding]
) -> dict[uuid.UUID, Asset]:
    """For findings with asset_id set, prefetch Asset rows; for findings
    where asset_id is null but the target string maps onto a known
    Asset.value (host-normalised), return the resolved match too.

    Returns a dict keyed by ExposureFinding.id."""
    result: dict[uuid.UUID, Asset] = {}
    if not findings:
        return result

    # Direct asset_id lookups — single bulk SELECT.
    asset_ids = {f.asset_id for f in findings if f.asset_id}
    if asset_ids:
        rows = (
            await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
        ).scalars().all()
        by_id = {r.id: r for r in rows}
        for f in findings:
            if f.asset_id and f.asset_id in by_id:
                result[f.id] = by_id[f.asset_id]

    # Orphan resolver — for findings without an asset_id, try to match
    # the target host against any Asset.value in the same org.
    orphans = [f for f in findings if not f.asset_id]
    if not orphans:
        return result

    org_ids = {f.organization_id for f in orphans}
    candidate_rows = (
        await db.execute(
            select(Asset).where(Asset.organization_id.in_(org_ids))
        )
    ).scalars().all()
    by_norm: dict[tuple[uuid.UUID, str], Asset] = {}
    for a in candidate_rows:
        if a.value:
            key = (a.organization_id, _normalise_target(a.value))
            # First match wins; subsequent collisions keep the earliest.
            by_norm.setdefault(key, a)
    for f in orphans:
        norm = _normalise_target(f.target)
        if not norm:
            continue
        match = by_norm.get((f.organization_id, norm))
        if match is not None:
            result[f.id] = match
    return result


async def _compute_blast_radius(
    db: AsyncSession,
    findings: list[ExposureFinding],
) -> dict[uuid.UUID, int]:
    """For each finding, count of OTHER open exposures in the same org
    that share at least one CVE id. Single bulk SELECT (we walk the same
    org's open findings once and intersect CVE sets in Python — the
    expected dataset is bounded since most orgs have <5k open exposures)."""
    if not findings:
        return {}
    org_ids = {f.organization_id for f in findings}
    open_rows = (
        await db.execute(
            select(ExposureFinding.id, ExposureFinding.organization_id, ExposureFinding.cve_ids)
            .where(ExposureFinding.organization_id.in_(org_ids))
            .where(ExposureFinding.state == ExposureState.OPEN.value)
        )
    ).all()
    # Map org_id → list[(id, cve_set)]
    by_org: dict[uuid.UUID, list[tuple[uuid.UUID, set[str]]]] = {}
    for row in open_rows:
        cves = {c.upper() for c in (row.cve_ids or []) if isinstance(c, str)}
        by_org.setdefault(row.organization_id, []).append((row.id, cves))

    result: dict[uuid.UUID, int] = {}
    for f in findings:
        my_cves = {c.upper() for c in (f.cve_ids or []) if isinstance(c, str)}
        if not my_cves:
            result[f.id] = 0
            continue
        cohort = by_org.get(f.organization_id, [])
        n = 0
        for fid, other_cves in cohort:
            if fid == f.id:
                continue
            if my_cves & other_cves:
                n += 1
        result[f.id] = n
    return result


def _serialize_exposure(
    f: ExposureFinding,
    *,
    asset: Asset | None,
    blast_radius: int | None,
    now_utc: datetime,
) -> dict:
    age_days: int | None = None
    if f.matched_at is not None:
        delta = now_utc - f.matched_at
        age_days = max(delta.days, 0)
    return {
        "id": f.id,
        "organization_id": f.organization_id,
        "asset_id": f.asset_id or (asset.id if asset else None),
        "asset_value": asset.value if asset else None,
        "asset_criticality": asset.criticality if asset else None,
        "discovery_job_id": f.discovery_job_id,
        "severity": f.severity,
        "category": f.category,
        "state": f.state,
        "source": f.source,
        "rule_id": f.rule_id,
        "title": f.title,
        "description": f.description,
        "target": f.target,
        "matched_at": f.matched_at,
        "last_seen_at": f.last_seen_at,
        "occurrence_count": f.occurrence_count,
        "cvss_score": f.cvss_score,
        "cve_ids": f.cve_ids or [],
        "cwe_ids": f.cwe_ids or [],
        "references": f.references or [],
        "matcher_data": f.matcher_data,
        "state_changed_by_user_id": f.state_changed_by_user_id,
        "state_changed_at": f.state_changed_at,
        "state_reason": f.state_reason,
        "epss_score": f.epss_score,
        "epss_percentile": f.epss_percentile,
        "is_kev": bool(f.is_kev),
        "kev_added_at": f.kev_added_at,
        "remediation_action": f.remediation_action,
        "remediation_patch_version": f.remediation_patch_version,
        "remediation_owner": f.remediation_owner,
        "remediation_notes": f.remediation_notes,
        "ai_priority": f.ai_priority,
        "ai_rationale": f.ai_rationale,
        "ai_triaged_at": f.ai_triaged_at,
        "ai_suggest_dismiss": bool(f.ai_suggest_dismiss),
        "ai_dismiss_reason": f.ai_dismiss_reason,
        "age_days": age_days,
        "blast_radius": blast_radius,
        "created_at": f.created_at,
        "updated_at": f.updated_at,
    }


@router.get("/exposures", response_model=list[ExposureResponse])
async def list_exposures(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: ExposureState | None = None,
    severity: ExposureSeverity | None = None,
    category: ExposureCategory | None = None,
    source: ExposureSource | None = None,
    asset_id: uuid.UUID | None = None,
    cve: str | None = None,
    is_kev: bool | None = None,
    q: str | None = None,
    sort: Annotated[str, Query(pattern="^(last_seen|matched|severity|cvss|epss|priority|age)$")] = "last_seen",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    qs = select(ExposureFinding).where(
        ExposureFinding.organization_id == organization_id
    )
    if state is not None:
        qs = qs.where(ExposureFinding.state == state.value)
    if severity is not None:
        qs = qs.where(ExposureFinding.severity == severity.value)
    if category is not None:
        qs = qs.where(ExposureFinding.category == category.value)
    if source is not None:
        qs = qs.where(ExposureFinding.source == source.value)
    if asset_id is not None:
        qs = qs.where(ExposureFinding.asset_id == asset_id)
    if cve:
        qs = qs.where(ExposureFinding.cve_ids.any(cve.upper()))
    if is_kev is not None:
        qs = qs.where(ExposureFinding.is_kev == is_kev)
    if q:
        like = f"%{q}%"
        qs = qs.where(
            (ExposureFinding.title.ilike(like))
            | (ExposureFinding.rule_id.ilike(like))
        )

    sort_columns = {
        "last_seen": ExposureFinding.last_seen_at.desc(),
        "matched": ExposureFinding.matched_at.desc(),
        "severity": ExposureFinding.severity.asc(),
        "cvss": ExposureFinding.cvss_score.desc().nullslast(),
        "epss": ExposureFinding.epss_score.desc().nullslast(),
        "priority": ExposureFinding.ai_priority.desc().nullslast(),
        "age": ExposureFinding.matched_at.asc(),  # oldest first
    }
    qs = qs.order_by(sort_columns[sort]).limit(limit).offset(offset)
    findings = list((await db.execute(qs)).scalars().all())

    # Read-time enrichment from CveRecord — single bulk SELECT.
    enriched_n = await enrich_findings(db, findings)
    asset_map = await _resolve_assets_for_findings(db, findings)
    blast = await _compute_blast_radius(db, findings)
    if enriched_n:
        await db.commit()  # cache the hydration so subsequent reads are no-ops

    now_utc = datetime.now(timezone.utc)
    return [
        _serialize_exposure(
            f,
            asset=asset_map.get(f.id),
            blast_radius=blast.get(f.id, 0),
            now_utc=now_utc,
        )
        for f in findings
    ]


@router.get("/exposures/{exposure_id}", response_model=ExposureResponse)
async def get_exposure(
    exposure_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(ExposureFinding, exposure_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Exposure not found")
    enriched_n = await enrich_findings(db, [f])
    asset_map = await _resolve_assets_for_findings(db, [f])
    blast = await _compute_blast_radius(db, [f])
    if enriched_n:
        await db.commit()
    return _serialize_exposure(
        f,
        asset=asset_map.get(f.id),
        blast_radius=blast.get(f.id, 0),
        now_utc=datetime.now(timezone.utc),
    )


@router.post("/exposures/{exposure_id}/state", response_model=ExposureResponse)
async def change_exposure_state(
    exposure_id: uuid.UUID,
    body: ExposureStateChange,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    f = await db.get(ExposureFinding, exposure_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Exposure not found")
    if body.to_state.value == f.state:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Exposure is already {f.state}"
        )
    if not is_state_transition_allowed(f.state, body.to_state.value):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Transition {f.state} → {body.to_state.value} is not allowed",
        )
    if body.to_state in (
        ExposureState.ACCEPTED_RISK,
        ExposureState.FALSE_POSITIVE,
        ExposureState.FIXED,
    ):
        if not body.reason or not body.reason.strip():
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "A non-empty reason is required to enter this state",
            )
    if body.remediation_action is not None:
        if body.remediation_action not in _REMEDIATION_ACTIONS:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "remediation_action must be one of "
                + ", ".join(sorted(_REMEDIATION_ACTIONS)),
            )

    from_state = f.state
    f.state = body.to_state.value
    f.state_changed_at = datetime.now(timezone.utc)
    f.state_changed_by_user_id = analyst.id
    f.state_reason = body.reason
    # Structured remediation — captured on terminal transitions and
    # cleared if the analyst reopens (so a stale remediation doesn't
    # follow a re-detected exposure forward).
    if body.to_state in (
        ExposureState.OPEN,
        ExposureState.REOPENED,
        ExposureState.ACKNOWLEDGED,
    ):
        f.remediation_action = None
        f.remediation_patch_version = None
        f.remediation_owner = None
        f.remediation_notes = None
    else:
        f.remediation_action = body.remediation_action
        f.remediation_patch_version = body.remediation_patch_version
        f.remediation_owner = body.remediation_owner or (analyst.email or None)
        f.remediation_notes = body.remediation_notes

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EXPOSURE_STATE_CHANGE,
        user=analyst,
        resource_type="exposure_finding",
        resource_id=str(f.id),
        details={
            "from": from_state,
            "to": body.to_state.value,
            "reason": body.reason,
            "remediation_action": body.remediation_action,
            "remediation_patch_version": body.remediation_patch_version,
            "remediation_owner": f.remediation_owner,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    asset_map = await _resolve_assets_for_findings(db, [f])
    blast = await _compute_blast_radius(db, [f])
    return _serialize_exposure(
        f,
        asset=asset_map.get(f.id),
        blast_radius=blast.get(f.id, 0),
        now_utc=datetime.now(timezone.utc),
    )


class LinkAssetRequest(BaseModel):
    asset_id: uuid.UUID


class TriageRequest(BaseModel):
    exposure_ids: list[uuid.UUID] | None = None
    use_llm: bool = True


class TriageResultDTO(BaseModel):
    exposure_id: uuid.UUID
    ai_priority: float
    ai_rationale: str
    ai_suggest_dismiss: bool
    ai_dismiss_reason: str | None


class TriageResponse(BaseModel):
    triaged_count: int
    suppressed_count: int
    llm_used: bool
    llm_failures: int
    results: list[TriageResultDTO]


@router.post("/exposures/triage", response_model=TriageResponse)
async def trigger_exposure_triage(
    organization_id: uuid.UUID,
    body: TriageRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Run the AI triage agent: rank open exposures by EPSS × CVSS × KEV ×
    asset criticality × age, persist ai_priority + rationale, and flag
    likely false positives based on prior analyst dismissals."""
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    report = await triage_exposures(
        db,
        organization_id,
        exposure_ids=body.exposure_ids,
        use_llm=body.use_llm,
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EXPOSURE_STATE_CHANGE,
        user=analyst,
        resource_type="exposure_finding",
        resource_id="batch",
        details={
            "operation": "ai_triage",
            "triaged_count": report.triaged_count,
            "suppressed_count": report.suppressed_count,
            "llm_used": report.llm_used,
            "llm_failures": report.llm_failures,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return TriageResponse(
        triaged_count=report.triaged_count,
        suppressed_count=report.suppressed_count,
        llm_used=report.llm_used,
        llm_failures=report.llm_failures,
        results=[
            TriageResultDTO(
                exposure_id=r.exposure_id,
                ai_priority=r.ai_priority,
                ai_rationale=r.ai_rationale,
                ai_suggest_dismiss=r.ai_suggest_dismiss,
                ai_dismiss_reason=r.ai_dismiss_reason,
            )
            for r in report.results
        ],
    )


@router.post("/exposures/{exposure_id}/link-asset", response_model=ExposureResponse)
async def link_exposure_to_asset(
    exposure_id: uuid.UUID,
    body: LinkAssetRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Resolve an orphan exposure by linking it to a specific asset."""
    f = await db.get(ExposureFinding, exposure_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Exposure not found")
    asset = await db.get(Asset, body.asset_id)
    if not asset or asset.organization_id != f.organization_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "asset_id is not in this exposure's organization",
        )
    f.asset_id = asset.id

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EXPOSURE_STATE_CHANGE,
        user=analyst,
        resource_type="exposure_finding",
        resource_id=str(f.id),
        details={
            "operation": "link_asset",
            "asset_id": str(asset.id),
            "asset_value": asset.value,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(f)
    asset_map = await _resolve_assets_for_findings(db, [f])
    blast = await _compute_blast_radius(db, [f])
    return _serialize_exposure(
        f,
        asset=asset_map.get(f.id),
        blast_radius=blast.get(f.id, 0),
        now_utc=datetime.now(timezone.utc),
    )


@router.post("/findings/{finding_id}/dismiss", response_model=FindingResponse)
async def dismiss_finding(
    finding_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    finding = await db.get(DiscoveryFinding, finding_id)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if finding.state != FindingState.NEW.value:
        return finding  # idempotent

    finding.state = FindingState.DISMISSED.value
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EASM_FINDING_DISMISS,
        user=analyst,
        resource_type="discovery_finding",
        resource_id=str(finding.id),
        details={"value": finding.value},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(finding)
    return finding
