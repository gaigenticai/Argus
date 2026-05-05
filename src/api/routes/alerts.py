"""Alert management endpoints — single-tenant.

All list/get/search/patch operations scope to the system organisation
resolved by ``src.core.tenant``. The route surface no longer accepts
``org_id`` from the client; passing one is a 400.
"""

from __future__ import annotations


import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.core.tenant import get_system_org_id
from src.models.auth import AuditAction
from src.models.cases import Case, CaseFinding
from src.models.intel import ActorSighting, ThreatActor
from src.models.takedown import TakedownTicket
from src.models.threat import (
    Alert,
    AlertStatus,
    Organization,
    RawIntel,
    ThreatCategory,
    ThreatSeverity,
)
from src.storage.database import get_session

router = APIRouter(prefix="/alerts", tags=["Threat Intelligence"])


class AlertResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    category: str
    severity: str
    status: str
    title: str
    summary: str
    confidence: float
    agent_reasoning: str | None
    recommended_actions: list | None
    matched_entities: dict | None
    analyst_notes: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: str | None = None
    analyst_notes: str | None = None
    # Analyst override of triage agent's classification. Both fields
    # are typed against the live enums so unknown values 422 before
    # they reach the row. Required: ``override_reason`` whenever
    # severity or category is set, so the audit trail captures *why*
    # the analyst disagreed with the agent.
    severity: ThreatSeverity | None = None
    category: ThreatCategory | None = None
    override_reason: str | None = None


class AlertStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_status: dict[str, int]


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    query = (
        select(Alert)
        .where(Alert.organization_id == org_id)
        .order_by(desc(Alert.created_at))
    )
    if severity:
        query = query.where(Alert.severity == severity)
    if category:
        query = query.where(Alert.category == category)
    if status:
        query = query.where(Alert.status == status)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=AlertStats)
async def alert_stats(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    base = select(Alert).where(Alert.organization_id == org_id)

    total = (await db.execute(
        select(func.count()).select_from(base.subquery())
    )).scalar() or 0

    sev_q = (
        select(Alert.severity, func.count())
        .where(Alert.organization_id == org_id)
        .group_by(Alert.severity)
    )
    by_severity = {row[0]: row[1] for row in (await db.execute(sev_q))}

    cat_q = (
        select(Alert.category, func.count())
        .where(Alert.organization_id == org_id)
        .group_by(Alert.category)
    )
    by_category = {row[0]: row[1] for row in (await db.execute(cat_q))}

    stat_q = (
        select(Alert.status, func.count())
        .where(Alert.organization_id == org_id)
        .group_by(Alert.status)
    )
    by_status = {row[0]: row[1] for row in (await db.execute(stat_q))}

    return AlertStats(
        total=total,
        by_severity=by_severity,
        by_category=by_category,
        by_status=by_status,
    )


@router.get("/search", response_model=list[AlertResponse])
async def search_alerts(
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(20, le=50),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """Full-text search across alert titles and summaries, scoped to the system organisation."""
    org_id = await get_system_org_id(db)
    pattern = f"%{q}%"
    query = (
        select(Alert)
        .where(
            Alert.organization_id == org_id,
            (Alert.title.ilike(pattern)) | (Alert.summary.ilike(pattern)),
        )
        .order_by(desc(Alert.created_at))
        .limit(limit)
    )
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: uuid.UUID,
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        # Don't leak existence of rows that belong to another (impossible
        # in single-tenant, but defensive against a future restore that
        # imports rows from another deployment).
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: uuid.UUID,
    body: AlertUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        raise HTTPException(404, "Alert not found")

    before: dict = {}
    after: dict = {}

    if body.status:
        try:
            AlertStatus(body.status)
        except ValueError:
            raise HTTPException(400, f"Invalid status: {body.status}")
        if alert.status != body.status:
            before["status"] = alert.status
            after["status"] = body.status
            alert.status = body.status

    if body.analyst_notes is not None and body.analyst_notes != (alert.analyst_notes or ""):
        before["analyst_notes"] = alert.analyst_notes
        after["analyst_notes"] = body.analyst_notes
        alert.analyst_notes = body.analyst_notes

    # Analyst override of severity / category. Pydantic already
    # validated the enum value; here we enforce that any actual change
    # carries a reason so the audit trail is meaningful. The agent's
    # original judgment + reasoning stays in ``agent_reasoning`` —
    # this only mutates the live triage labels.
    severity_changing = (
        body.severity is not None and body.severity.value != alert.severity
    )
    category_changing = (
        body.category is not None and body.category.value != alert.category
    )
    if severity_changing or category_changing:
        if not body.override_reason or not body.override_reason.strip():
            raise HTTPException(
                422,
                "override_reason is required when changing severity or category",
            )
        if severity_changing:
            before["severity"] = alert.severity
            after["severity"] = body.severity.value
            alert.severity = body.severity.value
        if category_changing:
            before["category"] = alert.category
            after["category"] = body.category.value
            alert.category = body.category.value
        # Capture the reason in the structured audit ``after`` blob
        # rather than mangling the analyst notes, so the audit log
        # is queryable as JSON without having to parse free text.
        after["override_reason"] = body.override_reason.strip()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ALERT_UPDATE,
        user=analyst,
        resource_type="alert",
        resource_id=str(alert_id),
        details={"before": before, "after": after} if (before or after) else {"no_change": True},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(alert)
    return alert


class AttributionFactorResponse(BaseModel):
    name: str
    weight: float
    raw: float
    contribution: float
    detail: str | None = None


class AttributionScoreResponse(BaseModel):
    actor_id: str
    primary_alias: str
    aliases: list[str]
    confidence: float
    factors: list[AttributionFactorResponse]


class AlertAttributionResponse(BaseModel):
    scores: list[AttributionScoreResponse]


@router.get("/{alert_id}/attribution", response_model=AlertAttributionResponse)
async def get_alert_attribution(
    alert_id: uuid.UUID,
    analyst: AnalystUser,
    limit: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_session),
):
    """Rank candidate threat actors for this alert with confidence
    breakdowns (P2 #2.9). Pure read-only — no DB writes."""
    from src.intel.attribution import score_alert

    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        raise HTTPException(404, "Alert not found")
    scores = await score_alert(db, alert_id=alert_id, limit=limit)
    return AlertAttributionResponse(scores=[s.to_dict() for s in scores])


class AlertSourceResponse(BaseModel):
    """Provenance for the alert — the raw intel item that produced it.

    Surfaces the most useful single link an analyst can have on the
    detail page: the original article / forum post / paste / report
    that the triage agent reasoned about. ``raw_intel_id`` may be null
    on legacy / synthetic alerts; in that case a 404 is returned.
    """
    raw_intel_id: uuid.UUID
    source_type: str
    source_name: str | None
    source_url: str | None
    title: str | None
    author: str | None
    published_at: datetime | None
    collected_at: datetime  # when the crawler ingested it (created_at on raw_intel)


@router.get("/{alert_id}/source", response_model=AlertSourceResponse)
async def get_alert_source(
    alert_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Return the raw_intel row that produced this alert (read-only).

    Used by the dashboard's alert detail page to render a "Source"
    section with a clickable link to the original article. Distinct
    endpoint (rather than embedded in AlertResponse) so the list-view
    payload stays lean.
    """
    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        raise HTTPException(404, "Alert not found")
    if not alert.raw_intel_id:
        raise HTTPException(404, "Alert has no source raw intel")
    raw = await db.get(RawIntel, alert.raw_intel_id)
    if raw is None:
        # Source intel was purged — surface honestly rather than 500.
        raise HTTPException(404, "Source raw intel not found")

    def _enum_value(v) -> str:
        return getattr(v, "value", None) or str(v)

    return AlertSourceResponse(
        raw_intel_id=raw.id,
        source_type=_enum_value(raw.source_type),
        source_name=raw.source_name,
        source_url=raw.source_url,
        title=raw.title,
        author=raw.author,
        published_at=raw.published_at,
        collected_at=raw.created_at,
    )


class AlertThresholdsResponse(BaseModel):
    """Triage confidence thresholds for the alert's org. Drives the
    dashboard's confidence-bar tier colours: alerts under
    ``needs_review_below`` would have been routed to NEEDS_REVIEW;
    alerts at or above ``high_above`` are eligible for the org's
    auto-takedown gates. Both come from the same org as the alert,
    so the bar mirrors the gates the operator already configured."""
    # The threshold below which the ingestion pipeline routes a fresh
    # alert to ``needs_review`` (org.settings.confidence_threshold).
    # 0.0 means the org has no threshold set — every alert lands as
    # ``new`` regardless of confidence.
    needs_review_below: float
    # The "high confidence" cutoff that auto-action gates respect.
    # Currently a system constant (0.85) — surfaced here so the
    # frontend doesn't have to hardcode a magic number.
    high_above: float


@router.get("/{alert_id}/thresholds", response_model=AlertThresholdsResponse)
async def get_alert_thresholds(
    alert_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Return the confidence thresholds the alert's org uses for
    triage routing + auto-action eligibility. Used by the dashboard
    to colour the confidence bar against the actual operator-tuned
    cutoffs instead of hardcoded magic numbers."""
    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        raise HTTPException(404, "Alert not found")
    org = await db.get(Organization, alert.organization_id)
    settings_blob = (org.settings if org and isinstance(org.settings, dict) else {}) or {}
    needs_review_below = float(settings_blob.get("confidence_threshold", 0.0) or 0.0)
    return AlertThresholdsResponse(
        needs_review_below=needs_review_below,
        high_above=0.85,
    )


class RelatedCase(BaseModel):
    id: uuid.UUID
    title: str
    state: str
    severity: str
    is_primary: bool
    linked_at: datetime


class RelatedTakedown(BaseModel):
    id: uuid.UUID
    state: str
    partner: str
    target_kind: str
    target_identifier: str
    submitted_at: datetime


class RelatedSighting(BaseModel):
    id: uuid.UUID
    threat_actor_id: uuid.UUID
    actor_alias: str
    source_platform: str
    alias_used: str
    seen_at: datetime  # ActorSighting.created_at


class AlertRelationsResponse(BaseModel):
    """Cross-table linkage for one alert. Drives the "Related" section
    on the detail page so analysts can see at a glance whether this
    alert is already in a case, has a takedown filed, or has actor
    sightings recorded — no need to navigate elsewhere and search."""
    cases: list[RelatedCase]
    takedowns: list[RelatedTakedown]
    sightings: list[RelatedSighting]


@router.get("/{alert_id}/relations", response_model=AlertRelationsResponse)
async def get_alert_relations(
    alert_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Return cases / takedowns / actor-sightings linked to this alert.

    Three independent queries kicked off in parallel — each is bounded
    by an indexed lookup so the cost is small even on a busy org.
    """
    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        raise HTTPException(404, "Alert not found")

    # Cases — join case_findings → cases, only the org's cases.
    case_q = (
        select(Case, CaseFinding.is_primary, CaseFinding.created_at)
        .join(CaseFinding, CaseFinding.case_id == Case.id)
        .where(
            CaseFinding.alert_id == alert_id,
            Case.organization_id == org_id,
        )
        .order_by(CaseFinding.created_at.desc())
    )
    case_rows = (await db.execute(case_q)).all()
    cases = [
        RelatedCase(
            id=c.id,
            title=c.title,
            state=str(c.state),
            severity=str(c.severity),
            is_primary=bool(is_primary),
            linked_at=linked_at,
        )
        for (c, is_primary, linked_at) in case_rows
    ]

    # Takedowns — source_finding_id matches alert_id (legacy contract;
    # newer findings use finding_type+finding_id but legacy alerts
    # still flow through source_finding_id == alert.id).
    td_q = (
        select(TakedownTicket)
        .where(
            TakedownTicket.source_finding_id == alert_id,
            TakedownTicket.organization_id == org_id,
        )
        .order_by(TakedownTicket.submitted_at.desc())
    )
    td_rows = list((await db.execute(td_q)).scalars().all())
    takedowns = [
        RelatedTakedown(
            id=t.id,
            state=str(t.state),
            partner=str(t.partner),
            target_kind=str(t.target_kind),
            target_identifier=t.target_identifier,
            submitted_at=t.submitted_at,
        )
        for t in td_rows
    ]

    # Actor sightings — join to threat_actors so the response carries
    # the alias the analyst recognises (the FK alone is meaningless
    # for human reading).
    sight_q = (
        select(ActorSighting, ThreatActor.primary_alias)
        .join(ThreatActor, ThreatActor.id == ActorSighting.threat_actor_id)
        .where(ActorSighting.alert_id == alert_id)
        .order_by(ActorSighting.created_at.desc())
    )
    sight_rows = (await db.execute(sight_q)).all()
    sightings = [
        RelatedSighting(
            id=s.id,
            threat_actor_id=s.threat_actor_id,
            actor_alias=alias,
            source_platform=s.source_platform,
            alias_used=s.alias_used,
            seen_at=s.created_at,
        )
        for (s, alias) in sight_rows
    ]

    return AlertRelationsResponse(
        cases=cases, takedowns=takedowns, sightings=sightings
    )


@router.get("/{alert_id}/navigator-layer")
async def get_alert_navigator_layer(
    alert_id: uuid.UUID,
    analyst: AnalystUser,
    matrix: str = Query(default="enterprise", pattern="^(enterprise|ics)$"),
    db: AsyncSession = Depends(get_session),
):
    """Download a MITRE ATT&CK Navigator v4.5 layer for this alert.

    Combines (a) every ``AttackTechniqueAttachment`` row on the alert
    with (b) the curated ``known_ttps`` of every threat actor sighted
    on the alert. The layer's per-square comments preserve provenance
    so the analyst sees which agent / actor / rule attached each
    technique.
    """
    from fastapi.responses import JSONResponse
    from src.intel.navigator_layer import build_alert_layer

    org_id = await get_system_org_id(db)
    alert = await db.get(Alert, alert_id)
    if not alert or alert.organization_id != org_id:
        raise HTTPException(404, "Alert not found")

    layer = await build_alert_layer(db, alert_id=alert_id, matrix=matrix)
    if layer is None:
        raise HTTPException(404, "Alert not found")

    filename = f"argus-alert-{alert_id}-{matrix}-layer.json"
    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
