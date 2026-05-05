"""External attack-surface API.

Surfaces the rich asset/finding/change data the EASM workers populate so
the dashboard can render a real attack-surface management view (ports,
HTTP, TLS, tech stack, screenshots, change timeline, risk score, AI
classification).

Endpoints
---------

    GET  /surface/assets                  list assets with full details
    GET  /surface/assets/{id}             single-asset detail
    GET  /surface/assets/{id}/exposures   exposures linked to this asset
    GET  /surface/changes                 change timeline (paginated)
    POST /surface/recompute-risk          recompute Asset.risk_score
    POST /surface/classify                run the AI classifier agent
    GET  /surface/stats                   per-org rollup
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.surface_classifier_agent import classify_org_assets
from src.core.auth import AnalystUser, audit_log
from src.easm.risk_scoring import compute_risk_for_org
from src.models.asset_schemas import AssetType
from src.models.auth import AuditAction
from src.models.easm import (
    AssetChange,
    ChangeKind,
    ChangeSeverity,
)
from src.models.exposures import ExposureFinding, ExposureState
from src.models.threat import Asset, Organization
from src.storage.database import get_session

router = APIRouter(prefix="/surface", tags=["External Surface"])


# --- Schemas -----------------------------------------------------------


class SurfaceAssetResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_type: str
    value: str
    criticality: str
    parent_asset_id: uuid.UUID | None
    discovery_method: str
    discovered_at: datetime | None
    last_scanned_at: datetime | None
    last_change_at: datetime | None
    is_active: bool
    monitoring_enabled: bool

    # Rolled-up enrichment from worker handlers.
    http_status_code: int | None = None
    http_title: str | None = None
    http_tech: list[str] = []
    ips: list[str] = []
    ports: list[dict[str, Any]] = []
    tls_grade: str | None = None
    tls_issue_counts: dict[str, int] | None = None
    has_screenshot: bool = False

    # Risk + AI signals.
    risk_score: float | None
    risk_score_updated_at: datetime | None
    ai_classification: dict[str, Any] | None
    ai_classified_at: datetime | None

    # Counts.
    open_exposures: int = 0
    kev_exposures: int = 0
    children_count: int = 0

    tags: list[str] = []

    model_config = {"from_attributes": True}


class SurfaceAssetDetailResponse(SurfaceAssetResponse):
    """Same fields as the list view + the full ``details`` JSONB blob."""

    details: dict[str, Any] | None = None
    parent_value: str | None = None


class SurfaceChangeResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    asset_value: str | None
    discovery_job_id: uuid.UUID | None
    kind: str
    severity: str
    summary: str
    before: dict | None
    after: dict | None
    detected_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class RecomputeRiskRequest(BaseModel):
    organization_id: uuid.UUID


class ClassifyRequest(BaseModel):
    organization_id: uuid.UUID
    use_llm: bool = True
    only_unclassified: bool = False
    asset_ids: list[uuid.UUID] | None = None


class ClassifyResponse(BaseModel):
    classified: int
    llm_used: int
    llm_failed: int
    total_assets: int


class SurfaceStats(BaseModel):
    organization_id: uuid.UUID
    total_assets: int
    by_type: dict[str, int]
    by_criticality: dict[str, int]
    accessible_count: int  # status 2xx
    auth_gated_count: int  # 401/403
    weak_tls_count: int
    open_exposures: int
    kev_exposures: int
    avg_risk_score: float | None
    top_risk_score: float | None


# --- Helpers ----------------------------------------------------------


def _serialize_asset_base(
    a: Asset,
    *,
    open_exp: int,
    kev_exp: int,
    children: int,
) -> dict[str, Any]:
    details = a.details or {}
    http = details.get("http") or {}
    ports = details.get("ports") or []
    tls = details.get("tls") or {}
    return {
        "id": a.id,
        "organization_id": a.organization_id,
        "asset_type": a.asset_type,
        "value": a.value,
        "criticality": a.criticality,
        "parent_asset_id": a.parent_asset_id,
        "discovery_method": a.discovery_method,
        "discovered_at": a.discovered_at,
        "last_scanned_at": a.last_scanned_at,
        "last_change_at": a.last_change_at,
        "is_active": a.is_active,
        "monitoring_enabled": a.monitoring_enabled,
        "http_status_code": http.get("status_code"),
        "http_title": http.get("title"),
        "http_tech": list(http.get("tech") or []),
        "ips": list(http.get("ips") or details.get("dns_detail", {}).get("a") or []),
        "ports": list(ports),
        "tls_grade": tls.get("grade"),
        "tls_issue_counts": tls.get("issue_counts") or None,
        "has_screenshot": bool((details.get("screenshot") or {}).get("data_url")),
        "risk_score": a.risk_score,
        "risk_score_updated_at": a.risk_score_updated_at,
        "ai_classification": a.ai_classification,
        "ai_classified_at": a.ai_classified_at,
        "open_exposures": open_exp,
        "kev_exposures": kev_exp,
        "children_count": children,
        "tags": list(a.tags or []),
    }


async def _exposure_counts_per_asset(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_ids: list[uuid.UUID],
) -> dict[uuid.UUID, tuple[int, int]]:
    """Returns ``{asset_id: (open_count, kev_count)}`` for each asset."""
    if not asset_ids:
        return {}
    rows = (
        await db.execute(
            select(
                ExposureFinding.asset_id,
                func.count(ExposureFinding.id),
                func.count(ExposureFinding.id).filter(ExposureFinding.is_kev),
            )
            .where(ExposureFinding.organization_id == org_id)
            .where(ExposureFinding.asset_id.in_(asset_ids))
            .where(ExposureFinding.state == ExposureState.OPEN.value)
            .group_by(ExposureFinding.asset_id)
        )
    ).all()
    return {r[0]: (r[1] or 0, r[2] or 0) for r in rows}


async def _children_counts(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_ids: list[uuid.UUID],
) -> dict[uuid.UUID, int]:
    if not asset_ids:
        return {}
    rows = (
        await db.execute(
            select(Asset.parent_asset_id, func.count(Asset.id))
            .where(Asset.organization_id == org_id)
            .where(Asset.parent_asset_id.in_(asset_ids))
            .group_by(Asset.parent_asset_id)
        )
    ).all()
    return {r[0]: r[1] for r in rows}


# --- Endpoints --------------------------------------------------------


@router.get("/assets", response_model=list[SurfaceAssetResponse])
async def list_surface_assets(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    asset_type: AssetType | None = None,
    parent_asset_id: uuid.UUID | None = None,
    has_open_exposures: bool | None = None,
    has_kev: bool | None = None,
    accessible_only: bool | None = None,
    weak_tls_only: bool | None = None,
    q: str | None = None,
    sort: Annotated[
        str,
        Query(pattern="^(risk|last_seen|discovered|value|criticality|exposures)$"),
    ] = "risk",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    qs = select(Asset).where(Asset.organization_id == organization_id)
    if asset_type is not None:
        qs = qs.where(Asset.asset_type == asset_type.value)
    if parent_asset_id is not None:
        qs = qs.where(Asset.parent_asset_id == parent_asset_id)
    if q:
        like = f"%{q}%"
        qs = qs.where(Asset.value.ilike(like))

    sort_columns = {
        "risk": Asset.risk_score.desc().nullslast(),
        "last_seen": Asset.last_scanned_at.desc().nullslast(),
        "discovered": Asset.discovered_at.desc().nullslast(),
        "value": Asset.value.asc(),
        "criticality": Asset.criticality.asc(),
        "exposures": Asset.risk_score.desc().nullslast(),  # falls back to risk
    }
    qs = qs.order_by(sort_columns[sort]).limit(limit).offset(offset)
    rows = list((await db.execute(qs)).scalars().all())

    asset_ids = [a.id for a in rows]
    expo_map = await _exposure_counts_per_asset(db, organization_id, asset_ids)
    children_map = await _children_counts(db, organization_id, asset_ids)

    out: list[dict[str, Any]] = []
    for a in rows:
        open_n, kev_n = expo_map.get(a.id, (0, 0))
        rec = _serialize_asset_base(
            a,
            open_exp=open_n,
            kev_exp=kev_n,
            children=children_map.get(a.id, 0),
        )
        if has_open_exposures is True and open_n == 0:
            continue
        if has_open_exposures is False and open_n > 0:
            continue
        if has_kev is True and kev_n == 0:
            continue
        if accessible_only:
            sc = rec.get("http_status_code")
            if not (isinstance(sc, int) and 200 <= sc < 300):
                continue
        if weak_tls_only and rec.get("tls_grade") not in ("F", "C"):
            continue
        out.append(rec)
    return out


@router.get("/assets/{asset_id}", response_model=SurfaceAssetDetailResponse)
async def get_surface_asset(
    asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    a = await db.get(Asset, asset_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    expo_map = await _exposure_counts_per_asset(db, a.organization_id, [a.id])
    children_map = await _children_counts(db, a.organization_id, [a.id])
    open_n, kev_n = expo_map.get(a.id, (0, 0))
    base = _serialize_asset_base(
        a,
        open_exp=open_n,
        kev_exp=kev_n,
        children=children_map.get(a.id, 0),
    )
    base["details"] = a.details
    parent_value = None
    if a.parent_asset_id:
        parent = await db.get(Asset, a.parent_asset_id)
        parent_value = parent.value if parent else None
    base["parent_value"] = parent_value
    return base


@router.get("/assets/{asset_id}/exposures", response_model=list[dict])
async def list_exposures_for_asset(
    asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    state: ExposureState | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    a = await db.get(Asset, asset_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    qs = select(ExposureFinding).where(
        and_(
            ExposureFinding.organization_id == a.organization_id,
            ExposureFinding.asset_id == asset_id,
        )
    )
    if state is not None:
        qs = qs.where(ExposureFinding.state == state.value)
    qs = qs.order_by(ExposureFinding.last_seen_at.desc()).limit(limit)
    rows = (await db.execute(qs)).scalars().all()
    out = []
    for f in rows:
        out.append({
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "state": f.state,
            "rule_id": f.rule_id,
            "category": f.category,
            "cve_ids": list(f.cve_ids or []),
            "is_kev": bool(f.is_kev),
            "epss_score": f.epss_score,
            "cvss_score": f.cvss_score,
            "ai_priority": f.ai_priority,
            "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
            "matched_at": f.matched_at.isoformat() if f.matched_at else None,
        })
    return out


@router.get("/changes", response_model=list[SurfaceChangeResponse])
async def list_surface_changes(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    asset_id: uuid.UUID | None = None,
    kind: ChangeKind | None = None,
    severity: ChangeSeverity | None = None,
    since_days: Annotated[int, Query(ge=1, le=365)] = 30,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Change timeline — every AssetChange row plus the human asset
    value joined in so the FE can show "TLS cert rotated on api.x.com"
    without a second roundtrip."""
    from datetime import timedelta, timezone as _tz

    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    cutoff = datetime.now(_tz.utc) - timedelta(days=since_days)
    qs = (
        select(AssetChange, Asset.value)
        .outerjoin(Asset, Asset.id == AssetChange.asset_id)
        .where(AssetChange.organization_id == organization_id)
        .where(AssetChange.detected_at >= cutoff)
    )
    if asset_id is not None:
        qs = qs.where(AssetChange.asset_id == asset_id)
    if kind is not None:
        qs = qs.where(AssetChange.kind == kind.value)
    if severity is not None:
        qs = qs.where(AssetChange.severity == severity.value)
    qs = qs.order_by(AssetChange.detected_at.desc()).limit(limit).offset(offset)
    rows = (await db.execute(qs)).all()
    out = []
    for change, value in rows:
        out.append({
            "id": change.id,
            "organization_id": change.organization_id,
            "asset_id": change.asset_id,
            "asset_value": value,
            "discovery_job_id": change.discovery_job_id,
            "kind": change.kind,
            "severity": change.severity,
            "summary": change.summary,
            "before": change.before,
            "after": change.after,
            "detected_at": change.detected_at,
            "created_at": change.created_at,
        })
    return out


@router.post("/recompute-risk", response_model=dict)
async def recompute_risk(
    body: RecomputeRiskRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    summary = await compute_risk_for_org(db, body.organization_id)
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "unknown")[:500]
    await audit_log(
        db,
        AuditAction.EASM_JOB_RUN,
        user=analyst,
        resource_type="surface",
        resource_id=str(body.organization_id),
        details={"operation": "recompute_risk", **summary},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return summary


@router.post("/classify", response_model=ClassifyResponse)
async def classify_assets(
    body: ClassifyRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    summary = await classify_org_assets(
        db,
        body.organization_id,
        use_llm=body.use_llm,
        only_unclassified=body.only_unclassified,
        asset_ids=body.asset_ids,
    )
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "unknown")[:500]
    await audit_log(
        db,
        AuditAction.EASM_JOB_RUN,
        user=analyst,
        resource_type="surface",
        resource_id=str(body.organization_id),
        details={"operation": "classify", **summary},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return ClassifyResponse(**summary)


@router.get("/stats", response_model=SurfaceStats)
async def surface_stats(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    rows = (
        await db.execute(
            select(Asset).where(Asset.organization_id == organization_id)
        )
    ).scalars().all()

    by_type: dict[str, int] = {}
    by_criticality: dict[str, int] = {}
    accessible = 0
    auth_gated = 0
    weak_tls = 0
    risk_scores: list[float] = []
    for a in rows:
        by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        by_criticality[a.criticality] = by_criticality.get(a.criticality, 0) + 1
        details = a.details or {}
        sc = (details.get("http") or {}).get("status_code")
        if isinstance(sc, int):
            if 200 <= sc < 300:
                accessible += 1
            elif sc in (401, 403):
                auth_gated += 1
        if (details.get("tls") or {}).get("grade") in ("F", "C"):
            weak_tls += 1
        if a.risk_score is not None:
            risk_scores.append(float(a.risk_score))

    expo_total, kev_total = (
        await db.execute(
            select(
                func.count(ExposureFinding.id),
                func.count(ExposureFinding.id).filter(ExposureFinding.is_kev),
            )
            .where(ExposureFinding.organization_id == organization_id)
            .where(ExposureFinding.state == ExposureState.OPEN.value)
        )
    ).one()

    avg_risk = (
        round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else None
    )
    top_risk = round(max(risk_scores), 2) if risk_scores else None

    return SurfaceStats(
        organization_id=organization_id,
        total_assets=len(rows),
        by_type=by_type,
        by_criticality=by_criticality,
        accessible_count=accessible,
        auth_gated_count=auth_gated,
        weak_tls_count=weak_tls,
        open_exposures=int(expo_total or 0),
        kev_exposures=int(kev_total or 0),
        avg_risk_score=avg_risk,
        top_risk_score=top_risk,
    )
