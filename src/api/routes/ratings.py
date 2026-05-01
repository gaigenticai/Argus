"""Security Rating API.

Endpoints
---------
    POST /ratings/recompute?organization_id=…   compute + persist + return current
    GET  /ratings/current?organization_id=…     latest "is_current" rating
    GET  /ratings/history?organization_id=…     list past ratings
    GET  /ratings/{id}                          one rating + its factor breakdown
    GET  /ratings/rubric                        the active rubric (weights + version)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.ratings import (
    RatingFactor,
    RatingGrade,
    RatingScope,
    SecurityRating,
)
from src.models.threat import Organization
from src.ratings.engine import (
    PILLAR_WEIGHTS,
    RUBRIC_VERSION,
    compute_rating,
    persist_rating,
)
from src.storage.database import get_session

router = APIRouter(prefix="/ratings", tags=["External Surface"])


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


class RatingFactorResponse(BaseModel):
    factor_key: str
    pillar: str
    label: str
    description: str | None
    weight: float
    raw_score: float
    weighted_score: float
    evidence: dict | None

    model_config = {"from_attributes": True}


class RatingResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scope: str
    rubric_version: str
    score: float
    grade: str
    is_current: bool
    summary: dict
    computed_at: datetime
    inputs_hash: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RatingDetailResponse(RatingResponse):
    factors: list[RatingFactorResponse]


class RubricResponse(BaseModel):
    version: str
    pillar_weights: dict[str, float]
    grade_thresholds: dict[str, float]
    pillar_descriptions: dict[str, str]


# --- Endpoints ----------------------------------------------------------


@router.get("/rubric", response_model=RubricResponse)
async def get_rubric(analyst: AnalystUser):
    return RubricResponse(
        version=RUBRIC_VERSION,
        pillar_weights=PILLAR_WEIGHTS,
        grade_thresholds={
            "A+": 95,
            "A": 90,
            "B": 80,
            "C": 70,
            "D": 60,
            "F": 0,
        },
        pillar_descriptions={
            "exposures": (
                "Open ExposureFinding load weighted by severity, age, and "
                "state (acknowledged half, reopened +25%). CISA KEV-style."
            ),
            "attack_surface": (
                "Per-host hygiene: TLS posture, scan freshness, HTTP/2, "
                "monitoring on. Mozilla Observatory + SSL Labs."
            ),
            "email_auth": (
                "DMARC + SPF coverage on email_domain assets. M3AAWG / "
                "DMARC.org guidance."
            ),
            "asset_governance": (
                "Monitoring %, ownership %, crown-jewel classification. "
                "NIST CSF 2.0 GV.OC + ID.AM."
            ),
            "breach_exposure": (
                "Reserved for Phase 5 (Data Leakage). Currently 100."
            ),
            "dark_web": (
                "Reserved for Phase 3 (Brand Protection). Currently 100."
            ),
        },
    )


@router.post("/recompute", response_model=RatingDetailResponse)
async def recompute_rating(
    organization_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    result = await compute_rating(db, organization_id)
    rating = await persist_rating(db, organization_id, result)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.RATING_RECOMPUTE,
        user=analyst,
        resource_type="security_rating",
        resource_id=str(rating.id),
        details={
            "organization_id": str(organization_id),
            "score": rating.score,
            "grade": rating.grade,
            "rubric_version": rating.rubric_version,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(rating)
    return _detail_response(rating)


@router.get("/current", response_model=RatingDetailResponse)
async def get_current_rating(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    res = (
        await db.execute(
            select(SecurityRating).where(
                and_(
                    SecurityRating.organization_id == organization_id,
                    SecurityRating.is_current == True,  # noqa: E712
                )
            )
        )
    ).scalar_one_or_none()
    if res is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No current rating yet — run /ratings/recompute first.",
        )
    return _detail_response(res)


@router.get("/history", response_model=list[RatingResponse])
async def get_history(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    rows = (
        await db.execute(
            select(SecurityRating)
            .where(SecurityRating.organization_id == organization_id)
            .order_by(SecurityRating.computed_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


@router.get("/{rating_id}", response_model=RatingDetailResponse)
async def get_rating(
    rating_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rating = await db.get(SecurityRating, rating_id)
    if not rating:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rating not found")
    return _detail_response(rating)


def _detail_response(r: SecurityRating) -> RatingDetailResponse:
    return RatingDetailResponse(
        id=r.id,
        organization_id=r.organization_id,
        scope=r.scope,
        rubric_version=r.rubric_version,
        score=r.score,
        grade=r.grade,
        is_current=r.is_current,
        summary=r.summary,
        computed_at=r.computed_at,
        inputs_hash=r.inputs_hash,
        created_at=r.created_at,
        updated_at=r.updated_at,
        factors=[RatingFactorResponse.model_validate(f) for f in r.factors],
    )
