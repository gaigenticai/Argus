"""Vendor scorecard engine.

Aggregates four pillars per vendor (asset of type ``vendor``):

    questionnaire   weighted average of latest reviewed answers
    security        latest SecurityRating attached to the vendor's
                    primary_domain (Phase 1.3)
    breach          per-vendor breach signal: open card-leakage and
                    DLP findings whose source is tied to the vendor's
                    primary domain over the configured window
    operational     based on contract metadata + data_access_level

Pillar weights and breach-pillar tunables come from ``AppSetting`` via
:func:`src.core.detector_config.load_tprm_rubric` so a customer can edit
them from the dashboard. Defaults sum to 1.0 and match the previous
in-code values (questionnaire 0.40, security 0.35, operational 0.15,
breach 0.10).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.ratings import RatingGrade, RatingScope, SecurityRating
from src.models.threat import Asset
from src.models.tprm import (
    QuestionnaireInstance,
    QuestionnaireState,
    VendorScorecard,
)
from src.ratings.engine import compute_vendor_rating, persist_rating


# Defaults — overridden at runtime by load_tprm_rubric. Kept here so
# tests / scripts that don't hit the DB get the same numbers.
PILLAR_WEIGHTS = {
    "questionnaire": 0.40,
    "security": 0.35,
    "operational": 0.15,
    "breach": 0.10,
}


def _grade(score: float) -> RatingGrade:
    if score >= 95:
        return RatingGrade.A_PLUS
    if score >= 90:
        return RatingGrade.A
    if score >= 80:
        return RatingGrade.B
    if score >= 70:
        return RatingGrade.C
    if score >= 60:
        return RatingGrade.D
    return RatingGrade.F


@dataclass
class VendorScoreResult:
    score: float
    grade: RatingGrade
    pillar_scores: dict[str, float]
    summary: dict[str, Any] = field(default_factory=dict)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _vendor_breach_pillar_internal(
    db: AsyncSession,
    organization_id: uuid.UUID,
    vendor_asset: Asset,
    rubric,
) -> tuple[float, dict[str, Any]]:
    """Compute the vendor breach-pillar score and evidence dict.

    The pillar starts at 100 and subtracts:

        * ``rubric.breach_card_penalty`` for every open
          ``CardLeakageFinding`` whose ``source_url`` references the
          vendor's primary domain (or whose linked vendor metadata
          says so)
        * ``rubric.breach_dlp_penalty[severity]`` for every open
          ``DlpFinding`` whose ``source_url`` references the vendor's
          primary domain

    Both queries use a window of ``rubric.breach_window_days`` so a
    vendor whose breach exposure was remediated months ago doesn't
    drag the score down forever.

    Vendors with no ``primary_domain`` get a 70-point neutral score
    (we surface the reason in the evidence dict, never silently 100).
    """
    primary_domain = (vendor_asset.details or {}).get("primary_domain")
    if not primary_domain:
        return 70.0, {
            "reason": "vendor has no primary_domain registered",
            "window_days": rubric.breach_window_days,
        }

    cutoff = _now() - timedelta(days=rubric.breach_window_days)
    pattern = f"%{primary_domain.strip().lower()}%"

    # Late imports — avoid cycle when leakage models import the rubric.
    from src.models.leakage import (
        CardLeakageFinding,
        DlpFinding,
        LeakageState,
    )

    open_states = (LeakageState.OPEN.value, LeakageState.NOTIFIED.value)

    card_count = (
        await db.execute(
            select(func.count())
            .select_from(CardLeakageFinding)
            .where(
                and_(
                    CardLeakageFinding.organization_id == organization_id,
                    CardLeakageFinding.state.in_(open_states),
                    CardLeakageFinding.detected_at >= cutoff,
                    or_(
                        CardLeakageFinding.source_url.ilike(pattern),
                        CardLeakageFinding.source_kind.ilike(pattern),
                    ),
                )
            )
        )
    ).scalar_one()

    dlp_rows = (
        await db.execute(
            select(DlpFinding.severity, func.count())
            .where(
                and_(
                    DlpFinding.organization_id == organization_id,
                    DlpFinding.state == LeakageState.OPEN.value,
                    DlpFinding.detected_at >= cutoff,
                    or_(
                        DlpFinding.source_url.ilike(pattern),
                        DlpFinding.source_kind.ilike(pattern),
                    ),
                )
            )
            .group_by(DlpFinding.severity)
        )
    ).all()
    dlp_by_sev = {sev: cnt for sev, cnt in dlp_rows}
    dlp_penalty = sum(
        rubric.breach_dlp_penalty.get(sev, 0.0) * cnt
        for sev, cnt in dlp_by_sev.items()
    )
    card_penalty = card_count * rubric.breach_card_penalty
    score = max(0.0, 100.0 - card_penalty - dlp_penalty)

    return score, {
        "primary_domain": primary_domain,
        "window_days": rubric.breach_window_days,
        "open_card_leaks": int(card_count),
        "open_dlp_by_severity": dlp_by_sev,
        "penalty_card": round(card_penalty, 2),
        "penalty_dlp": round(dlp_penalty, 2),
    }


async def _vendor_breach_pillar(
    db: AsyncSession,
    organization_id: uuid.UUID,
    vendor_asset: Asset,
    rubric,
) -> tuple[float, dict[str, Any]]:
    """Composite breach pillar = internal-leak signals (existing) blended
    with HIBP + sanctions. Sanctions hit caps the entire pillar at 25.

    Weights inside the pillar:
        internal leaks  : 0.45
        HIBP            : 0.35
        sanctions       : 0.20
    """
    internal_score, internal_evidence = await _vendor_breach_pillar_internal(
        db, organization_id, vendor_asset, rubric,
    )

    primary_domain = (vendor_asset.details or {}).get("primary_domain") or ""
    vendor_name = vendor_asset.value or ""

    # HIBP + sanctions are best-effort; failures fall back to neutral.
    try:
        from src.tprm.breach_hibp import assess_vendor_breach
        hibp_score, hibp_evidence = await assess_vendor_breach(primary_domain)
    except Exception as e:  # noqa: BLE001
        hibp_score, hibp_evidence = 70.0, {"error": str(e)[:200]}

    try:
        from src.tprm.sanctions import screen_vendor
        hits = await screen_vendor(vendor_name)
        matched = [h.source for h in hits if h.matched]
        sanctions_score = 0.0 if matched else 100.0
        sanctions_evidence = {
            "matched_sources": matched,
            "results": [
                {
                    "source": h.source,
                    "matched": h.matched,
                    "score": h.score,
                    "matched_term": h.payload.get("matched_term"),
                }
                for h in hits
            ],
        }
    except Exception as e:  # noqa: BLE001
        sanctions_score, sanctions_evidence = 100.0, {"error": str(e)[:200]}

    composite = (
        internal_score * 0.45 + hibp_score * 0.35 + sanctions_score * 0.20
    )
    if sanctions_evidence.get("matched_sources"):
        # Hard cap when on a sanctions list — no breach pillar score
        # above 25 should be possible.
        composite = min(composite, 25.0)
    composite = max(0.0, min(100.0, composite))

    return composite, {
        "internal_leaks": internal_evidence | {"score": internal_score},
        "hibp": hibp_evidence | {"score": hibp_score},
        "sanctions": sanctions_evidence | {"score": sanctions_score},
        "composite": round(composite, 2),
        "weights": {"internal": 0.45, "hibp": 0.35, "sanctions": 0.20},
    }


async def compute_vendor_score(
    db: AsyncSession,
    organization_id: uuid.UUID,
    vendor_asset_id: uuid.UUID,
) -> VendorScoreResult:
    vendor = await db.get(Asset, vendor_asset_id)
    if vendor is None or vendor.organization_id != organization_id:
        raise LookupError("vendor asset not found in this organization")
    if vendor.asset_type != "vendor":
        raise ValueError("asset is not of type 'vendor'")

    from src.core.detector_config import load_tprm_rubric

    rubric = await load_tprm_rubric(db, organization_id)
    weights = rubric.pillar_weights

    # 1) Questionnaire pillar — latest reviewed instance.
    last_q = (
        await db.execute(
            select(QuestionnaireInstance)
            .where(
                and_(
                    QuestionnaireInstance.organization_id == organization_id,
                    QuestionnaireInstance.vendor_asset_id == vendor_asset_id,
                    QuestionnaireInstance.state == QuestionnaireState.REVIEWED.value,
                )
            )
            .order_by(QuestionnaireInstance.reviewed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    q_score = float(last_q.score) if last_q and last_q.score is not None else 0.0

    # 2) Security pillar — vendor-scoped SecurityRating.
    vendor_rating_result = await compute_vendor_rating(
        db, organization_id, vendor
    )
    sec_row = await persist_rating(
        db,
        organization_id,
        vendor_rating_result,
        scope=RatingScope.VENDOR,
        vendor_asset_id=vendor.id,
    )
    sec_score = float(sec_row.score)

    # 3) Operational pillar — data_access_level + contract presence + email security.
    details = vendor.details or {}
    access = (details.get("data_access_level") or "metadata").lower()
    access_score = {
        "none": 95,
        "metadata": 85,
        "pii": 65,
        "financial": 55,
        "crown_jewel": 45,
    }.get(access, 70)
    has_contract = bool(details.get("contract_start") and details.get("contract_end"))
    relationship = (details.get("relationship_type") or "").lower()
    relationship_bonus = (
        10 if relationship in ("auditor", "consultant", "saas") else 0
    )
    op_base = min(
        100, access_score + relationship_bonus + (5 if has_contract else 0)
    )
    # Email security blends in at 30% — DMARC/SPF/DKIM is operational
    # hygiene the procurement team should see.
    primary_domain_for_email = (details.get("primary_domain") or "").strip().lower()
    email_security_evidence: dict[str, Any] = {}
    if primary_domain_for_email:
        try:
            from src.tprm.email_security import assess_email_security
            email_score, email_security_evidence = await assess_email_security(
                primary_domain_for_email
            )
        except Exception as e:  # noqa: BLE001
            email_score = 70.0
            email_security_evidence = {"error": str(e)[:200]}
    else:
        email_score = 70.0
        email_security_evidence = {"reason": "no primary_domain"}
    op_score = min(100.0, max(0.0, op_base * 0.7 + email_score * 0.3))

    # 4) Breach pillar — real computation against vendor-attributed findings.
    breach_score, breach_evidence = await _vendor_breach_pillar(
        db, organization_id, vendor, rubric,
    )

    pillar = {
        "questionnaire": round(q_score, 2),
        "security": round(sec_score, 2),
        "operational": round(op_score, 2),
        "breach": round(breach_score, 2),
    }
    final = sum(pillar[p] * w for p, w in weights.items())
    final = round(max(0.0, min(100.0, final)), 2)
    return VendorScoreResult(
        score=final,
        grade=_grade(final),
        pillar_scores=pillar,
        summary={
            "weights": weights,
            "questionnaire_instance_id": str(last_q.id) if last_q else None,
            "security_rating_id": str(sec_row.id) if sec_row else None,
            "data_access_level": access,
            "has_contract": has_contract,
            "breach_evidence": breach_evidence,
            "email_security_evidence": email_security_evidence,
            "operational_base": op_base,
            "operational_email_security_score": email_score,
        },
    )


async def persist_vendor_scorecard(
    db: AsyncSession,
    organization_id: uuid.UUID,
    vendor_asset_id: uuid.UUID,
    result: VendorScoreResult,
) -> VendorScorecard:
    # Mark previous current scorecards as not-current.
    prev = (
        await db.execute(
            select(VendorScorecard).where(
                and_(
                    VendorScorecard.organization_id == organization_id,
                    VendorScorecard.vendor_asset_id == vendor_asset_id,
                    VendorScorecard.is_current == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()
    for p in prev:
        p.is_current = False

    card = VendorScorecard(
        organization_id=organization_id,
        vendor_asset_id=vendor_asset_id,
        score=result.score,
        grade=result.grade.value,
        is_current=True,
        pillar_scores=dict(result.pillar_scores),
        summary=result.summary,
        computed_at=_now(),
    )
    db.add(card)
    await db.flush()
    # Trend snapshot — append-only, used by the FE sparkline.
    try:
        from src.tprm.snapshots import record_snapshot
        await record_snapshot(
            db,
            organization_id=organization_id,
            vendor_asset_id=vendor_asset_id,
            score=result.score,
            grade=result.grade.value,
            pillar_scores=dict(result.pillar_scores),
        )
    except Exception:  # noqa: BLE001
        # Snapshot failures must not block the primary scorecard write.
        pass
    return card


__all__ = [
    "PILLAR_WEIGHTS",
    "VendorScoreResult",
    "compute_vendor_score",
    "persist_vendor_scorecard",
]
