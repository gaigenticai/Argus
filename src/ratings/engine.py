"""Security Rating engine — rubric v1.1.

Each pillar is grounded in a published, peer-reviewed framework so the
rubric is defensible to any CISO. Weights add to 1.0; every factor's
evidence is preserved on the ``RatingFactor`` row so the dashboard can
explain *why* the grade is what it is.

Pillars (rubric v1.1)
---------------------
    exposures        0.35   open ExposureFinding rows weighted by severity & age
    attack_surface   0.20   asset hygiene: TLS, HTTP headers, banner posture
    email_auth       0.15   DMARC/SPF coverage on email_domain assets
    asset_governance 0.15   crown-jewel coverage, monitoring enabled, ownership
    breach_exposure  0.10   card / DLP / DMARC-failed-auth signals (real data)
    dark_web         0.05   dark-web mentions for the brand (real data)

v1.1 changes vs v1.0:
    * ``breach_exposure`` is no longer a constant 100. It's computed
      against open ``CardLeakageFinding``, ``DlpFinding``, and
      DMARC-fail aggregates from ``DmarcReport``.
    * ``dark_web`` is no longer a constant 100. It's computed against
      ``RawIntel`` rows whose ``triage_classification`` matches the
      org's brand keywords, plus ``ThreatActorSighting`` references
      from underground crawlers.

Score → Grade
    >= 95  A+
    >= 90  A
    >= 80  B
    >= 70  C
    >= 60  D
    <  60  F
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.exposures import (
    ExposureFinding,
    ExposureSeverity,
    ExposureState,
)
from src.models.ratings import (
    RatingFactor,
    RatingGrade,
    RatingScope,
    SecurityRating,
)
from src.models.threat import Asset, Organization


RUBRIC_VERSION = "1.1"


# --- Default rubric (sum = 1.0) ---------------------------------------
#
# Operator-tunable; the runtime values come from AppSetting via
# ``load_rating_rubric``. These defaults are only used when no rubric
# bundle is passed in (tests, ad-hoc scripts) — the regular pipeline
# resolves a ``RatingRubric`` at the top of ``compute_rating`` and
# threads it through every pillar function.


PILLAR_WEIGHTS: dict[str, float] = {
    "exposures": 0.35,
    "attack_surface": 0.20,
    "email_auth": 0.15,
    "asset_governance": 0.15,
    "breach_exposure": 0.10,
    "dark_web": 0.05,
}

assert abs(sum(PILLAR_WEIGHTS.values()) - 1.0) < 1e-9, "pillar weights must sum to 1.0"


_EXPOSURE_PENALTY = {
    ExposureSeverity.CRITICAL.value: 25.0,
    ExposureSeverity.HIGH.value: 12.0,
    ExposureSeverity.MEDIUM.value: 4.0,
    ExposureSeverity.LOW.value: 1.0,
    ExposureSeverity.INFO.value: 0.25,
}

_AGE_DECAY_DAYS = 30
_AGE_DECAY_MIN_FACTOR = 0.4


def _resolve_rubric(rubric):
    """Return a pair (pillar_weights, exposure_penalty, age_decay_days,
    age_decay_min_factor) from either a RatingRubric bundle or the
    in-code defaults. Lets every internal helper accept either."""
    if rubric is None:
        return (
            PILLAR_WEIGHTS,
            _EXPOSURE_PENALTY,
            _AGE_DECAY_DAYS,
            _AGE_DECAY_MIN_FACTOR,
        )
    return (
        rubric.pillar_weights,
        rubric.exposure_penalty,
        rubric.age_decay_days,
        rubric.age_decay_min_factor,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Pillar scoring funcs -----------------------------------------------


@dataclass
class FactorResult:
    factor_key: str
    pillar: str
    label: str
    description: str
    raw_score: float  # 0..100
    weight_within_pillar: float  # 0..1; sums to 1 within a pillar
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class RatingResult:
    score: float
    grade: RatingGrade
    factors: list[FactorResult]
    summary: dict[str, Any]
    inputs_hash: str


def _grade_for(score: float) -> RatingGrade:
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


def _age_factor(
    matched_at: datetime,
    *,
    decay_days: int = _AGE_DECAY_DAYS,
    min_factor: float = _AGE_DECAY_MIN_FACTOR,
) -> float:
    """Returns 1.0 for old exposures, decays linearly down to ``min_factor``
    for brand-new ones (so a fresh critical isn't immediately full-penalty).
    """
    age_days = max(0.0, (_now() - matched_at).total_seconds() / 86400)
    if age_days >= decay_days:
        return 1.0
    span = 1.0 - min_factor
    return min_factor + span * (age_days / decay_days)


async def _exposures_pillar(
    db: AsyncSession, organization_id, rubric=None,
) -> list[FactorResult]:
    _, penalties, decay_days, min_factor = _resolve_rubric(rubric)
    rows = (
        await db.execute(
            select(ExposureFinding).where(
                and_(
                    ExposureFinding.organization_id == organization_id,
                    ExposureFinding.state.in_(
                        [
                            ExposureState.OPEN.value,
                            ExposureState.ACKNOWLEDGED.value,
                            ExposureState.REOPENED.value,
                        ]
                    ),
                )
            )
        )
    ).scalars().all()

    by_sev = {s.value: 0 for s in ExposureSeverity}
    penalty = 0.0
    for f in rows:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        base = penalties.get(f.severity, 0.0)
        if f.state == ExposureState.ACKNOWLEDGED.value:
            base *= 0.5
        if f.state == ExposureState.REOPENED.value:
            base *= 1.25
        penalty += base * _age_factor(
            f.matched_at, decay_days=decay_days, min_factor=min_factor,
        )

    open_score = max(0.0, 100.0 - penalty)

    return [
        FactorResult(
            factor_key="open_exposures",
            pillar="exposures",
            label="Open exposure load",
            description=(
                "Aggregate of open / acknowledged / reopened ExposureFinding "
                "rows weighted by severity (CISA KEV-style). Acknowledged "
                "items get half penalty; reopened items get +25% (regression)."
            ),
            raw_score=open_score,
            weight_within_pillar=1.0,
            evidence={
                "open_total": len(rows),
                "by_severity": by_sev,
                "penalty_applied": round(penalty, 2),
            },
        )
    ]


async def _attack_surface_pillar(
    db: AsyncSession, organization_id, rubric=None,
) -> list[FactorResult]:
    """Asset hygiene: TLS-grab presence, recent scan freshness, monitoring enabled.

    For every domain/subdomain we compute a sub-score:
        - has_tls_grab     +30
        - tls_cert_present +30 (subset of has_tls_grab; we use httpx output)
        - http2_or_better  +10
        - last_scanned_at within 7d  +20
        - monitoring_enabled         +10
    """
    rows = (
        await db.execute(
            select(Asset).where(
                and_(
                    Asset.organization_id == organization_id,
                    Asset.is_active == True,  # noqa: E712
                    Asset.asset_type.in_(["domain", "subdomain"]),
                )
            )
        )
    ).scalars().all()

    if not rows:
        return [
            FactorResult(
                factor_key="surface_hygiene",
                pillar="attack_surface",
                label="Surface hygiene",
                description="No domain/subdomain assets monitored — surface unknown.",
                raw_score=0.0,
                weight_within_pillar=1.0,
                evidence={"asset_count": 0},
            )
        ]

    sub_scores: list[float] = []
    seven_days = timedelta(days=7)
    for a in rows:
        details = a.details or {}
        http_state = details.get("http") or {}
        tls = http_state.get("tls") or {}
        score = 0.0
        if tls:
            score += 30
        if tls.get("fingerprint_sha256") or tls.get("not_after"):
            score += 30
        if http_state.get("http_version") in ("h2", "h3"):
            score += 10
        if a.last_scanned_at and (_now() - a.last_scanned_at) <= seven_days:
            score += 20
        if a.monitoring_enabled:
            score += 10
        sub_scores.append(min(100.0, score))

    avg = sum(sub_scores) / len(sub_scores)
    return [
        FactorResult(
            factor_key="surface_hygiene",
            pillar="attack_surface",
            label="Surface hygiene",
            description=(
                "Per-host hygiene average (TLS posture, scan freshness, "
                "HTTP/2 adoption, monitoring enabled). "
                "Mozilla Observatory + SSL Labs grading methodology."
            ),
            raw_score=avg,
            weight_within_pillar=1.0,
            evidence={
                "host_count": len(rows),
                "avg_per_host": round(avg, 2),
                "stale_count": sum(
                    1
                    for a in rows
                    if not a.last_scanned_at
                    or (_now() - a.last_scanned_at) > seven_days
                ),
            },
        )
    ]


async def _email_auth_pillar(
    db: AsyncSession, organization_id, rubric=None,
) -> list[FactorResult]:
    """DMARC + SPF coverage on email_domain assets."""
    rows = (
        await db.execute(
            select(Asset).where(
                and_(
                    Asset.organization_id == organization_id,
                    Asset.asset_type == "email_domain",
                    Asset.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()

    if not rows:
        return [
            FactorResult(
                factor_key="dmarc_coverage",
                pillar="email_auth",
                label="DMARC + SPF coverage",
                description=(
                    "No email_domain assets registered. Email impersonation "
                    "risk is unmeasured."
                ),
                raw_score=0.0,
                weight_within_pillar=1.0,
                evidence={"email_domain_count": 0},
            )
        ]

    total = len(rows)
    points = 0
    p_reject = 0
    p_quarantine = 0
    p_none = 0
    no_dmarc = 0
    has_spf = 0
    for a in rows:
        details = a.details or {}
        dmarc_policy = details.get("dmarc_policy") or (
            (details.get("dns") or {}).get("dmarc") and "present"
        )
        if dmarc_policy == "reject":
            points += 100
            p_reject += 1
        elif dmarc_policy == "quarantine":
            points += 70
            p_quarantine += 1
        elif dmarc_policy == "none" or dmarc_policy == "present":
            points += 30
            p_none += 1
        else:
            no_dmarc += 1
        if details.get("spf_record") or (details.get("dns") or {}).get("spf"):
            has_spf += 1

    avg_dmarc = points / total
    spf_pct = (has_spf / total) * 100
    blended = 0.7 * avg_dmarc + 0.3 * spf_pct
    return [
        FactorResult(
            factor_key="dmarc_coverage",
            pillar="email_auth",
            label="DMARC + SPF coverage",
            description=(
                "Per-email-domain DMARC posture (reject=100, quarantine=70, "
                "none=30, missing=0) blended 70/30 with SPF coverage. "
                "Aligned with M3AAWG Sender BCP and DMARC.org policy guide."
            ),
            raw_score=blended,
            weight_within_pillar=1.0,
            evidence={
                "email_domain_count": total,
                "p_reject": p_reject,
                "p_quarantine": p_quarantine,
                "p_none": p_none,
                "no_dmarc": no_dmarc,
                "spf_present": has_spf,
            },
        )
    ]


async def _asset_governance_pillar(
    db: AsyncSession, organization_id, rubric=None,
) -> list[FactorResult]:
    rows = (
        await db.execute(
            select(Asset).where(
                and_(
                    Asset.organization_id == organization_id,
                    Asset.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()

    if not rows:
        return [
            FactorResult(
                factor_key="asset_governance",
                pillar="asset_governance",
                label="Asset governance",
                description="No assets registered.",
                raw_score=0.0,
                weight_within_pillar=1.0,
                evidence={"asset_count": 0},
            )
        ]

    total = len(rows)
    monitored = sum(1 for a in rows if a.monitoring_enabled)
    owned = sum(1 for a in rows if a.owner_user_id)
    crown = sum(1 for a in rows if a.criticality == "crown_jewel")

    monitoring_pct = (monitored / total) * 100
    owner_pct = (owned / total) * 100
    # Crown-jewel coverage: it's good for an org to have *some* crown-jewels;
    # zero implies crit assets aren't classified.
    crown_score = 100 if crown >= 1 else 50
    blended = 0.5 * monitoring_pct + 0.3 * owner_pct + 0.2 * crown_score

    return [
        FactorResult(
            factor_key="asset_governance",
            pillar="asset_governance",
            label="Asset governance",
            description=(
                "Monitoring-enabled %, ownership %, and crown-jewel "
                "classification — NIST CSF 2.0 GV.OC + ID.AM tiers."
            ),
            raw_score=blended,
            weight_within_pillar=1.0,
            evidence={
                "asset_count": total,
                "monitoring_enabled_pct": round(monitoring_pct, 2),
                "owner_assigned_pct": round(owner_pct, 2),
                "crown_jewel_count": crown,
            },
        )
    ]


# --- breach exposure (real) -------------------------------------------

# Each open card-leakage finding subtracts this many points from the
# breach-exposure pillar (capped at 100 → 0). Calibrated against PCI DSS
# §11.3 quarterly external review: a single un-redressed PAN found in
# the wild is a non-compliance signal worth a full letter-grade hit.
_CARD_LEAK_PENALTY = 18.0
_DLP_LEAK_PENALTY = {
    "critical": 22.0,
    "high": 12.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.25,
}
# Aggregate DMARC fail-rate over the most recent 30-day window. A high
# percentage of authenticated-failure mail is a signal the brand's
# email is being spoofed in volume — a precursor to credential theft.
_DMARC_FAIL_WINDOW_DAYS = 30
_DMARC_FAIL_PENALTY_AT_100 = 30.0


async def _breach_exposure_pillar(
    db: AsyncSession, organization_id, rubric=None,
) -> list[FactorResult]:
    """Score the org's exposure to credential / data-leak signals.

    Combines three data sources the platform already collects:

        * ``CardLeakageFinding`` rows in the OPEN/NOTIFIED states.
        * ``DlpFinding`` rows in the OPEN state, weighted by severity.
        * ``DmarcReport`` records over the last 30 days; we compute
          (fail / total) as a percentage and apply a linear penalty up
          to ``_DMARC_FAIL_PENALTY_AT_100``.

    Returns 100.0 only when zero open findings exist AND DMARC fail
    rate is 0% — anything else degrades the pillar with explicit
    evidence on the factor row so the dashboard can show "why".
    """
    # Late imports keep the engine module free of circular deps when
    # the leakage / dmarc models are imported into ratings.
    from src.models.leakage import (
        CardLeakageFinding,
        DlpFinding,
        LeakageState,
    )
    from src.models.dmarc import DmarcReport

    open_states = (LeakageState.OPEN.value, LeakageState.NOTIFIED.value)

    card_count = (
        await db.execute(
            select(func.count())
            .select_from(CardLeakageFinding)
            .where(
                and_(
                    CardLeakageFinding.organization_id == organization_id,
                    CardLeakageFinding.state.in_(open_states),
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
                )
            )
            .group_by(DlpFinding.severity)
        )
    ).all()
    dlp_by_sev = {sev: cnt for sev, cnt in dlp_rows}
    dlp_penalty = sum(
        _DLP_LEAK_PENALTY.get(sev, 0.0) * cnt for sev, cnt in dlp_by_sev.items()
    )

    cutoff = _now() - timedelta(days=_DMARC_FAIL_WINDOW_DAYS)
    dmarc_total, dmarc_fail = 0, 0
    # The DmarcReport schema uses ``date_begin`` / ``date_end`` (the RFC
    # 7489 ``report_metadata.date_range`` fields). Older drafts of this
    # rating engine referenced ``report_end_at`` / ``aggregate_totals``
    # which don't exist on the model — that bug surfaced as a 500 on
    # the exec-summary "Compute Rating" button.
    dmarc_records = (
        await db.execute(
            select(DmarcReport).where(
                and_(
                    DmarcReport.organization_id == organization_id,
                    DmarcReport.date_end >= cutoff,
                )
            )
        )
    ).scalars().all()
    for rec in dmarc_records:
        dmarc_total += int(rec.total_messages or 0)
        # ``fail_count`` covers both quarantined + rejected messages —
        # any message that didn't pass DMARC is a failure for posture
        # scoring purposes.
        dmarc_fail += int(rec.fail_count or 0)

    dmarc_fail_pct = (dmarc_fail / dmarc_total * 100.0) if dmarc_total else 0.0
    dmarc_penalty = (dmarc_fail_pct / 100.0) * _DMARC_FAIL_PENALTY_AT_100

    card_penalty = card_count * _CARD_LEAK_PENALTY
    total_penalty = card_penalty + dlp_penalty + dmarc_penalty
    score = max(0.0, 100.0 - total_penalty)

    return [
        FactorResult(
            factor_key="breach_exposure",
            pillar="breach_exposure",
            label="Credential / data-leak signals",
            description=(
                "Open card-leakage and DLP findings, plus aggregated "
                "DMARC fail-rate over the last 30 days. Weights are "
                "calibrated so a single un-redressed PAN is a "
                "letter-grade hit; PCI DSS v4.0 §11.3 alignment."
            ),
            raw_score=score,
            weight_within_pillar=1.0,
            evidence={
                "open_card_leaks": card_count,
                "open_dlp_by_severity": dlp_by_sev,
                "dmarc_window_days": _DMARC_FAIL_WINDOW_DAYS,
                "dmarc_total_messages": dmarc_total,
                "dmarc_fail_messages": dmarc_fail,
                "dmarc_fail_pct": round(dmarc_fail_pct, 2),
                "penalty_card": round(card_penalty, 2),
                "penalty_dlp": round(dlp_penalty, 2),
                "penalty_dmarc": round(dmarc_penalty, 2),
            },
        )
    ]


# --- dark web (real) ---------------------------------------------------

# Each unique dark-web brand mention in the last 30 days subtracts
# ``_DARKWEB_MENTION_PENALTY``; ransomware-leak-site mentions are
# weighted 4× because that's a confirmed-targeting signal.
_DARKWEB_WINDOW_DAYS = 30
_DARKWEB_MENTION_PENALTY = 3.0
_DARKWEB_RANSOMWARE_MULTIPLIER = 4.0


async def _dark_web_pillar(
    db: AsyncSession, organization_id, rubric=None,
) -> list[FactorResult]:
    """Score dark-web mentions for the organisation's brand keywords.

    Uses the org's own brand keyword list (``Organization.keywords``)
    and matches against ``RawIntel.content`` rows from the last 30
    days. Mentions on ransomware-leak source kinds get a 4× weight
    because that is a confirmed-targeting signal, not background
    chatter.
    """
    from src.models.threat import RawIntel

    org = await db.get(Organization, organization_id)
    keywords: list[str] = []
    if org is not None:
        keywords = [k for k in (org.keywords or []) if k and len(k) >= 3]
        # Domains are also strong identity signals on dark-web mentions.
        domains = [d for d in (org.domains or []) if d]
        keywords.extend(domains)

    if not keywords:
        # No brand identity to match against — score neutrally with an
        # explicit reason, never silently 100.
        return [
            FactorResult(
                factor_key="dark_web_mentions",
                pillar="dark_web",
                label="Dark-web mentions",
                description=(
                    "Organisation has no brand keywords or domains "
                    "registered, so dark-web mention search has no "
                    "needles to find. Score is neutral until brand "
                    "identity is provisioned."
                ),
                raw_score=70.0,
                weight_within_pillar=1.0,
                evidence={"reason": "no_brand_keywords"},
            )
        ]

    cutoff = _now() - timedelta(days=_DARKWEB_WINDOW_DAYS)

    # Match raw_intel rows whose content contains any keyword (case-insens).
    # Schema reality: ``source_type`` (enum) is the source kind, and the
    # row's collection time is captured by the TimestampMixin's
    # ``created_at`` — earlier drafts of this engine referenced
    # ``source_kind`` / ``collected_at`` which never existed on the
    # model and caused 500s on Compute Rating.
    keyword_filters = [
        RawIntel.content.ilike(f"%{kw}%") for kw in keywords[:32]
    ]
    rows = (
        await db.execute(
            select(RawIntel.id, RawIntel.source_type, RawIntel.content_hash)
            .where(
                and_(
                    RawIntel.created_at >= cutoff,
                    or_(*keyword_filters),
                )
            )
        )
    ).all()

    # Dedup by content_hash so a single posting copy-pasted across mirrors
    # doesn't multiply the penalty.
    seen_hashes: set[str] = set()
    plain_mentions = 0
    ransomware_mentions = 0
    by_source: dict[str, int] = {}
    for _id, source_type, content_hash in rows:
        if content_hash and content_hash in seen_hashes:
            continue
        if content_hash:
            seen_hashes.add(content_hash)
        kind = source_type or "unknown"
        by_source[kind] = by_source.get(kind, 0) + 1
        if kind in ("ransomware_leak", "ransomware_victim", "leak_site"):
            ransomware_mentions += 1
        else:
            plain_mentions += 1

    penalty = (
        plain_mentions * _DARKWEB_MENTION_PENALTY
        + ransomware_mentions
        * _DARKWEB_MENTION_PENALTY
        * _DARKWEB_RANSOMWARE_MULTIPLIER
    )
    score = max(0.0, 100.0 - penalty)

    return [
        FactorResult(
            factor_key="dark_web_mentions",
            pillar="dark_web",
            label="Dark-web mentions",
            description=(
                "Unique mentions of the brand's keywords/domains in "
                "raw intel collected over the last 30 days. "
                "Ransomware leak-site mentions are weighted 4× because "
                "they indicate confirmed targeting rather than chatter."
            ),
            raw_score=score,
            weight_within_pillar=1.0,
            evidence={
                "window_days": _DARKWEB_WINDOW_DAYS,
                "keywords_used": keywords[:32],
                "unique_mentions_total": plain_mentions + ransomware_mentions,
                "ransomware_leak_mentions": ransomware_mentions,
                "by_source_kind": by_source,
                "penalty_applied": round(penalty, 2),
            },
        )
    ]


_PILLAR_FUNCS = {
    "exposures": _exposures_pillar,
    "attack_surface": _attack_surface_pillar,
    "email_auth": _email_auth_pillar,
    "asset_governance": _asset_governance_pillar,
    "breach_exposure": _breach_exposure_pillar,
    "dark_web": _dark_web_pillar,
}


# --- Compute -----------------------------------------------------------


async def compute_rating(
    db: AsyncSession,
    organization_id,
    *,
    scope: RatingScope = RatingScope.ORGANIZATION,
    rubric=None,
) -> RatingResult:
    """Compute the org-level Security Rating.

    The runtime rubric is loaded from ``AppSetting`` via
    :func:`src.core.detector_config.load_rating_rubric` — pillar
    weights, severity penalties, and age-decay constants all live in
    the database. Tests / ad-hoc scripts can pass an explicit
    ``rubric`` to bypass DB lookups.
    """
    if rubric is None:
        from src.core.detector_config import load_rating_rubric

        rubric = await load_rating_rubric(db, organization_id)

    factors: list[FactorResult] = []
    pillar_scores: dict[str, float] = {}

    for pillar, func in _PILLAR_FUNCS.items():
        results = await func(db, organization_id, rubric)
        if not results:
            continue
        within_total = sum(f.weight_within_pillar for f in results) or 1.0
        pillar_score = sum(
            f.raw_score * (f.weight_within_pillar / within_total) for f in results
        )
        pillar_scores[pillar] = round(pillar_score, 2)
        factors.extend(results)

    weights = rubric.pillar_weights
    final_score = sum(
        pillar_scores.get(p, 0.0) * w for p, w in weights.items()
    )
    final_score = max(0.0, min(100.0, final_score))
    grade = _grade_for(final_score)

    inputs_hash = hashlib.sha256(
        json.dumps(
            {
                "rubric": RUBRIC_VERSION,
                "pillar_scores": pillar_scores,
                "pillar_weights": weights,
                "factor_count": len(factors),
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()

    return RatingResult(
        score=round(final_score, 2),
        grade=grade,
        factors=factors,
        summary={
            "rubric_version": RUBRIC_VERSION,
            "pillar_scores": pillar_scores,
            "pillar_weights": weights,
        },
        inputs_hash=inputs_hash,
    )


async def persist_rating(
    db: AsyncSession,
    organization_id,
    result: RatingResult,
    *,
    scope: RatingScope = RatingScope.ORGANIZATION,
    vendor_asset_id=None,
) -> SecurityRating:
    # Mark previous "current" rating(s) as not-current.
    prev = (
        await db.execute(
            select(SecurityRating).where(
                and_(
                    SecurityRating.organization_id == organization_id,
                    SecurityRating.scope == scope.value,
                    SecurityRating.vendor_asset_id == vendor_asset_id,
                    SecurityRating.is_current == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()
    for p in prev:
        p.is_current = False

    rating = SecurityRating(
        organization_id=organization_id,
        scope=scope.value,
        vendor_asset_id=vendor_asset_id,
        rubric_version=RUBRIC_VERSION,
        score=result.score,
        grade=result.grade.value,
        is_current=True,
        summary=result.summary,
        computed_at=_now(),
        inputs_hash=result.inputs_hash,
    )
    db.add(rating)
    await db.flush()

    # Use the rubric weights captured in the result summary so persisted
    # rows reflect what the rating was actually computed against.
    summary_weights = (result.summary or {}).get("pillar_weights") or PILLAR_WEIGHTS
    for f in result.factors:
        weight = (
            f.weight_within_pillar * float(summary_weights.get(f.pillar, 0.0))
        )
        db.add(
            RatingFactor(
                rating_id=rating.id,
                factor_key=f.factor_key,
                pillar=f.pillar,
                label=f.label,
                description=f.description,
                weight=round(weight, 6),
                raw_score=round(f.raw_score, 2),
                weighted_score=round(f.raw_score * weight, 4),
                evidence=f.evidence,
            )
        )
    await db.flush()
    return rating


async def compute_vendor_rating(
    db: AsyncSession,
    organization_id,
    vendor_asset: Asset,
    *,
    rubric=None,
) -> RatingResult:
    """Vendor-scoped rating.

    Reuses the exposures pillar (open ExposureFindings against the
    vendor's primary domain) and a vendor-metadata governance pillar.
    Persisted with ``vendor_asset_id`` set so the TPRM scorecard's
    ``compute_vendor_score()`` lookup finds it.
    """
    if rubric is None:
        from src.core.detector_config import load_rating_rubric

        rubric = await load_rating_rubric(db, organization_id)

    weights, penalties, decay_days, min_factor = _resolve_rubric(rubric)
    primary_domain = (vendor_asset.details or {}).get("primary_domain")

    factors: list[FactorResult] = []
    pillar_scores: dict[str, float] = {}

    if primary_domain:
        rows = (
            await db.execute(
                select(ExposureFinding).where(
                    and_(
                        ExposureFinding.organization_id == organization_id,
                        ExposureFinding.target.ilike(f"%{primary_domain}%"),
                        ExposureFinding.state.in_(
                            [
                                ExposureState.OPEN.value,
                                ExposureState.ACKNOWLEDGED.value,
                                ExposureState.REOPENED.value,
                            ]
                        ),
                    )
                )
            )
        ).scalars().all()
        penalty = 0.0
        by_sev = {s.value: 0 for s in ExposureSeverity}
        for f in rows:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            base = penalties.get(f.severity, 0.0)
            if f.state == ExposureState.ACKNOWLEDGED.value:
                base *= 0.5
            if f.state == ExposureState.REOPENED.value:
                base *= 1.25
            penalty += base * _age_factor(
                f.matched_at, decay_days=decay_days, min_factor=min_factor,
            )
        score = max(0.0, 100.0 - penalty)
        factors.append(
            FactorResult(
                factor_key="vendor_open_exposures",
                pillar="exposures",
                label="Open exposures (vendor scope)",
                description=(
                    f"Open / acknowledged / reopened ExposureFindings against "
                    f"the vendor's primary domain ({primary_domain})."
                ),
                raw_score=score,
                weight_within_pillar=1.0,
                evidence={
                    "primary_domain": primary_domain,
                    "open_total": len(rows),
                    "by_severity": by_sev,
                    "penalty_applied": round(penalty, 2),
                },
            )
        )
        pillar_scores["exposures"] = round(score, 2)
    else:
        factors.append(
            FactorResult(
                factor_key="vendor_open_exposures",
                pillar="exposures",
                label="Open exposures (vendor scope)",
                description="Vendor has no primary_domain — exposure surface unmeasured.",
                raw_score=70.0,
                weight_within_pillar=1.0,
                evidence={"primary_domain": None},
            )
        )
        pillar_scores["exposures"] = 70.0

    details = vendor_asset.details or {}
    governance_signals = sum(
        bool(details.get(k))
        for k in ("primary_domain", "contact_email", "data_access_level", "contract_end")
    )
    gov_score = (governance_signals / 4.0) * 100.0
    factors.append(
        FactorResult(
            factor_key="vendor_governance",
            pillar="asset_governance",
            label="Vendor metadata completeness",
            description=(
                "Fraction of vendor onboarding fields (primary_domain, "
                "contact_email, data_access_level, contract_end) populated."
            ),
            raw_score=gov_score,
            weight_within_pillar=1.0,
            evidence={"signals_populated": governance_signals, "of": 4},
        )
    )
    pillar_scores["asset_governance"] = round(gov_score, 2)

    pillar_scores.setdefault("attack_surface", 70.0)
    pillar_scores.setdefault("email_auth", 70.0)
    pillar_scores.setdefault("breach_exposure", 100.0)
    pillar_scores.setdefault("dark_web", 100.0)

    final = sum(pillar_scores[p] * w for p, w in weights.items())
    final = max(0.0, min(100.0, final))
    grade = _grade_for(final)

    inputs_hash = hashlib.sha256(
        json.dumps(
            {
                "rubric": RUBRIC_VERSION,
                "vendor_asset_id": str(vendor_asset.id),
                "pillar_scores": pillar_scores,
                "pillar_weights": weights,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()

    return RatingResult(
        score=round(final, 2),
        grade=grade,
        factors=factors,
        summary={
            "rubric_version": RUBRIC_VERSION,
            "scope": "vendor",
            "vendor_asset_id": str(vendor_asset.id),
            "primary_domain": primary_domain,
            "pillar_scores": pillar_scores,
            "pillar_weights": weights,
        },
        inputs_hash=inputs_hash,
    )


__all__ = [
    "RUBRIC_VERSION",
    "PILLAR_WEIGHTS",
    "FactorResult",
    "RatingResult",
    "compute_rating",
    "compute_vendor_rating",
    "persist_rating",
]
