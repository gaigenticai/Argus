"""Executive Summary — CIO-grade briefing endpoints.

Five endpoints, all keyed to ``organization_id``, designed to make
``/exec-summary`` read like a board briefing instead of a metrics grid:

    POST /api/v1/exec/briefing            LLM-generated headline + narrative + 3 actions
    GET  /api/v1/exec/top-risks           ranked risks by computed business-impact score
    GET  /api/v1/exec/changes             7-day delta on every CIO-visible metric
    GET  /api/v1/exec/compliance          DMARC pass-rate, NEEDS_REVIEW backlog, MFA, asset coverage
    GET  /api/v1/exec/suggested-actions   actionable nudges derived from intel_setup gaps

The briefing is the agentic centrepiece — it pulls every other
endpoint's output, frames it for a CIO audience, and writes a coherent
narrative. The other four are deterministic aggregations that the
briefing prompt-builder also consumes.

Caching: the briefing is expensive (LLM round-trip) so we memoise it
in ``app_settings`` with a 1h TTL keyed on ``(org_id, data_hash)``.
The other endpoints are cheap aggregations and don't cache.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routes.organizations import _client_meta
from src.config.settings import settings
from src.core.auth import AnalystUser, audit_log
from src.llm.providers import LLMNotConfigured, LLMTransportError, get_provider
from src.models.auth import AuditAction
from src.models.cases import Case, CaseSeverity, CaseState  # noqa: F401
from src.models.threat import Asset, Organization
from src.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/exec", tags=["External Surface"])

BRIEFING_CACHE_KEY_PREFIX = "exec_briefing_v2"
BRIEFING_CACHE_TTL_SECONDS = 3600  # 1h
# v1 (free-form ``link`` field) cached payloads stay in app_settings
# but are unreachable under the v2 prefix — they age out naturally
# without a migration script. New operators never see the legacy
# schema; existing operators get a one-time miss + regenerate on
# their next briefing fetch.

_SEVERITY_WEIGHT = {
    "critical": 100,
    "high": 60,
    "medium": 30,
    "low": 10,
    "info": 2,
}

_GRADE_RANK = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


# ----------------------------------------------------------------------
# Response models
# ----------------------------------------------------------------------

class BriefingActionItem(BaseModel):
    """One recommended action in the AI briefing.

    The LLM picks ``playbook_id`` from the catalog handed to it in the
    user prompt — it does not invent action types. ``rationale`` is the
    only free-form field. ``params`` lets the LLM seed any obvious
    operator-input on a ``requires_input`` playbook (e.g. an initial
    VIP roster pulled from public sources); the operator can edit
    before clicking Execute.

    The legacy ``link`` field is gone — the dashboard opens an
    in-context drawer keyed on ``playbook_id`` instead of routing the
    operator to a generic page.
    """

    playbook_id: str
    title: str
    rationale: str
    params: dict[str, Any] = Field(default_factory=dict)


class BriefingResponse(BaseModel):
    headline: str
    narrative: str
    posture_change: str  # "improving" | "stable" | "deteriorating"
    top_actions: list[BriefingActionItem]
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    generated_at: datetime
    cached: bool = False
    rubric_grade: str | None = None
    rubric_score: float | None = None


class TopRiskItem(BaseModel):
    kind: str  # "case" | "exposure" | "suspect_domain" | "kev_match"
    id: str
    title: str
    severity: str | None
    score: float
    age_days: int
    evidence: str
    link: str


class TopRisksResponse(BaseModel):
    items: list[TopRiskItem]
    generated_at: datetime


class DeltaMetric(BaseModel):
    label: str
    current: float
    previous: float
    delta: float
    direction: str  # "up" | "down" | "flat"
    interpretation: str  # "good" | "bad" | "neutral"
    note: str | None = None


class ChangesResponse(BaseModel):
    window_days: int
    metrics: list[DeltaMetric]
    generated_at: datetime


class ComplianceMetric(BaseModel):
    key: str
    label: str
    value: float | int | str
    target: float | int | str | None = None
    status: str  # "ok" | "warn" | "fail" | "unknown"
    note: str | None = None


class ComplianceResponse(BaseModel):
    metrics: list[ComplianceMetric]
    generated_at: datetime


class SuggestedAction(BaseModel):
    priority: str  # "high" | "medium" | "low"
    title: str
    detail: str
    # Either link (deep-link to a settings/admin page) or playbook_id
    # (opens the in-page ActionDrawer keyed on a registered playbook).
    # When both are present the dashboard prefers playbook_id — drawer
    # is always the better UX than dumping the operator on a generic
    # page.
    link: str | None = None
    playbook_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class SuggestedActionsResponse(BaseModel):
    actions: list[SuggestedAction]
    generated_at: datetime


# ----------------------------------------------------------------------
# Helpers — data aggregation (shared by endpoints)
# ----------------------------------------------------------------------

@dataclass
class ExecSnapshot:
    """Compact projection of every signal the CIO page needs.

    Built once per request so endpoints don't repeat the same SQL. The
    briefing builder consumes this dict directly when constructing the
    LLM prompt.
    """
    org: Organization
    cases_open_total: int
    cases_by_severity: dict[str, int]
    cases_overdue: int
    rating_grade: str | None
    rating_score: float | None
    rating_age_days: int | None
    suspect_count: int
    kev_match_count: int
    impersonation_count: int
    fraud_count: int
    rogue_app_count: int
    needs_review_count: int
    last_typosquat_scan_age_days: int | None
    dmarc_pass_rate: float | None
    vip_count: int

    def hash(self) -> str:
        """Stable hash used as the briefing cache key. If any of these
        numbers change, the cached briefing is invalidated."""
        h = hashlib.sha256()
        for field in (
            self.cases_open_total, self.cases_by_severity, self.cases_overdue,
            self.rating_grade, round(self.rating_score, 1) if self.rating_score is not None else None,
            self.suspect_count, self.kev_match_count, self.impersonation_count,
            self.fraud_count, self.rogue_app_count, self.needs_review_count,
            self.last_typosquat_scan_age_days, self.dmarc_pass_rate, self.vip_count,
        ):
            h.update(json.dumps(field, sort_keys=True, default=str).encode())
        return h.hexdigest()[:16]


async def _build_snapshot(
    db: AsyncSession, organization_id: uuid.UUID
) -> ExecSnapshot:
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    # --- Cases ---
    cases = (
        await db.execute(
            select(Case).where(Case.organization_id == organization_id)
        )
    ).scalars().all()
    cases_by_severity: dict[str, int] = {}
    cases_open_total = 0
    cases_overdue = 0
    now = datetime.now(timezone.utc)
    for c in cases:
        if c.state in (CaseState.CLOSED.value, CaseState.VERIFIED.value):
            continue
        cases_open_total += 1
        sev = (c.severity or "info").lower()
        cases_by_severity[sev] = cases_by_severity.get(sev, 0) + 1
        if c.sla_due_at and c.sla_due_at < now:
            cases_overdue += 1

    # --- Rating ---
    rating_grade, rating_score, rating_age_days = await _latest_rating(
        db, organization_id
    )

    # --- Brand suspects ---
    suspect_count = await _count_suspects(db, organization_id)

    # --- Other CIO-visible counts ---
    kev_match_count = await _count_kev_matches(db, organization_id)
    impersonation_count = await _count_impersonations(db, organization_id)
    fraud_count = await _count_fraud(db, organization_id)
    rogue_app_count = await _count_rogue_apps(db, organization_id)
    needs_review_count = await _count_needs_review(db, organization_id)
    typosquat_age = await _typosquat_scan_age_days(db, organization_id)
    dmarc_pass_rate = await _dmarc_pass_rate(db, organization_id, days=30)
    vip_count = await _count_vips(db, organization_id)

    return ExecSnapshot(
        org=org,
        cases_open_total=cases_open_total,
        cases_by_severity=cases_by_severity,
        cases_overdue=cases_overdue,
        rating_grade=rating_grade,
        rating_score=rating_score,
        rating_age_days=rating_age_days,
        suspect_count=suspect_count,
        kev_match_count=kev_match_count,
        impersonation_count=impersonation_count,
        fraud_count=fraud_count,
        rogue_app_count=rogue_app_count,
        needs_review_count=needs_review_count,
        last_typosquat_scan_age_days=typosquat_age,
        dmarc_pass_rate=dmarc_pass_rate,
        vip_count=vip_count,
    )


async def _latest_rating(
    db: AsyncSession, organization_id: uuid.UUID
) -> tuple[str | None, float | None, int | None]:
    from src.models.ratings import SecurityRating
    row = (
        await db.execute(
            select(SecurityRating).where(
                and_(
                    SecurityRating.organization_id == organization_id,
                    SecurityRating.is_current == True,  # noqa: E712
                )
            ).limit(1)
        )
    ).scalar_one_or_none()
    if not row:
        return None, None, None
    age_days = (
        datetime.now(timezone.utc) - row.computed_at
    ).days if row.computed_at else None
    return row.grade, float(row.score or 0.0), age_days


async def _count_suspects(
    db: AsyncSession, organization_id: uuid.UUID
) -> int:
    try:
        from src.models.brand import SuspectDomain
    except ImportError:
        return 0
    # "Open + investigation" = anything not yet dismissed/cleared. Aligns
    # with the exec-summary KPI tile semantic ("brand suspects: open +
    # investigation").
    count = await db.execute(
        select(func.count()).select_from(SuspectDomain).where(
            SuspectDomain.organization_id == organization_id,
            SuspectDomain.state.notin_(("dismissed", "cleared")),
        )
    )
    return int(count.scalar_one() or 0)


async def _count_kev_matches(
    db: AsyncSession, organization_id: uuid.UUID
) -> int:
    """KEV CVEs that match the org's tech_stack — a critical CIO signal.

    KEV records carry CPE strings (``cpe:2.3:a:vendor:product:*:*:...``)
    plus title / description text. Rather than parse CPEs into structured
    vendor/product tuples we match by text containment on the title +
    description + first 3 CPE segments. Lossy but adequate for the
    CIO-posture signal (if the title or CPE mentions Ivanti EPMM, that
    KEV affects the org). The triage agent already does the deep work
    on actual case creation.
    """
    try:
        from src.models.intel_polish import CveRecord
    except ImportError:
        return 0
    org = await db.get(Organization, organization_id)
    if not org or not (org.tech_stack or {}):
        return 0
    stack_terms: list[str] = []
    for items in (org.tech_stack or {}).values():
        if isinstance(items, list):
            stack_terms.extend(str(i) for i in items)
    if not stack_terms:
        return 0
    rows = (
        await db.execute(
            select(
                CveRecord.cve_id, CveRecord.title, CveRecord.description, CveRecord.cpes,
            ).where(CveRecord.is_kev == True)  # noqa: E712
        )
    ).all()
    matched = 0
    stack_lower = [s.lower() for s in stack_terms if s]
    for _id, title, description, cpes in rows:
        haystack_parts: list[str] = [(title or "").lower(), (description or "").lower()]
        for cpe in (cpes or [])[:6]:
            haystack_parts.append((cpe or "").lower())
        haystack = " ".join(haystack_parts)
        if any(term in haystack for term in stack_lower):
            matched += 1
    return matched


async def _count_impersonations(
    db: AsyncSession, organization_id: uuid.UUID
) -> int:
    try:
        from src.models.social import ImpersonationFinding
    except ImportError:
        return 0
    count = await db.execute(
        select(func.count()).select_from(ImpersonationFinding).where(
            ImpersonationFinding.organization_id == organization_id,
            ImpersonationFinding.state.notin_(("dismissed", "cleared")),
        )
    )
    return int(count.scalar_one() or 0)


async def _count_fraud(
    db: AsyncSession, organization_id: uuid.UUID
) -> int:
    try:
        from src.models.fraud import FraudFinding
    except ImportError:
        return 0
    # FraudState enum doesn't have "cleared" — only "dismissed" is the
    # negative terminal state. Anything else (open / reported_to_regulator /
    # takedown_requested / confirmed) counts as actively-tracked fraud.
    count = await db.execute(
        select(func.count()).select_from(FraudFinding).where(
            FraudFinding.organization_id == organization_id,
            FraudFinding.state != "dismissed",
        )
    )
    return int(count.scalar_one() or 0)


async def _count_rogue_apps(
    db: AsyncSession, organization_id: uuid.UUID
) -> int:
    try:
        from src.models.social import MobileAppFinding
    except ImportError:
        return 0
    count = await db.execute(
        select(func.count()).select_from(MobileAppFinding).where(
            MobileAppFinding.organization_id == organization_id,
            MobileAppFinding.state.notin_(("dismissed", "cleared")),
        )
    )
    return int(count.scalar_one() or 0)


async def _count_needs_review(
    db: AsyncSession, organization_id: uuid.UUID
) -> int:
    """NEEDS_REVIEW alerts — the human-gate backlog from triage."""
    from src.models.threat import Alert
    count = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.organization_id == organization_id,
            Alert.status == "needs_review",
        )
    )
    return int(count.scalar_one() or 0)


async def _typosquat_scan_age_days(
    db: AsyncSession, organization_id: uuid.UUID
) -> int | None:
    """Days since the most recent suspect_domain row was created.

    A long gap means typosquat scans aren't running — a real CIO concern.
    """
    try:
        from src.models.brand import SuspectDomain
    except ImportError:
        return None
    latest = (
        await db.execute(
            select(func.max(SuspectDomain.created_at)).where(
                SuspectDomain.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if not latest:
        return None
    return (datetime.now(timezone.utc) - latest).days


async def _dmarc_pass_rate(
    db: AsyncSession, organization_id: uuid.UUID, days: int
) -> float | None:
    """Aggregate DMARC pass / total over the recent window. None if no data."""
    try:
        from src.models.dmarc import DmarcReport
    except ImportError:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        await db.execute(
            select(
                func.coalesce(func.sum(DmarcReport.pass_count), 0),
                func.coalesce(func.sum(DmarcReport.total_messages), 0),
            ).where(
                and_(
                    DmarcReport.organization_id == organization_id,
                    DmarcReport.date_end >= cutoff,
                )
            )
        )
    ).one()
    pass_count, total = int(rows[0] or 0), int(rows[1] or 0)
    if total == 0:
        return None
    return pass_count / total


async def _count_vips(
    db: AsyncSession, organization_id: uuid.UUID
) -> int:
    from src.models.threat import VIPTarget
    count = await db.execute(
        select(func.count()).select_from(VIPTarget).where(
            VIPTarget.organization_id == organization_id,
        )
    )
    return int(count.scalar_one() or 0)


# ----------------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------------

@router.post("/briefing", response_model=BriefingResponse)
async def exec_briefing(
    request: Request,
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    force_refresh: bool = Query(False, description="Skip cache, regenerate fresh"),
    db: AsyncSession = Depends(get_session),
):
    """LLM-generated CIO briefing — narrative + top 3 actions.

    Cached 1h keyed on (org_id, snapshot hash). When the underlying
    data changes (new case, rating recompute, etc.) the hash flips and
    the next call regenerates without operator intervention.
    """
    snap = await _build_snapshot(db, organization_id)
    cache_key = f"{BRIEFING_CACHE_KEY_PREFIX}.{organization_id}.{snap.hash()}"

    if not force_refresh:
        cached = await _read_briefing_cache(db, cache_key)
        if cached:
            # The cached payload was serialized with ``cached=False``;
            # strip that key before re-hydrating so we can flip it to
            # True without a duplicate-kwarg TypeError.
            cached.pop("cached", None)
            return BriefingResponse(**cached, cached=True)

    # Fresh generation.
    try:
        provider = get_provider(settings.llm)
    except LLMNotConfigured as exc:
        raise HTTPException(
            503,
            "LLM provider not configured — set ARGUS_LLM_API_KEY or enable "
            "the Claude Code Bridge in Settings → Services. "
            f"({exc})",
        )

    system_prompt, user_prompt = _build_briefing_prompt(snap)
    try:
        raw = await provider.call(system_prompt, user_prompt)
    except LLMTransportError as exc:
        raise HTTPException(
            502,
            f"LLM provider failed to respond: {exc}. Retry in a few seconds, "
            "or check Settings → Services → LLM provider for diagnostics.",
        )

    parsed = _parse_briefing_json(raw)
    if not parsed:
        raise HTTPException(
            502,
            "LLM returned an unparseable briefing payload. The provider may "
            "be returning markdown instead of JSON — check the configured "
            "model supports system+user prompt JSON-only mode.",
        )

    # Defensive top_actions assembly. The LLM is *instructed* to return
    # playbook_ids from the catalog, but a confused model can still
    # invent one or revert to the legacy free-form schema. Drop any
    # action that doesn't reference a registered playbook so the rest
    # of the briefing renders cleanly instead of 500-ing.
    from src.core.exec_playbooks import all_playbooks

    valid_playbook_ids = {pb.id for pb in all_playbooks()}
    raw_actions = parsed.get("top_actions", []) or []
    safe_actions: list[BriefingActionItem] = []
    for a in raw_actions[:5]:
        if not isinstance(a, dict):
            continue
        playbook_id = (a.get("playbook_id") or "").strip()
        if playbook_id not in valid_playbook_ids:
            logger.info(
                "briefing: dropping action with unknown playbook_id=%r",
                playbook_id or a,
            )
            continue
        safe_actions.append(
            BriefingActionItem(
                playbook_id=playbook_id,
                title=str(a.get("title", "") or "")[:200],
                rationale=str(a.get("rationale", "") or "")[:1000],
                params=a.get("params") or {},
            )
        )

    response = BriefingResponse(
        headline=parsed.get("headline", "")[:200],
        narrative=parsed.get("narrative", "")[:4000],
        posture_change=parsed.get("posture_change", "stable"),
        top_actions=safe_actions,
        confidence=float(parsed.get("confidence", 0.6)),
        generated_at=datetime.now(timezone.utc),
        rubric_grade=snap.rating_grade,
        rubric_score=snap.rating_score,
    )

    await _write_briefing_cache(
        db, cache_key, response.model_dump(mode="json"), organization_id
    )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.REPORT_GENERATE,
        user=analyst,
        resource_type="exec_briefing",
        resource_id=str(organization_id),
        details={"snapshot_hash": snap.hash(), "headline": response.headline},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return response


@router.get("/top-risks", response_model=TopRisksResponse)
async def exec_top_risks(
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_session),
):
    """Ranked top-N risks for the org by computed business-impact score.

    Score = severity_weight × age_factor × confirmation_factor.
    """
    items: list[TopRiskItem] = []

    # Open cases — confirmed, in-progress threats. Highest base weight.
    cases = (
        await db.execute(
            select(Case).where(
                and_(
                    Case.organization_id == organization_id,
                    Case.state.notin_(
                        (CaseState.CLOSED.value, CaseState.VERIFIED.value)
                    ),
                )
            )
        )
    ).scalars().all()
    now = datetime.now(timezone.utc)
    for c in cases:
        sev = (c.severity or "info").lower()
        sev_w = _SEVERITY_WEIGHT.get(sev, 1)
        age_days = (now - c.created_at).days if c.created_at else 0
        # Confirmed cases have full weight; aging amplifies (older =
        # more urgent the longer it sits unresolved).
        score = sev_w * (1 + min(age_days, 30) / 10) * 1.0
        items.append(
            TopRiskItem(
                kind="case",
                id=str(c.id),
                title=c.title or f"Case #{str(c.id)[:8]}",
                severity=sev,
                score=round(score, 1),
                age_days=age_days,
                evidence=(c.summary or "")[:200],
                link=f"/cases/{c.id}",
            )
        )

    # Suspect domains in open / investigation states.
    try:
        from src.models.brand import SuspectDomain
        suspects = (
            await db.execute(
                select(SuspectDomain).where(
                    and_(
                        SuspectDomain.organization_id == organization_id,
                        SuspectDomain.state.notin_(("dismissed", "cleared")),
                    )
                ).limit(50)
            )
        ).scalars().all()
        for s in suspects:
            # Suspect domains weight lower than cases because they're
            # candidates, not confirmed compromise. Multiplier scales
            # by similarity-to-brand (high similarity = high impact).
            similarity = float(s.similarity or 0.5)
            sev_w = 30  # treat suspects as "high" by default
            age_days = (now - s.created_at).days if s.created_at else 0
            score = sev_w * (1 + min(age_days, 30) / 30) * (0.5 + similarity / 2)
            items.append(
                TopRiskItem(
                    kind="suspect_domain",
                    id=str(s.id),
                    title=f"Lookalike: {s.domain}",
                    severity="high" if similarity >= 0.85 else "medium",
                    score=round(score, 1),
                    age_days=age_days,
                    evidence=(s.permutation_kind or "domain match"),
                    link="/brand#suspects",
                )
            )
    except ImportError:
        pass

    # Sort + cap.
    items.sort(key=lambda x: x.score, reverse=True)
    return TopRisksResponse(
        items=items[:limit],
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/changes", response_model=ChangesResponse)
async def exec_changes(
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    window_days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_session),
):
    """7-day delta on every CIO-visible metric."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

    metrics: list[DeltaMetric] = []

    # New cases in window vs cases that existed before.
    new_cases = (
        await db.execute(
            select(func.count()).select_from(Case).where(
                and_(
                    Case.organization_id == organization_id,
                    Case.created_at >= cutoff,
                )
            )
        )
    ).scalar_one()
    new_critical = (
        await db.execute(
            select(func.count()).select_from(Case).where(
                and_(
                    Case.organization_id == organization_id,
                    Case.created_at >= cutoff,
                    Case.severity == CaseSeverity.CRITICAL.value,
                )
            )
        )
    ).scalar_one()
    closed_in_window = (
        await db.execute(
            select(func.count()).select_from(Case).where(
                and_(
                    Case.organization_id == organization_id,
                    Case.closed_at.isnot(None),
                    Case.closed_at >= cutoff,
                )
            )
        )
    ).scalar_one()

    metrics.append(
        DeltaMetric(
            label="New cases",
            current=int(new_cases),
            previous=0.0,
            delta=int(new_cases),
            direction="up" if new_cases > 0 else "flat",
            interpretation="bad" if new_cases > closed_in_window else "neutral",
            note=f"{closed_in_window} closed in the same window",
        )
    )
    metrics.append(
        DeltaMetric(
            label="New critical cases",
            current=int(new_critical),
            previous=0.0,
            delta=int(new_critical),
            direction="up" if new_critical > 0 else "flat",
            interpretation="bad" if new_critical > 0 else "good",
        )
    )
    metrics.append(
        DeltaMetric(
            label="Cases closed",
            current=int(closed_in_window),
            previous=0.0,
            delta=int(closed_in_window),
            direction="up" if closed_in_window > 0 else "flat",
            interpretation="good" if closed_in_window > 0 else "neutral",
        )
    )

    # New suspect domains.
    try:
        from src.models.brand import SuspectDomain
        new_suspects = (
            await db.execute(
                select(func.count()).select_from(SuspectDomain).where(
                    and_(
                        SuspectDomain.organization_id == organization_id,
                        SuspectDomain.created_at >= cutoff,
                    )
                )
            )
        ).scalar_one()
        metrics.append(
            DeltaMetric(
                label="New brand suspects",
                current=int(new_suspects),
                previous=0.0,
                delta=int(new_suspects),
                direction="up" if new_suspects > 0 else "flat",
                interpretation="neutral",
                note="Lookalike domains flagged by typosquat scans",
            )
        )
    except ImportError:
        pass

    # Rating change since the last persisted rating before window.
    try:
        from src.models.ratings import SecurityRating
        prior = (
            await db.execute(
                select(SecurityRating).where(
                    and_(
                        SecurityRating.organization_id == organization_id,
                        SecurityRating.computed_at < cutoff,
                    )
                ).order_by(SecurityRating.computed_at.desc()).limit(1)
            )
        ).scalar_one_or_none()
        current = (
            await db.execute(
                select(SecurityRating).where(
                    and_(
                        SecurityRating.organization_id == organization_id,
                        SecurityRating.is_current == True,  # noqa: E712
                    )
                ).limit(1)
            )
        ).scalar_one_or_none()
        if current and prior:
            delta = float((current.score or 0) - (prior.score or 0))
            direction = "up" if delta > 0 else ("down" if delta < 0 else "flat")
            metrics.append(
                DeltaMetric(
                    label="Security rating",
                    current=float(current.score or 0),
                    previous=float(prior.score or 0),
                    delta=delta,
                    direction=direction,
                    interpretation="good" if delta > 0 else ("bad" if delta < 0 else "neutral"),
                    note=f"{prior.grade} → {current.grade}",
                )
            )
    except ImportError:
        pass

    return ChangesResponse(
        window_days=window_days,
        metrics=metrics,
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/compliance", response_model=ComplianceResponse)
async def exec_compliance(
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_session),
):
    """Compliance posture mini-grid for the CIO page."""
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    metrics: list[ComplianceMetric] = []

    # DMARC pass-rate (last 30d).
    pass_rate = await _dmarc_pass_rate(db, organization_id, days=30)
    if pass_rate is None:
        metrics.append(
            ComplianceMetric(
                key="dmarc",
                label="DMARC pass-rate (30d)",
                value="—",
                target=0.95,
                status="unknown",
                note="No DMARC reports ingested. Verify aggregate reports are being delivered to Argus.",
            )
        )
    else:
        metrics.append(
            ComplianceMetric(
                key="dmarc",
                label="DMARC pass-rate (30d)",
                value=round(pass_rate, 4),
                target=0.95,
                status="ok" if pass_rate >= 0.95 else ("warn" if pass_rate >= 0.85 else "fail"),
            )
        )

    # NEEDS_REVIEW backlog.
    backlog = await _count_needs_review(db, organization_id)
    metrics.append(
        ComplianceMetric(
            key="needs_review_backlog",
            label="NEEDS_REVIEW backlog",
            value=backlog,
            target=0,
            status="ok" if backlog == 0 else ("warn" if backlog < 20 else "fail"),
            note="Borderline triage matches awaiting analyst Approve / Reject.",
        )
    )

    # Asset coverage % — count assets with any monitoring vs total.
    total_assets = (
        await db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.organization_id == organization_id,
            )
        )
    ).scalar_one()
    monitored_assets = (
        await db.execute(
            select(func.count()).select_from(Asset).where(
                and_(
                    Asset.organization_id == organization_id,
                    Asset.monitoring_profile.isnot(None),
                )
            )
        )
    ).scalar_one()
    coverage = (monitored_assets / total_assets) if total_assets else None
    metrics.append(
        ComplianceMetric(
            key="asset_coverage",
            label="Asset monitoring coverage",
            value=round(coverage, 4) if coverage is not None else "—",
            target=1.0,
            status=(
                "unknown" if coverage is None
                else "ok" if coverage >= 0.9
                else ("warn" if coverage >= 0.6 else "fail")
            ),
            note=f"{monitored_assets} of {total_assets} assets have monitoring profiles",
        )
    )

    # Last typosquat scan age.
    age = await _typosquat_scan_age_days(db, organization_id)
    metrics.append(
        ComplianceMetric(
            key="typosquat_scan_age",
            label="Last typosquat scan",
            value=f"{age}d ago" if age is not None else "never",
            target="< 2d",
            status=(
                "unknown" if age is None
                else "ok" if age <= 2
                else ("warn" if age <= 7 else "fail")
            ),
        )
    )

    # MFA enrolled %.
    from src.models.auth import User as AuthUser
    total_users = (
        await db.execute(
            select(func.count()).select_from(AuthUser).where(
                AuthUser.is_active == True,  # noqa: E712
            )
        )
    ).scalar_one()
    mfa_enrolled = (
        await db.execute(
            select(func.count()).select_from(AuthUser).where(
                and_(
                    AuthUser.is_active == True,  # noqa: E712
                    AuthUser.mfa_enrolled_at.isnot(None),
                )
            )
        )
    ).scalar_one()
    mfa_pct = (mfa_enrolled / total_users) if total_users else None
    metrics.append(
        ComplianceMetric(
            key="mfa_enrollment",
            label="MFA enrolled (active users)",
            value=round(mfa_pct, 4) if mfa_pct is not None else "—",
            target=1.0,
            status=(
                "unknown" if mfa_pct is None
                else "ok" if mfa_pct >= 0.95
                else ("warn" if mfa_pct >= 0.7 else "fail")
            ),
            note=f"{mfa_enrolled} of {total_users}",
        )
    )

    return ComplianceResponse(
        metrics=metrics,
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/suggested-actions", response_model=SuggestedActionsResponse)
async def exec_suggested_actions(
    analyst: AnalystUser,
    organization_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_session),
):
    """Operator nudges derived from current state.

    Generated deterministically (not LLM-powered): we look at common
    misconfigurations and stale-data signals and emit actionable items.
    """
    actions: list[SuggestedAction] = []
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    # No VIPs configured → credential-leak / impersonation detection
    # missing a huge surface.
    vip_count = await _count_vips(db, organization_id)
    if vip_count == 0:
        actions.append(
            SuggestedAction(
                priority="high",
                title="Add VIP targets to enable credential-leak detection",
                detail=(
                    "Without VIPs the triage agent has no exec emails / "
                    "usernames to match against leaked stealer logs. Argus "
                    "auto-expands names into common email patterns at "
                    "match time, so even partial info (name + title) is "
                    "useful."
                ),
                # Playbook does the create — opens the in-page form drawer
                # so the operator never lands on /admin and writes VIPs
                # straight into a real audit-logged execution.
                playbook_id="add_vip_roster",
                # Legacy link kept as a fallback if the dashboard build
                # doesn't yet ship the drawer.
                link="/admin#vips",
            )
        )

    # Google Alerts placeholders still on REPLACE_FEED_ID.
    from src.models.admin import CrawlerKind, CrawlerTarget
    placeholders = (
        await db.execute(
            select(CrawlerTarget).where(
                and_(
                    CrawlerTarget.organization_id == organization_id,
                    CrawlerTarget.kind == CrawlerKind.CUSTOM_HTTP.value,
                )
            )
        )
    ).scalars().all()
    pending_alerts = sum(
        1 for t in placeholders
        if isinstance(t.config, dict)
        and "REPLACE_FEED_ID" in str(t.config.get("url", ""))
    )
    if pending_alerts:
        actions.append(
            SuggestedAction(
                priority="medium",
                title=f"Paste {pending_alerts} Google Alerts RSS URL(s)",
                detail=(
                    f"{pending_alerts} placeholder target(s) in /crawlers → "
                    "Custom HTTP / RSS / JSON. Set up brand alerts at "
                    "google.com/alerts → Deliver to RSS feed → paste each "
                    "URL into the matching placeholder."
                ),
                link="/crawlers",
            )
        )

    # Rating is stale or missing.
    rating_grade, rating_score, rating_age = await _latest_rating(
        db, organization_id
    )
    if rating_grade is None:
        actions.append(
            SuggestedAction(
                priority="medium",
                title="Compute initial security rating",
                detail=(
                    "No rating computed yet. Click Compute Rating on the "
                    "Security rating panel to seed the executive dashboard "
                    "and unlock posture-trend tracking."
                ),
                link="/exec-summary",
            )
        )
    elif rating_age is not None and rating_age > 14:
        actions.append(
            SuggestedAction(
                priority="low",
                title=f"Rating is {rating_age} days stale — recompute",
                detail=(
                    "The persisted security rating hasn't been refreshed "
                    "in over two weeks. Recompute to reflect the current "
                    "case / exposure / brand posture."
                ),
                link="/exec-summary",
            )
        )

    # NEEDS_REVIEW backlog.
    backlog = await _count_needs_review(db, organization_id)
    if backlog >= 5:
        actions.append(
            SuggestedAction(
                priority="medium",
                title=f"Review {backlog} borderline alerts",
                detail=(
                    "Borderline triage matches need analyst Approve / "
                    "Reject. Use /alerts?status=needs_review."
                ),
                link="/alerts?status=needs_review",
            )
        )

    # Stale typosquat scan.
    typo_age = await _typosquat_scan_age_days(db, organization_id)
    if typo_age is not None and typo_age > 7:
        actions.append(
            SuggestedAction(
                priority="low",
                title=f"Typosquat scan is {typo_age}d old",
                detail=(
                    "Recurring scan should run daily. Check that the "
                    "ARGUS_WORKER_TYPOSQUAT_SCAN_INTERVAL worker loop is "
                    "active and the brand scanner has DNS resolver "
                    "credentials."
                ),
                link="/brand",
            )
        )

    return SuggestedActionsResponse(
        actions=actions,
        generated_at=datetime.now(timezone.utc),
    )


# ----------------------------------------------------------------------
# Briefing prompt + cache
# ----------------------------------------------------------------------

_BRIEFING_SYSTEM_PROMPT = """You are Argus, an elite CISO writing a board-level
briefing for the CIO. The CIO is technically literate but cares about business
impact, posture trends, and concrete next steps — not raw counts.

You MUST respond with valid JSON ONLY (no markdown, no commentary). The JSON
schema is:

{
  "headline": "<one-sentence summary, max 140 chars>",
  "narrative": "<2-3 short paragraphs separated by \\n\\n. Plain language.>",
  "posture_change": "improving" | "stable" | "deteriorating",
  "top_actions": [
    {
      "playbook_id": "<MUST be one of the ids listed in the AVAILABLE PLAYBOOKS section below>",
      "title": "<imperative phrase, ≤ 90 chars>",
      "rationale": "<why this matters NOW for this org. Reference exact numbers from the snapshot.>",
      "params": { ... optional, only if the playbook has input_schema and you can seed sensible defaults ... }
    }
  ],
  "confidence": <float 0..1>
}

Rules:
- Headline must be specific, not generic ("155 brand suspects + 34 rogue mobile apps demand a takedown sprint" —
  not "Posture is okay").
- Narrative leads with the biggest current risk, then trend, then quick positives. Reference exact numbers
  when they're informative.
- top_actions: 3 items, ordered by urgency. Each playbook_id MUST come from AVAILABLE PLAYBOOKS — do
  not invent ids. If fewer than 3 playbooks are applicable, return only the applicable ones (1 or 2 is fine).
- title is imperative and specific. rationale explains why THIS org needs THIS playbook RIGHT NOW.
- Only seed `params` when the playbook has an input_schema and the snapshot gives you concrete data
  to fill it. Otherwise omit `params` and the operator will fill it in.
- Set posture_change based on the ratio of new-vs-closed cases, rating trend, and KEV-stack-match growth.
- confidence: 0.4 if many telemetry fields are missing (DMARC no-data, no rating), 0.85 if well-instrumented.
- NEVER speculate about peer benchmarks or financial impact unless the data explicitly supports it.
"""


def _format_playbook_catalog(snap: "ExecSnapshot") -> str:
    """Render the applicable-to-this-org catalog as plaintext for the prompt.

    Imported lazily so module-load order doesn't matter and so a
    catalog-validation failure surfaces at request time rather than as
    a startup crash hidden behind FastAPI's traceback.
    """
    from src.core.exec_playbooks import applicable_catalog

    # Briefing surface = org-level response recommendations.
    catalog = applicable_catalog(snap, scope="global")
    if not catalog:
        return "(no playbooks are currently applicable — return top_actions: [])"

    lines: list[str] = []
    for pb in catalog:
        flags = []
        if pb.requires_approval:
            flags.append("requires admin approval")
        if pb.requires_input:
            flags.append("requires operator input")
        flag_suffix = f" [{', '.join(flags)}]" if flags else ""
        lines.append(f"- {pb.id}: {pb.title}{flag_suffix}")
        lines.append(f"    {pb.description}")
        if pb.requires_input and pb.input_schema:
            lines.append(
                f"    input_schema (JSON Schema): {json.dumps(pb.input_schema)}"
            )
    return "\n".join(lines)


def _build_briefing_prompt(snap: ExecSnapshot) -> tuple[str, str]:
    catalog_block = _format_playbook_catalog(snap)
    user_prompt = f"""Organization: {snap.org.name}
Industry: {snap.org.industry or "unknown"}
Domains: {", ".join(snap.org.domains or [])}

## Current posture
Security rating: {snap.rating_grade or "not computed"} ({snap.rating_score or 0:.0f} / 100, {snap.rating_age_days or "?"}d old)
Open cases: {snap.cases_open_total} ({snap.cases_overdue} overdue)
  by severity: {json.dumps(snap.cases_by_severity)}
Brand suspects (open + investigation): {snap.suspect_count}
KEV CVEs matching tech_stack: {snap.kev_match_count}
Active impersonations: {snap.impersonation_count}
Rogue mobile apps: {snap.rogue_app_count}
Fraud findings: {snap.fraud_count}
NEEDS_REVIEW backlog (LLM-borderline alerts): {snap.needs_review_count}
DMARC pass-rate (30d): {f"{snap.dmarc_pass_rate:.1%}" if snap.dmarc_pass_rate is not None else "no data"}
Last typosquat scan: {f"{snap.last_typosquat_scan_age_days}d ago" if snap.last_typosquat_scan_age_days is not None else "never"}
VIPs configured: {snap.vip_count}

## AVAILABLE PLAYBOOKS  (top_actions[].playbook_id MUST be one of these ids)
{catalog_block}

Write the JSON briefing for this CIO. Lead with whatever's most urgent. Pair each
recommended action with the most appropriate playbook from the list above.
"""
    return _BRIEFING_SYSTEM_PROMPT, user_prompt


def _parse_briefing_json(raw: str) -> dict[str, Any] | None:
    """Tolerant JSON extractor — handles models that wrap output in ```json fences."""
    s = (raw or "").strip()
    if s.startswith("```"):
        # Strip code fence: ```json\n...\n```
        s = s.split("```", 2)[1]
        if s.startswith("json"):
            s = s[4:]
        s = s.split("```", 1)[0].strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # Last-ditch: find the first { ... } block.
        start = s.find("{")
        end = s.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(s[start : end + 1])
            except json.JSONDecodeError:
                return None
        return None


async def _read_briefing_cache(
    db: AsyncSession, key: str
) -> dict | None:
    """Read briefing from ``app_settings`` with TTL check.

    AppSetting has a composite primary key on (organization_id, key);
    we encode the org id into the key already so a wildcard org_id
    (NULL) row stores the briefing scoped per-org via the cache key.
    """
    from src.models.admin import AppSetting
    row = (
        await db.execute(
            select(AppSetting).where(AppSetting.key == key).limit(1)
        )
    ).scalar_one_or_none()
    if not row:
        return None
    envelope = row.value if isinstance(row.value, dict) else None
    if not envelope:
        return None
    written_at = envelope.get("_written_at")
    if not written_at:
        return None
    try:
        written_dt = datetime.fromisoformat(written_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if (datetime.now(timezone.utc) - written_dt).total_seconds() > BRIEFING_CACHE_TTL_SECONDS:
        return None
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return None
    return payload


async def _write_briefing_cache(
    db: AsyncSession, key: str, payload: dict, organization_id: uuid.UUID
) -> None:
    from src.models.admin import AppSetting, AppSettingType, AppSettingCategory
    envelope = {
        "_written_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    existing = (
        await db.execute(
            select(AppSetting).where(AppSetting.key == key).limit(1)
        )
    ).scalar_one_or_none()
    if existing:
        existing.value = envelope
    else:
        db.add(
            AppSetting(
                organization_id=organization_id,
                key=key,
                value=envelope,
                value_type=AppSettingType.JSON.value,
                category=AppSettingCategory.GENERAL.value,
                description="Cached executive briefing payload (1h TTL)",
            )
        )
    await db.flush()
