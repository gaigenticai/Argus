"""LinkedIn brand monitor (Audit B3 — Phase 4.1).

Scrapes LinkedIn Company pages for handles configured per-organization
and surfaces:

- :class:`ImpersonationFinding` rows when a candidate Company / Person
  page's name fuzzy-matches a registered :class:`VipProfile` alias or
  brand NAME term.
- :class:`FraudFinding` rows when the page's "about" / headline text
  scores above the fraud threshold.

Why Company pages and not personal scraping
-------------------------------------------
The 9th Circuit's hiQ Labs v. LinkedIn ruling held that scraping
publicly available LinkedIn data does not violate the CFAA — the
public Company-page surface is the right legal target. Aggressive
profile-of-individuals scraping is both legally risky outside the US
and operationally fragile (LinkedIn's anti-abuse stack is the most
hostile of any major platform).

Operational risk
----------------
LinkedIn detects automation aggressively. Even with a real account the
operator's credentials get throttled / locked within hours of regular
scraping. This module enforces:

- Hard per-tick rate limit (one Company every 60s).
- ``ARGUS_WORKER_LINKEDIN_INTERVAL`` defaults to 0 (disabled).
- ``ARGUS_LINKEDIN_USERNAME`` + ``ARGUS_LINKEDIN_PASSWORD`` env vars
  required; absent = fail-closed log + no-op.
- DEPLOYMENT.md documents the ban-risk + recommends a dedicated
  LinkedIn account that is *not* tied to a real person.

Tests inject an async ``load_company`` callable so they never spin up
Selenium / hit LinkedIn.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Iterable

from rapidfuzz import fuzz
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.brand import BrandTerm, BrandTermKind
from src.models.fraud import (
    FraudChannel,
    FraudFinding,
    FraudKind,
    FraudState,
)
from src.models.social import (
    ImpersonationFinding,
    ImpersonationKind,
    ImpersonationState,
    SocialPlatform,
    VipProfile,
)
from src.models.threat import Organization
from src.social.fraud import score_text as fraud_score_text


_logger = logging.getLogger(__name__)


DEFAULT_FRAUD_THRESHOLD = 0.4
DEFAULT_IMPERSONATION_THRESHOLD = 75
# Hard floor on the per-Company delay. LinkedIn's anti-abuse system
# triggers on tight bursts; one request per minute keeps us under the
# documented heuristic threshold.
PER_COMPANY_DELAY_SECONDS = 60


@dataclass
class LinkedInCompanySnapshot:
    """Normalised Company-page payload."""

    handle: str
    display_name: str | None
    headline: str | None
    about: str | None
    industry: str | None
    profile_url: str
    raw: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    organization_id: uuid.UUID
    handles_scanned: int
    fraud_findings_created: int
    fraud_findings_seen_again: int
    impersonations_created: int
    fail_closed: bool = False
    errors: list[str] = field(default_factory=list)


# --- Loader -------------------------------------------------------------


async def _load_company_via_linkedin_scraper(
    handle: str,
) -> LinkedInCompanySnapshot | None:
    """Real-network loader. Production path.

    Returns ``None`` for missing / private / banned pages and *also*
    when operator credentials are missing — the worker tick is the
    decision-maker on whether to skip the whole scan; this loader
    just declines to fetch.
    """
    username = os.environ.get("ARGUS_LINKEDIN_USERNAME")
    password = os.environ.get("ARGUS_LINKEDIN_PASSWORD")
    if not username or not password:
        _logger.warning(
            "linkedin monitor invoked without ARGUS_LINKEDIN_USERNAME/"
            "PASSWORD; skipping handle %s",
            handle,
        )
        return None

    try:
        from linkedin_scraper import Company, login_with_credentials  # type: ignore
    except ImportError:
        _logger.warning("linkedin-scraper not installed; skipping %s", handle)
        return None

    def _sync() -> LinkedInCompanySnapshot | None:
        try:
            driver = login_with_credentials(username, password, headless=True)
        except Exception as e:  # noqa: BLE001
            _logger.warning("linkedin login failed: %s", e)
            return None
        try:
            url = f"https://www.linkedin.com/company/{handle}/"
            company = Company(linkedin_url=url, driver=driver, scrape=True)
            return LinkedInCompanySnapshot(
                handle=handle,
                display_name=getattr(company, "name", None),
                headline=getattr(company, "headline", None) or getattr(company, "tagline", None),
                about=getattr(company, "about_us", None) or getattr(company, "description", None),
                industry=getattr(company, "industry", None),
                profile_url=url,
                raw={
                    "founded": getattr(company, "founded", None),
                    "headquarters": getattr(company, "headquarters", None),
                    "company_size": getattr(company, "company_size", None),
                },
            )
        except Exception as e:  # noqa: BLE001
            _logger.info("linkedin company %s unavailable: %s", handle, e)
            return None
        finally:
            try:
                driver.quit()
            except Exception:  # noqa: BLE001
                pass

    return await asyncio.to_thread(_sync)


# --- Persistence ------------------------------------------------------


async def _persist_fraud(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    snapshot: LinkedInCompanySnapshot,
    excerpt: str,
    score,
) -> FraudFinding | None:
    target = snapshot.profile_url
    try:
        kind = FraudKind(score.kind)
    except ValueError:
        kind = FraudKind.OTHER

    existing = (
        await db.execute(
            select(FraudFinding).where(
                and_(
                    FraudFinding.organization_id == organization_id,
                    FraudFinding.channel == FraudChannel.SOCIAL.value,
                    FraudFinding.target_identifier == target,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.score = max(existing.score, float(score.score))
        existing.rationale = score.rationale
        existing.matched_keywords = list(score.matched_keywords)
        existing.matched_brand_terms = list(score.matched_brand_terms)
        return None

    finding = FraudFinding(
        organization_id=organization_id,
        kind=kind.value,
        channel=FraudChannel.SOCIAL.value,
        target_identifier=target,
        title=f"LinkedIn: {snapshot.display_name or snapshot.handle}",
        excerpt=excerpt[:500],
        matched_brand_terms=list(score.matched_brand_terms),
        matched_keywords=list(score.matched_keywords),
        score=float(score.score),
        rationale=score.rationale,
        detected_at=datetime.now(timezone.utc),
        state=FraudState.OPEN.value,
        raw={
            "platform": "linkedin",
            "handle": snapshot.handle,
            "extra": score.extra,
        },
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


def _impersonation_score(
    snapshot: LinkedInCompanySnapshot,
    *,
    vip_profiles: Iterable[VipProfile],
    brand_names: Iterable[str],
) -> tuple[int, str | None, str | None, uuid.UUID | None]:
    handle_l = snapshot.handle.lower()
    name_l = (snapshot.display_name or "").lower()

    best = 0
    best_term: str | None = None
    best_kind: str | None = None
    best_vip: uuid.UUID | None = None

    def _try(target: str, term: str, kind: str, vip_id: uuid.UUID | None):
        nonlocal best, best_term, best_kind, best_vip
        c_l = (term or "").lower().strip()
        if len(c_l) < 4 or not target:
            return
        score = fuzz.partial_ratio(c_l, target)
        if score > best:
            best = score
            best_term = term
            best_kind = kind
            best_vip = vip_id

    for vp in vip_profiles:
        for c in [vp.full_name or ""] + list(vp.aliases or []):
            _try(handle_l, c, "vip", vp.id)
            if name_l:
                _try(name_l, c, "vip", vp.id)
    for b in brand_names:
        _try(handle_l, b, "brand", None)
        if name_l:
            _try(name_l, b, "brand", None)
    return best, best_term, best_kind, best_vip


async def _persist_impersonation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    snapshot: LinkedInCompanySnapshot,
    score: int,
    matched_term: str,
    kind: str,
    vip_profile_id: uuid.UUID | None,
) -> ImpersonationFinding | None:
    impers_kind = (
        ImpersonationKind.EXECUTIVE.value
        if kind == "vip"
        else ImpersonationKind.BRAND_ACCOUNT.value
    )
    existing = (
        await db.execute(
            select(ImpersonationFinding).where(
                and_(
                    ImpersonationFinding.organization_id == organization_id,
                    ImpersonationFinding.platform == SocialPlatform.LINKEDIN.value,
                    ImpersonationFinding.candidate_handle == snapshot.handle,
                    ImpersonationFinding.kind == impers_kind,
                )
            )
        )
    ).scalar_one_or_none()
    score_f = float(score) / 100.0
    if existing is not None:
        existing.aggregate_score = max(existing.aggregate_score, score_f)
        existing.handle_similarity = max(existing.handle_similarity, score_f)
        return None

    finding = ImpersonationFinding(
        organization_id=organization_id,
        vip_profile_id=vip_profile_id,
        platform=SocialPlatform.LINKEDIN.value,
        candidate_handle=snapshot.handle,
        candidate_display_name=snapshot.display_name,
        candidate_bio=snapshot.about or snapshot.headline,
        candidate_url=snapshot.profile_url,
        kind=impers_kind,
        name_similarity=score_f if kind == "vip" else 0.0,
        handle_similarity=score_f,
        bio_similarity=0.0,
        photo_similarity=None,
        aggregate_score=score_f,
        signals=[
            f"linkedin_handle:{kind}_match",
            f"matched_term={matched_term}",
        ],
        state=ImpersonationState.OPEN.value,
        detected_at=datetime.now(timezone.utc),
        raw={
            "source": "linkedin_monitor",
            "matched_term": matched_term,
            "matched_term_kind": kind,
            "fuzz_partial_ratio": score,
            "industry": snapshot.industry,
        },
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


# --- Scan orchestration -------------------------------------------------


def _handles_for_org(org: Organization) -> list[str]:
    settings = (org.settings or {}) if hasattr(org, "settings") else {}
    raw = (settings or {}).get("linkedin_monitor_handles") or []
    if isinstance(raw, str):
        return [s.strip().lstrip("@") for s in raw.split(",") if s.strip()]
    if isinstance(raw, list):
        return [str(s).strip().lstrip("@") for s in raw if s]
    return []


async def scan_organization(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    fraud_threshold: float | None = None,
    impersonation_threshold: int | None = None,
    load_company: Callable[[str], Awaitable[LinkedInCompanySnapshot | None]]
    | None = None,
    per_company_delay: float = PER_COMPANY_DELAY_SECONDS,
) -> ScanReport:
    if load_company is None:
        load_company = _load_company_via_linkedin_scraper

    if fraud_threshold is None or impersonation_threshold is None:
        from src.core.detector_config import load_social_thresholds

        bundle = await load_social_thresholds(db, organization_id, "linkedin")
        if fraud_threshold is None:
            fraud_threshold = bundle.fraud_threshold
        if impersonation_threshold is None:
            impersonation_threshold = bundle.impersonation_threshold

    org = await db.get(Organization, organization_id)
    if org is None:
        return ScanReport(
            organization_id=organization_id,
            handles_scanned=0,
            fraud_findings_created=0,
            fraud_findings_seen_again=0,
            impersonations_created=0,
        )
    handles = _handles_for_org(org)
    if not handles:
        return ScanReport(
            organization_id=organization_id,
            handles_scanned=0,
            fraud_findings_created=0,
            fraud_findings_seen_again=0,
            impersonations_created=0,
        )

    brand_terms = (
        await db.execute(
            select(BrandTerm).where(
                and_(
                    BrandTerm.organization_id == organization_id,
                    BrandTerm.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()
    brand_term_values = [t.value for t in brand_terms]
    brand_name_values = [
        t.value for t in brand_terms if t.kind == BrandTermKind.NAME.value
    ]
    vip_profiles = (
        await db.execute(
            select(VipProfile).where(VipProfile.organization_id == organization_id)
        )
    ).scalars().all()

    fraud_created = 0
    fraud_seen = 0
    impers_created = 0
    errors: list[str] = []

    consecutive_none = 0
    fail_closed = False

    for idx, handle in enumerate(handles):
        try:
            snapshot = await load_company(handle)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{handle}: {type(e).__name__}: {e}")
            snapshot = None

        if snapshot is None:
            consecutive_none += 1
            # Fail-closed heuristic: if the first N companies all
            # decline (commonly: missing creds), don't burn the rest
            # of the list waiting on per_company_delay.
            if consecutive_none >= 3:
                fail_closed = True
                break
            if idx < len(handles) - 1 and per_company_delay > 0:
                await asyncio.sleep(per_company_delay)
            continue
        consecutive_none = 0

        score, matched_term, kind, vip_id = _impersonation_score(
            snapshot, vip_profiles=vip_profiles, brand_names=brand_name_values
        )
        if score >= impersonation_threshold and matched_term and kind:
            created = await _persist_impersonation(
                db,
                organization_id=organization_id,
                snapshot=snapshot,
                score=score,
                matched_term=matched_term,
                kind=kind,
                vip_profile_id=vip_id,
            )
            if created is not None:
                impers_created += 1

        excerpt_pieces = [snapshot.headline or "", snapshot.about or ""]
        excerpt = " — ".join(p for p in excerpt_pieces if p).strip()
        if excerpt:
            f_score = fraud_score_text(excerpt, brand_terms=brand_term_values)
            if f_score.score >= fraud_threshold:
                created = await _persist_fraud(
                    db,
                    organization_id=organization_id,
                    snapshot=snapshot,
                    excerpt=excerpt,
                    score=f_score,
                )
                if created is None:
                    fraud_seen += 1
                else:
                    fraud_created += 1

        if idx < len(handles) - 1 and per_company_delay > 0:
            await asyncio.sleep(per_company_delay)

    return ScanReport(
        organization_id=organization_id,
        handles_scanned=len(handles),
        fraud_findings_created=fraud_created,
        fraud_findings_seen_again=fraud_seen,
        impersonations_created=impers_created,
        fail_closed=fail_closed,
        errors=errors,
    )


__all__ = [
    "LinkedInCompanySnapshot",
    "ScanReport",
    "scan_organization",
    "DEFAULT_FRAUD_THRESHOLD",
    "DEFAULT_IMPERSONATION_THRESHOLD",
    "PER_COMPANY_DELAY_SECONDS",
]
