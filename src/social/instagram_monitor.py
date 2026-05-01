"""Instagram brand monitor (Audit B3 — Phase 4.1).

Pulls public-profile data via :mod:`instaloader` for handles
configured per-organization, then runs:

- ``score_text()`` over each profile's biography to surface fraud /
  crypto-giveaway signals that mention the org's brand terms.
- ``rapidfuzz.partial_ratio()`` between the candidate handle / full
  name and every :class:`VipProfile` alias plus brand NAME terms to
  surface impersonation.

Why public-profile only
-----------------------
Authenticated scraping triggers Instagram's anti-abuse stack inside
hours. The Bellingcat OSINT toolkit explicitly recommends the
``instaloader --no-login`` mode for production-grade brand monitoring
because:

- public profiles are the attack surface customers care about (private
  profiles can't impersonate at scale);
- no operator-supplied credentials means no account-ban risk;
- rate-limit (~1-2 req/30s) is tolerable when polling 5-50 handles
  per org per hour.

Configuration
-------------
``Organization.settings["instagram_monitor_handles"]`` — list of
public handles (without the leading ``@``). Absent = no-op.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

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


@dataclass
class InstagramProfileSnapshot:
    """Whatever the loader returns, normalised onto the columns we
    consume. ``raw`` carries upstream metadata for analyst drill-in."""

    handle: str
    full_name: str | None
    biography: str | None
    is_verified: bool
    is_private: bool
    profile_url: str
    raw: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    organization_id: uuid.UUID
    handles_scanned: int
    fraud_findings_created: int
    fraud_findings_seen_again: int
    impersonations_created: int
    errors: list[str] = field(default_factory=list)


# --- Loader -------------------------------------------------------------


def _load_profile_sync(handle: str) -> InstagramProfileSnapshot | None:
    """Synchronous instaloader call. The loader is fundamentally sync
    (uses ``requests``); the worker tick wraps every call in
    ``asyncio.to_thread`` so we don't block the event loop.

    A missing / private / banned handle returns ``None`` rather than
    raising — most "this handle is gone" outcomes are signal in their
    own right (an impersonator that got platform-removed) but they're
    not actionable for the brand monitor.
    """
    try:
        import instaloader
    except ImportError:
        _logger.warning("instaloader not installed; skipping handle %s", handle)
        return None

    try:
        L = instaloader.Instaloader(
            quiet=True,
            download_pictures=False,
            download_videos=False,
            download_video_thumbnails=False,
            download_geotags=False,
            download_comments=False,
            save_metadata=False,
            compress_json=False,
            request_timeout=15.0,
            max_connection_attempts=1,
        )
        profile = instaloader.Profile.from_username(L.context, handle)
    except Exception as e:  # noqa: BLE001 — loader has many exception classes
        _logger.info("instagram profile %s unavailable: %s", handle, e)
        return None

    return InstagramProfileSnapshot(
        handle=profile.username,
        full_name=profile.full_name or None,
        biography=profile.biography or None,
        is_verified=bool(getattr(profile, "is_verified", False)),
        is_private=bool(getattr(profile, "is_private", False)),
        profile_url=f"https://www.instagram.com/{profile.username}/",
        raw={
            "userid": getattr(profile, "userid", None),
            "followers": getattr(profile, "followers", None),
            "followees": getattr(profile, "followees", None),
            "external_url": getattr(profile, "external_url", None),
        },
    )


# --- Persistence -------------------------------------------------------


async def _persist_fraud(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    snapshot: InstagramProfileSnapshot,
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
        title=f"Instagram: @{snapshot.handle}",
        excerpt=(snapshot.biography or "")[:500],
        matched_brand_terms=list(score.matched_brand_terms),
        matched_keywords=list(score.matched_keywords),
        score=float(score.score),
        rationale=score.rationale,
        detected_at=datetime.now(timezone.utc),
        state=FraudState.OPEN.value,
        raw={
            "platform": "instagram",
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
    snapshot: InstagramProfileSnapshot,
    *,
    vip_profiles: Iterable[VipProfile],
    brand_names: Iterable[str],
) -> tuple[int, str | None, str | None, uuid.UUID | None]:
    """Best score across (handle | full_name) × (vip aliases | brand names)."""
    handle_l = snapshot.handle.lower()
    full_l = (snapshot.full_name or "").lower()

    best = 0
    best_term: str | None = None
    best_kind: str | None = None
    best_vip: uuid.UUID | None = None

    def _try(candidate_str: str, term: str, kind: str, vip_id: uuid.UUID | None):
        nonlocal best, best_term, best_kind, best_vip
        c_l = candidate_str.lower().strip()
        if len(c_l) < 4 or not term:
            return
        score = fuzz.partial_ratio(c_l, term.lower())
        if score > best:
            best = score
            best_term = term
            best_kind = kind
            best_vip = vip_id

    for vp in vip_profiles:
        for c in [vp.full_name or ""] + list(vp.aliases or []):
            _try(handle_l, c, "vip", vp.id)
            if full_l:
                _try(full_l, c, "vip", vp.id)
    for b in brand_names:
        _try(handle_l, b, "brand", None)
        if full_l:
            _try(full_l, b, "brand", None)

    return best, best_term, best_kind, best_vip


async def _persist_impersonation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    snapshot: InstagramProfileSnapshot,
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
                    ImpersonationFinding.platform
                    == SocialPlatform.INSTAGRAM.value,
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
        existing.candidate_display_name = (
            existing.candidate_display_name or snapshot.full_name
        )
        existing.candidate_bio = existing.candidate_bio or snapshot.biography
        return None

    finding = ImpersonationFinding(
        organization_id=organization_id,
        vip_profile_id=vip_profile_id,
        platform=SocialPlatform.INSTAGRAM.value,
        candidate_handle=snapshot.handle,
        candidate_display_name=snapshot.full_name,
        candidate_bio=snapshot.biography,
        candidate_url=snapshot.profile_url,
        kind=impers_kind,
        name_similarity=score_f if kind == "vip" else 0.0,
        handle_similarity=score_f,
        bio_similarity=0.0,
        photo_similarity=None,
        aggregate_score=score_f,
        signals=[
            f"instagram_handle:{kind}_match",
            f"matched_term={matched_term}",
            *(["verified_account"] if snapshot.is_verified else []),
        ],
        state=ImpersonationState.OPEN.value,
        detected_at=datetime.now(timezone.utc),
        raw={
            "source": "instagram_monitor",
            "matched_term": matched_term,
            "matched_term_kind": kind,
            "fuzz_partial_ratio": score,
            "is_verified": snapshot.is_verified,
            "is_private": snapshot.is_private,
        },
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


# --- Top-level scan ----------------------------------------------------


def _handles_for_org(org: Organization) -> list[str]:
    settings = (org.settings or {}) if hasattr(org, "settings") else {}
    raw = (settings or {}).get("instagram_monitor_handles") or []
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
    auto_case_high: float | None = None,
    impersonation_auto_case_high: int | None = None,
    load_profile=None,
) -> ScanReport:
    """Pull every configured handle, score, persist.

    ``load_profile`` is a sync callable ``(handle) -> InstagramProfileSnapshot | None``;
    tests inject canned data without touching the loader / network.

    Thresholds default to the live ``AppSetting`` values for the
    organisation. Tests pass explicit values to bypass DB lookups.
    """
    load_profile = load_profile or _load_profile_sync

    if (
        fraud_threshold is None or impersonation_threshold is None
        or auto_case_high is None or impersonation_auto_case_high is None
    ):
        from src.core.detector_config import load_social_thresholds

        bundle = await load_social_thresholds(db, organization_id, "instagram")
        if fraud_threshold is None:
            fraud_threshold = bundle.fraud_threshold
        if impersonation_threshold is None:
            impersonation_threshold = bundle.impersonation_threshold
        if auto_case_high is None:
            auto_case_high = bundle.auto_case_high
        if impersonation_auto_case_high is None:
            impersonation_auto_case_high = bundle.impersonation_auto_case_high

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

    for handle in handles:
        try:
            snapshot = await asyncio.to_thread(load_profile, handle)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{handle}: {type(e).__name__}: {e}")
            continue
        if snapshot is None:
            continue

        # Impersonation scoring on handle / full name
        score, matched_term, kind, vip_id = _impersonation_score(
            snapshot,
            vip_profiles=vip_profiles,
            brand_names=brand_name_values,
        )
        if (
            score >= impersonation_threshold
            and matched_term
            and kind
            and not snapshot.is_verified
        ):
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
                await _maybe_auto_link_impersonation(
                    db,
                    organization_id=organization_id,
                    finding=created,
                    score=score,
                    auto_case_high=impersonation_auto_case_high,
                )

        # Fraud scoring on biography
        if snapshot.biography:
            f_score = fraud_score_text(
                snapshot.biography, brand_terms=brand_term_values
            )
            if f_score.score >= fraud_threshold:
                created = await _persist_fraud(
                    db,
                    organization_id=organization_id,
                    snapshot=snapshot,
                    score=f_score,
                )
                if created is None:
                    fraud_seen += 1
                else:
                    fraud_created += 1
                    await _maybe_auto_link_fraud(
                        db,
                        organization_id=organization_id,
                        finding=created,
                        score=f_score.score,
                        auto_case_high=auto_case_high,
                    )

    return ScanReport(
        organization_id=organization_id,
        handles_scanned=len(handles),
        fraud_findings_created=fraud_created,
        fraud_findings_seen_again=fraud_seen,
        impersonations_created=impers_created,
        errors=errors,
    )


async def _maybe_auto_link_fraud(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    finding: FraudFinding,
    score: float,
    auto_case_high: float = 0.7,
) -> None:
    try:
        from src.cases.auto_link import auto_link_finding

        sev = "high" if score >= auto_case_high else "medium"
        await auto_link_finding(
            db,
            organization_id=organization_id,
            finding_type="fraud_finding",
            finding_id=finding.id,
            severity=sev,
            title=f"Instagram fraud: {finding.title or finding.target_identifier}",
            summary=(
                finding.rationale
                or "Instagram bio scored above the fraud threshold."
            ),
            event_kind="data_leakage",
            dedup_key=f"fraud:instagram:{finding.target_identifier}",
            tags=("fraud", "instagram"),
        )
    except Exception:  # noqa: BLE001
        _logger.exception(
            "auto_link_finding failed for instagram fraud %s", finding.id
        )


async def _maybe_auto_link_impersonation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    finding: ImpersonationFinding,
    score: int,
    auto_case_high: int = 90,
) -> None:
    try:
        from src.cases.auto_link import auto_link_finding

        sev = "high" if score >= auto_case_high else "medium"
        await auto_link_finding(
            db,
            organization_id=organization_id,
            finding_type="impersonation_finding",
            finding_id=finding.id,
            severity=sev,
            title=(
                f"Instagram impersonation: @{finding.candidate_handle} "
                f"({finding.kind})"
            ),
            summary=(
                f"Handle / display name fuzzy-matched at {score}/100"
            ),
            event_kind="impersonation_detection",
            dedup_key=(
                f"impersonation:instagram:{finding.candidate_handle}:{finding.kind}"
            ),
            tags=("impersonation", "instagram"),
        )
    except Exception:  # noqa: BLE001
        _logger.exception(
            "auto_link_finding failed for instagram impersonation %s",
            finding.id,
        )


__all__ = [
    "InstagramProfileSnapshot",
    "ScanReport",
    "scan_organization",
    "DEFAULT_FRAUD_THRESHOLD",
    "DEFAULT_IMPERSONATION_THRESHOLD",
]
