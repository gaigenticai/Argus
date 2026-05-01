"""TikTok brand monitor (Audit B3 — Phase 4.1).

Pulls public-account data via :mod:`TikTokApi` (davidteather/TikTok-Api,
MIT-licensed) for handles configured per-organization, then runs
fraud + impersonation scoring identical to the Instagram + Telegram
monitors so the SOC sees one consistent finding shape across
platforms.

Why TikTok-Api
--------------
- Actively maintained as of April 2026 (v7.3.x).
- Used by 250+ companies in production, well-known anti-detection track
  record.
- Public users + trending content work without authenticated session.
- Async-native (asyncio.gather across handles is essentially free).

Operational note
----------------
TikTokApi spawns a Chromium browser via Playwright for token
generation. The TikTok worker tick is therefore opt-in:

- ``ARGUS_WORKER_TIKTOK_INTERVAL=0`` (default) — disabled. No browser
  ever launches.
- ``ARGUS_WORKER_TIKTOK_INTERVAL>0`` — the deploy environment must
  have ``playwright install chromium`` run. Documented in DEPLOYMENT.md.

This module is pure logic + an injectable loader. The loader uses
TikTokApi when available; tests inject a callable that produces
canned ``TikTokProfileSnapshot`` objects so unit tests never spawn a
browser.
"""

from __future__ import annotations

import asyncio
import logging
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
DEFAULT_VIDEO_SCAN_LIMIT = 5  # most-recent N videos per handle


@dataclass
class TikTokVideoSnapshot:
    """A single video's text content — used for fraud scoring."""

    video_id: str
    description: str
    url: str


@dataclass
class TikTokProfileSnapshot:
    handle: str
    display_name: str | None
    biography: str | None
    is_verified: bool
    profile_url: str
    videos: list[TikTokVideoSnapshot] = field(default_factory=list)
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


async def _load_profile_via_tiktokapi(
    handle: str, video_limit: int = DEFAULT_VIDEO_SCAN_LIMIT
) -> TikTokProfileSnapshot | None:
    """Real-network loader that boots TikTokApi + Playwright.

    Wrapped so a missing/private/unreachable handle returns ``None``
    rather than killing the worker tick. Tests should never call this.
    """
    try:
        from TikTokApi import TikTokApi
    except ImportError:
        _logger.warning("TikTokApi not installed; skipping handle %s", handle)
        return None

    try:
        async with TikTokApi() as api:
            await api.create_sessions(
                num_sessions=1, headless=True, sleep_after=2
            )
            user = api.user(username=handle)
            info = await user.info()
            videos: list[TikTokVideoSnapshot] = []
            async for v in user.videos(count=video_limit):
                d = v.as_dict if hasattr(v, "as_dict") else {}
                vid = d.get("id") or getattr(v, "id", None) or ""
                desc = d.get("desc") or getattr(v, "desc", "") or ""
                if not vid:
                    continue
                videos.append(
                    TikTokVideoSnapshot(
                        video_id=str(vid),
                        description=str(desc),
                        url=f"https://www.tiktok.com/@{handle}/video/{vid}",
                    )
                )
            user_data = (info or {}).get("userInfo", {}).get("user", {}) or {}
            return TikTokProfileSnapshot(
                handle=user_data.get("uniqueId") or handle,
                display_name=user_data.get("nickname"),
                biography=user_data.get("signature"),
                is_verified=bool(user_data.get("verified", False)),
                profile_url=f"https://www.tiktok.com/@{handle}",
                videos=videos,
                raw={"info": info},
            )
    except Exception as e:  # noqa: BLE001
        _logger.info("tiktok profile %s unavailable: %s", handle, e)
        return None


# --- Persistence -------------------------------------------------------


async def _persist_fraud(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    handle: str,
    target_url: str,
    excerpt: str,
    score,
) -> FraudFinding | None:
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
                    FraudFinding.target_identifier == target_url,
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
        target_identifier=target_url,
        title=f"TikTok: @{handle}",
        excerpt=excerpt[:500],
        matched_brand_terms=list(score.matched_brand_terms),
        matched_keywords=list(score.matched_keywords),
        score=float(score.score),
        rationale=score.rationale,
        detected_at=datetime.now(timezone.utc),
        state=FraudState.OPEN.value,
        raw={"platform": "tiktok", "handle": handle, "extra": score.extra},
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


def _impersonation_score(
    snapshot: TikTokProfileSnapshot,
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
    snapshot: TikTokProfileSnapshot,
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
                    ImpersonationFinding.platform == SocialPlatform.TIKTOK.value,
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
        platform=SocialPlatform.TIKTOK.value,
        candidate_handle=snapshot.handle,
        candidate_display_name=snapshot.display_name,
        candidate_bio=snapshot.biography,
        candidate_url=snapshot.profile_url,
        kind=impers_kind,
        name_similarity=score_f if kind == "vip" else 0.0,
        handle_similarity=score_f,
        bio_similarity=0.0,
        photo_similarity=None,
        aggregate_score=score_f,
        signals=[
            f"tiktok_handle:{kind}_match",
            f"matched_term={matched_term}",
            *(["verified_account"] if snapshot.is_verified else []),
        ],
        state=ImpersonationState.OPEN.value,
        detected_at=datetime.now(timezone.utc),
        raw={
            "source": "tiktok_monitor",
            "matched_term": matched_term,
            "matched_term_kind": kind,
            "fuzz_partial_ratio": score,
            "is_verified": snapshot.is_verified,
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
    raw = (settings or {}).get("tiktok_monitor_handles") or []
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
    load_profile: Callable[[str], Awaitable[TikTokProfileSnapshot | None]]
    | None = None,
) -> ScanReport:
    """Scan all configured handles for one org. ``load_profile`` is
    awaitable so tests can inject async fakes; production uses
    :func:`_load_profile_via_tiktokapi`.
    """
    if load_profile is None:
        load_profile = _load_profile_via_tiktokapi

    if fraud_threshold is None or impersonation_threshold is None:
        from src.core.detector_config import load_social_thresholds

        bundle = await load_social_thresholds(db, organization_id, "tiktok")
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

    for handle in handles:
        try:
            snapshot = await load_profile(handle)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{handle}: {type(e).__name__}: {e}")
            continue
        if snapshot is None:
            continue

        # Impersonation
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

        # Fraud — score the bio + each video description.
        # Bio
        if snapshot.biography:
            f_score = fraud_score_text(
                snapshot.biography, brand_terms=brand_term_values
            )
            if f_score.score >= fraud_threshold:
                created = await _persist_fraud(
                    db,
                    organization_id=organization_id,
                    handle=snapshot.handle,
                    target_url=snapshot.profile_url,
                    excerpt=snapshot.biography,
                    score=f_score,
                )
                if created is None:
                    fraud_seen += 1
                else:
                    fraud_created += 1
        # Videos
        for v in snapshot.videos:
            if not v.description:
                continue
            f_score = fraud_score_text(
                v.description, brand_terms=brand_term_values
            )
            if f_score.score < fraud_threshold:
                continue
            created = await _persist_fraud(
                db,
                organization_id=organization_id,
                handle=snapshot.handle,
                target_url=v.url,
                excerpt=v.description,
                score=f_score,
            )
            if created is None:
                fraud_seen += 1
            else:
                fraud_created += 1

    return ScanReport(
        organization_id=organization_id,
        handles_scanned=len(handles),
        fraud_findings_created=fraud_created,
        fraud_findings_seen_again=fraud_seen,
        impersonations_created=impers_created,
        errors=errors,
    )


__all__ = [
    "TikTokVideoSnapshot",
    "TikTokProfileSnapshot",
    "ScanReport",
    "scan_organization",
    "DEFAULT_FRAUD_THRESHOLD",
    "DEFAULT_IMPERSONATION_THRESHOLD",
    "DEFAULT_VIDEO_SCAN_LIMIT",
]
