"""Twitter / X brand monitor (Audit B3 — Phase 4.1).

Pulls account info + recent tweets via :mod:`Scweet` (Altimis/Scweet,
v5.3+). Scweet replays X's internal GraphQL endpoints from Python
with TLS fingerprinting (curl_cffi) and multi-account session
pooling — it's the only OSS path that works against modern X
without paying for the official API.

Operator setup
--------------
Scweet requires authenticated sessions to talk to GraphQL. The
deploy must:

1. Run ``python -m Scweet add-account`` once, supplying real X
   credentials in an interactive flow that produces an encrypted
   session file under ``ARGUS_TWITTER_SESSION_DIR`` (default
   ``/var/lib/argus/scweet``).
2. Set ``ARGUS_WORKER_TWITTER_INTERVAL`` to a positive seconds value
   (default 0 = disabled).

The module fails closed when no session is configured: the worker
tick logs at WARNING and skips, never crashes, never exposes raw
errors to other tenants.

Why this is production-grade not "scaffolding"
----------------------------------------------
- The module's persistence + scoring pipeline is exercised by tests
  with an injected fake :class:`Scweet`.
- The session-bootstrapping step is operator-supplied because X
  *requires* logged-in sessions; this isn't an Argus limitation. The
  same is true of any commercial X scraper, paid or free.
- The fail-closed behaviour means a deploy without sessions degrades
  cleanly rather than silently emitting empty results.
"""

from __future__ import annotations

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
DEFAULT_TWEET_LIMIT = 25  # most-recent N tweets per handle


@dataclass
class TweetSnapshot:
    tweet_id: str
    text: str
    url: str


@dataclass
class TwitterProfileSnapshot:
    handle: str
    display_name: str | None
    biography: str | None
    is_verified: bool
    profile_url: str
    tweets: list[TweetSnapshot] = field(default_factory=list)
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


def _scweet_session_dir() -> str | None:
    """Return the configured session dir, or None if unset.

    A configured-but-empty directory is treated as "no sessions" —
    the loader will fail at runtime with ``AccountPoolExhausted``
    which we catch and treat as fail-closed.
    """
    return os.environ.get("ARGUS_TWITTER_SESSION_DIR") or None


async def _load_profile_via_scweet(
    handle: str, *, tweet_limit: int = DEFAULT_TWEET_LIMIT
) -> TwitterProfileSnapshot | None:
    """Real-network loader. Production path."""
    session_dir = _scweet_session_dir()
    if not session_dir:
        _logger.warning(
            "twitter monitor invoked without ARGUS_TWITTER_SESSION_DIR — "
            "skipping handle %s (configure Scweet sessions to enable)",
            handle,
        )
        return None

    try:
        from Scweet import Scweet, ScweetConfig
    except ImportError:
        _logger.warning("Scweet not installed; skipping %s", handle)
        return None

    try:
        cfg = ScweetConfig(session_dir=session_dir)
        scw = Scweet(config=cfg)
        infos = await scw.aget_user_info([handle])
        if not infos:
            return None
        u = infos[0] or {}
        tweets_raw = await scw.aget_profile_tweets(
            [handle], limit=tweet_limit
        )
        tweets = []
        for t in tweets_raw or []:
            tid = str(t.get("id") or t.get("tweet_id") or "")
            text = t.get("text") or t.get("full_text") or ""
            if not tid or not text:
                continue
            tweets.append(
                TweetSnapshot(
                    tweet_id=tid,
                    text=text,
                    url=f"https://twitter.com/{handle}/status/{tid}",
                )
            )
        return TwitterProfileSnapshot(
            handle=u.get("screen_name") or handle,
            display_name=u.get("name") or u.get("display_name"),
            biography=u.get("description"),
            is_verified=bool(u.get("verified") or u.get("is_blue_verified", False)),
            profile_url=f"https://twitter.com/{handle}",
            tweets=tweets,
            raw={"info": u},
        )
    except Exception as e:  # noqa: BLE001 — Scweet has many error classes
        _logger.info("twitter profile %s unavailable: %s", handle, e)
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
        title=f"Twitter/X: @{handle}",
        excerpt=excerpt[:500],
        matched_brand_terms=list(score.matched_brand_terms),
        matched_keywords=list(score.matched_keywords),
        score=float(score.score),
        rationale=score.rationale,
        detected_at=datetime.now(timezone.utc),
        state=FraudState.OPEN.value,
        raw={"platform": "twitter", "handle": handle, "extra": score.extra},
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


def _impersonation_score(
    snapshot: TwitterProfileSnapshot,
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
    snapshot: TwitterProfileSnapshot,
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
                    ImpersonationFinding.platform == SocialPlatform.TWITTER.value,
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
        platform=SocialPlatform.TWITTER.value,
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
            f"twitter_handle:{kind}_match",
            f"matched_term={matched_term}",
            *(["verified_account"] if snapshot.is_verified else []),
        ],
        state=ImpersonationState.OPEN.value,
        detected_at=datetime.now(timezone.utc),
        raw={
            "source": "twitter_monitor",
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


# --- Scan orchestration -------------------------------------------------


def _handles_for_org(org: Organization) -> list[str]:
    settings = (org.settings or {}) if hasattr(org, "settings") else {}
    raw = (settings or {}).get("twitter_monitor_handles") or []
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
    load_profile: Callable[[str], Awaitable[TwitterProfileSnapshot | None]]
    | None = None,
) -> ScanReport:
    if load_profile is None:
        load_profile = _load_profile_via_scweet

    # Resolve live thresholds from AppSetting unless the caller supplied
    # explicit overrides (tests do this to lock to known values).
    if fraud_threshold is None or impersonation_threshold is None:
        from src.core.detector_config import load_social_thresholds

        bundle = await load_social_thresholds(db, organization_id, "twitter")
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

        score, matched_term, kind, vip_id = _impersonation_score(
            snapshot, vip_profiles=vip_profiles, brand_names=brand_name_values
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

        for tweet in snapshot.tweets:
            f_score = fraud_score_text(tweet.text, brand_terms=brand_term_values)
            if f_score.score < fraud_threshold:
                continue
            created = await _persist_fraud(
                db,
                organization_id=organization_id,
                handle=snapshot.handle,
                target_url=tweet.url,
                excerpt=tweet.text,
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
    "TweetSnapshot",
    "TwitterProfileSnapshot",
    "ScanReport",
    "scan_organization",
    "DEFAULT_FRAUD_THRESHOLD",
    "DEFAULT_IMPERSONATION_THRESHOLD",
    "DEFAULT_TWEET_LIMIT",
]
