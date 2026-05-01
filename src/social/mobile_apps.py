"""Mobile-app store scanner (Audit B3 — Phase 4.4).

For each organization with active brand-NAME terms, query Google Play
and the Apple App Store for apps whose title or publisher contains the
brand. Anything past the similarity threshold lands as a
``MobileAppFinding``; if the publisher matches the org's known
``official_publishers`` list it's marked ``is_official_publisher=True``
and downgraded — the unknown publishers are the rogue-app signal.

Sources
-------
- **Google Play**: ``google-play-scraper`` (pure-Python, no key).
- **Apple App Store**: Apple's public iTunes Search API
  (``itunes.apple.com/search``) hit directly with aiohttp. No SDK
  required — the third-party ``app-store-scraper`` is broken on Python
  3.13 and the official endpoint is well-documented.

Both calls happen in parallel per term and per store. Network errors
short-circuit the affected store but never crash the scan.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

import aiohttp
from rapidfuzz import fuzz
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.brand import BrandTerm, BrandTermKind
from src.models.social import (
    MobileAppFinding,
    MobileAppFindingState,
    MobileAppStore,
)


_logger = logging.getLogger(__name__)


# Stop-words that turn into noise on a 2-3 char brand. Most brand names
# safely clear this; "ai" / "io" / "qr" would not, and we'd rather skip
# the scan than swamp the queue with false positives.
_MIN_BRAND_LEN = 4
# Default similarity threshold; tunable per-call. 70 = title or
# publisher fuzzy-matches the brand at ≥70% on rapidfuzz partial_ratio.
DEFAULT_MIN_SIMILARITY = 70

ITUNES_SEARCH_URL = "https://itunes.apple.com/search"
ITUNES_DEFAULT_COUNTRY = "us"
ITUNES_RESULT_LIMIT = 50

GOOGLE_PLAY_RESULT_LIMIT = 30


@dataclass
class AppCandidate:
    """One app surfaced from a store search.

    Whatever-the-store-returned, normalised onto the columns we persist
    as ``MobileAppFinding``. ``raw`` keeps the upstream payload so an
    analyst can drill into the original record (icon URL, screenshots,
    review counts) without us having to model every store-specific
    field.
    """

    store: MobileAppStore
    app_id: str
    title: str
    publisher: str | None
    description: str | None
    url: str | None
    rating: float | None
    install_estimate: str | None
    raw: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    organization_id: uuid.UUID
    terms_scanned: int
    candidates_seen: int
    suspects_created: int
    suspects_seen_again: int
    skipped_official: int
    errors: list[str] = field(default_factory=list)


# --- Store adapters -----------------------------------------------------


def _google_play_search(query: str, limit: int) -> list[AppCandidate]:
    """Synchronous google-play-scraper call. Caller wraps in to_thread.

    We import lazily so a missing/broken dependency doesn't crash the
    whole module — the worker tick just logs and moves on.
    """
    try:
        from google_play_scraper import search as gp_search
    except ImportError:
        return []

    results = gp_search(query, n_hits=limit, lang="en", country="us")
    out: list[AppCandidate] = []
    for r in results or []:
        app_id = r.get("appId") or r.get("app_id")
        title = r.get("title")
        if not app_id or not title:
            continue
        out.append(
            AppCandidate(
                store=MobileAppStore.GOOGLE_PLAY,
                app_id=app_id,
                title=title,
                publisher=r.get("developer"),
                description=r.get("description"),
                url=r.get("url"),
                rating=r.get("score"),
                install_estimate=r.get("installs"),
                raw={k: v for k, v in r.items() if isinstance(v, (str, int, float, bool, type(None)))},
            )
        )
    return out


async def _itunes_search(
    session: aiohttp.ClientSession,
    query: str,
    *,
    country: str = ITUNES_DEFAULT_COUNTRY,
    limit: int = ITUNES_RESULT_LIMIT,
) -> list[AppCandidate]:
    """Apple's public iTunes Search API — no key, no SDK.

    Docs: https://performance-partners.apple.com/search-api
    """
    params = {
        "term": query,
        "country": country,
        "media": "software",
        "entity": "software,iPadSoftware",
        "limit": str(limit),
    }
    try:
        async with session.get(
            ITUNES_SEARCH_URL, params=params, timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status != 200:
                return []
            payload = await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001 — store outage shouldn't break scan
        _logger.warning("itunes search failed for %r: %s", query, e)
        return []

    results = payload.get("results") or []
    out: list[AppCandidate] = []
    for r in results:
        app_id = r.get("trackId")
        title = r.get("trackName")
        if not app_id or not title:
            continue
        out.append(
            AppCandidate(
                store=MobileAppStore.APPLE,
                app_id=str(app_id),
                title=title,
                publisher=r.get("sellerName") or r.get("artistName"),
                description=r.get("description"),
                url=r.get("trackViewUrl"),
                rating=r.get("averageUserRating"),
                install_estimate=None,  # Apple doesn't publish install counts
                raw={
                    k: v for k, v in r.items()
                    if isinstance(v, (str, int, float, bool, type(None)))
                },
            )
        )
    return out


# --- Matching -----------------------------------------------------------


def _score_against_brand(candidate: AppCandidate, brand: str) -> int:
    """Best fuzzy score across title + publisher.

    rapidfuzz.partial_ratio handles substring + reordering, which is
    what we need for "Argus Pro" vs "argus" and "argus security" vs
    "argus".
    """
    brand_l = brand.lower()
    title_score = fuzz.partial_ratio(brand_l, candidate.title.lower())
    pub_score = (
        fuzz.partial_ratio(brand_l, (candidate.publisher or "").lower())
        if candidate.publisher
        else 0
    )
    return max(title_score, pub_score)


def _is_official_publisher(
    candidate: AppCandidate, official_publishers: Iterable[str]
) -> bool:
    if not candidate.publisher:
        return False
    cand = candidate.publisher.lower().strip()
    for off in official_publishers:
        off_l = off.lower().strip()
        if not off_l:
            continue
        # Equal, prefix, or fuzzy >=92.
        if cand == off_l or cand.startswith(off_l) or off_l in cand:
            return True
        if fuzz.ratio(cand, off_l) >= 92:
            return True
    return False


# --- Scan orchestration -------------------------------------------------


async def scan_organization(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    official_publishers: Iterable[str] | None = None,
    min_similarity: int = DEFAULT_MIN_SIMILARITY,
    google_play_search=_google_play_search,
    itunes_search=_itunes_search,
) -> ScanReport:
    """Scan both stores for apps matching this org's NAME brand terms.

    The default ``google_play_search`` / ``itunes_search`` callables are
    overridable so tests can inject canned results without monkey-
    patching pip-installed packages.
    """
    official_publishers = list(official_publishers or [])

    terms = (
        await db.execute(
            select(BrandTerm).where(
                and_(
                    BrandTerm.organization_id == organization_id,
                    BrandTerm.is_active == True,  # noqa: E712
                    BrandTerm.kind == BrandTermKind.NAME.value,
                )
            )
        )
    ).scalars().all()

    name_terms = [t for t in terms if len(t.value or "") >= _MIN_BRAND_LEN]

    if not name_terms:
        return ScanReport(
            organization_id=organization_id,
            terms_scanned=0,
            candidates_seen=0,
            suspects_created=0,
            suspects_seen_again=0,
            skipped_official=0,
            errors=[],
        )

    candidates_seen = 0
    suspects_created = 0
    suspects_seen_again = 0
    skipped_official = 0
    errors: list[str] = []

    async with aiohttp.ClientSession() as http:
        for term in name_terms:
            brand = term.value
            try:
                gp_task = asyncio.to_thread(
                    google_play_search, brand, GOOGLE_PLAY_RESULT_LIMIT
                )
                ios_task = itunes_search(http, brand)
                gp_hits, ios_hits = await asyncio.gather(
                    gp_task, ios_task, return_exceptions=True
                )
            except Exception as e:  # noqa: BLE001
                errors.append(f"{brand}: {type(e).__name__}: {e}")
                continue

            for store_hits, label in (
                (gp_hits, "google_play"),
                (ios_hits, "apple"),
            ):
                if isinstance(store_hits, Exception):
                    errors.append(f"{brand}/{label}: {store_hits}")
                    continue
                for cand in store_hits:
                    candidates_seen += 1
                    score = _score_against_brand(cand, brand)
                    if score < min_similarity:
                        continue
                    is_official = _is_official_publisher(cand, official_publishers)
                    if is_official:
                        skipped_official += 1
                        # We still record it (with the official flag) so
                        # an analyst can audit the assumption later, but
                        # we don't promote it via auto-case.
                    created = await _persist_finding(
                        db,
                        organization_id=organization_id,
                        candidate=cand,
                        matched_term=term.value,
                        is_official_publisher=is_official,
                    )
                    if created is None:
                        suspects_seen_again += 1
                    else:
                        suspects_created += 1
                        if not is_official:
                            await _maybe_auto_link(
                                db, organization_id, created, brand, score
                            )

    return ScanReport(
        organization_id=organization_id,
        terms_scanned=len(name_terms),
        candidates_seen=candidates_seen,
        suspects_created=suspects_created,
        suspects_seen_again=suspects_seen_again,
        skipped_official=skipped_official,
        errors=errors,
    )


async def _persist_finding(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    candidate: AppCandidate,
    matched_term: str,
    is_official_publisher: bool,
) -> MobileAppFinding | None:
    """Insert-or-touch one finding. Returns the new row, or ``None`` if
    the (org, store, app_id) tuple already exists (touched ``raw`` +
    ``state_changed_at`` to bump last-seen)."""
    existing = (
        await db.execute(
            select(MobileAppFinding).where(
                and_(
                    MobileAppFinding.organization_id == organization_id,
                    MobileAppFinding.store == candidate.store.value,
                    MobileAppFinding.app_id == candidate.app_id,
                )
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.raw = candidate.raw
        existing.title = candidate.title
        existing.publisher = candidate.publisher
        existing.rating = candidate.rating
        existing.install_estimate = candidate.install_estimate
        return None

    finding = MobileAppFinding(
        organization_id=organization_id,
        store=candidate.store.value,
        app_id=candidate.app_id,
        title=candidate.title,
        publisher=candidate.publisher,
        description=candidate.description,
        url=candidate.url,
        rating=candidate.rating,
        install_estimate=candidate.install_estimate,
        matched_term=matched_term,
        matched_term_kind="name",
        is_official_publisher=is_official_publisher,
        state=MobileAppFindingState.OPEN.value,
        raw=candidate.raw,
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return None
    return finding


async def _maybe_auto_link(
    db: AsyncSession,
    organization_id: uuid.UUID,
    finding: MobileAppFinding,
    brand: str,
    score: int,
) -> None:
    """Audit D12+D13 — route every non-official rogue app finding through
    the same auto-link helper the other detectors use. Failure here must
    not roll back the finding insert.
    """
    try:
        from src.cases.auto_link import auto_link_finding

        # Heuristic: app with a non-official publisher that fuzzy-matches
        # the brand by ≥85 is a strong rogue signal → high. 70-84 → medium.
        sev = "high" if score >= 85 else "medium"
        await auto_link_finding(
            db,
            organization_id=organization_id,
            finding_type="mobile_app",
            finding_id=finding.id,
            severity=sev,
            title=(
                f"Suspicious mobile app: {finding.title} "
                f"({finding.store}) — looks like {brand}"
            ),
            summary=(
                f"Publisher: {finding.publisher or 'unknown'}; "
                f"similarity={score}; matched_term={brand}"
            ),
            event_kind="impersonation_detection",
            dedup_key=f"mobile_app:{finding.store}:{finding.app_id}",
            tags=("mobile_app", finding.store),
        )
    except Exception:  # noqa: BLE001
        _logger.exception(
            "auto_link_finding failed for mobile_app %s", finding.id
        )


__all__ = [
    "AppCandidate",
    "ScanReport",
    "scan_organization",
    "DEFAULT_MIN_SIMILARITY",
]
