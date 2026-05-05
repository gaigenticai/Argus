"""Mobile-app store scanner (Audit B3 — Phase 4.4).

For each organization with active brand-NAME terms, query Google Play
and the Apple App Store for apps whose title or publisher contains the
brand. Anything past the similarity threshold lands as a
``MobileAppFinding``; if the publisher matches the org's known
``official_publishers`` list it's marked ``is_official_publisher=True``
and downgraded — the unknown publishers are the rogue-app signal.

Sources
-------
- **Google Play**: native aiohttp scraper. Was on the third-party
  ``google-play-scraper`` library which does brittle deep-DOM
  traversal (``dataset["ds:4"][0][1][0][23][16]``) that returns None
  for short queries — silently dropping coverage. We now hit the
  search page ourselves, extract package IDs with a stable regex
  (``/store/apps/details?id=PKG`` URLs are part of the public
  contract), then fetch each app's detail page and parse Open Graph
  meta tags (``og:title``, ``og:description``) plus the developer
  link. Open Graph is a public web standard — Google can change its
  internal JSON shape without breaking this scraper.
- **Apple App Store**: Apple's public iTunes Search API
  (``itunes.apple.com/search``) hit directly with aiohttp. No SDK
  required — the third-party ``app-store-scraper`` is broken on
  Python 3.13 and the official endpoint is well-documented.
- **Feed Health**: every per-store call records a ``feed_health`` row
  via :mod:`src.core.feed_health` so silent degradation (Google
  blocks us, Apple changes a field name, library DOM mismatch) is
  visible in the dashboard's Feed Health panel before findings dry
  up.

Both calls happen in parallel per term and per store. Network errors
short-circuit the affected store but never crash the scan.
"""

from __future__ import annotations

import asyncio
import html as html_module
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import quote_plus

import aiohttp
from rapidfuzz import fuzz
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.models.admin import FeedHealthStatus
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


GOOGLE_PLAY_BASE = "https://play.google.com"
GOOGLE_PLAY_SEARCH_URL = GOOGLE_PLAY_BASE + "/store/search"
GOOGLE_PLAY_DETAIL_URL = GOOGLE_PLAY_BASE + "/store/apps/details"
GOOGLE_PLAY_DETAIL_CONCURRENCY = 8

# Browser-flavoured UA so Google returns the same HTML mobile/desktop
# users see (some experiments serve a stripped-down page to bare
# requests/aiohttp UA strings).
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.0 Safari/605.1.15"
    ),
    "Accept-Language": "en-US,en;q=0.8",
}


# Search-page link → Android package id. Stable: every Play Store app
# is reachable at /store/apps/details?id=<package> and that URL is in
# the public crawl contract Google publishes for SEO.
_GP_PACKAGE_RE = re.compile(r'/store/apps/details\?id=([A-Za-z0-9_.]+)')

# Tags we extract from a /store/apps/details?id=X page. Open Graph is
# a documented standard (https://ogp.me) — Google can rearrange its
# internal JSON without breaking these.
_OG_TITLE_RE = re.compile(
    r'<meta\s+property="og:title"\s+content="([^"]*)"', re.IGNORECASE
)
_OG_DESC_RE = re.compile(
    r'<meta\s+property="og:description"\s+content="([^"]*)"', re.IGNORECASE
)
_OG_IMAGE_RE = re.compile(
    r'<meta\s+property="og:image"\s+content="([^"]*)"', re.IGNORECASE
)
# Developer link sits under /store/apps/dev?id=<num>|<name>. Capture
# both id and visible label.
_DEV_LINK_RE = re.compile(
    r'<a[^>]+href="/store/apps/dev\?id=([^"]+)"[^>]*>([^<]+)</a>',
    re.IGNORECASE,
)
# Free-text install count line. Best-effort — Google often hides it.
_INSTALL_COUNT_RE = re.compile(
    r'>\s*([\d,.+KMB]+)\s+downloads?\b', re.IGNORECASE
)


async def _gp_fetch(
    session: aiohttp.ClientSession, url: str, *, timeout: float = 10.0
) -> str | None:
    try:
        async with session.get(
            url,
            headers=_BROWSER_HEADERS,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                _logger.warning(
                    "google_play GET %s → HTTP %d", url, resp.status
                )
                return None
            return await resp.text()
    except aiohttp.ClientError as exc:
        _logger.warning("google_play GET %s → network: %s", url, exc)
        return None
    except asyncio.TimeoutError:
        _logger.warning("google_play GET %s → timeout", url)
        return None


def _gp_parse_detail(html: str, package_id: str) -> AppCandidate | None:
    """Parse a single /store/apps/details page for OG-meta fields.

    Anything we can't extract cleanly is left as None; a missing title
    causes us to drop the candidate (a Google Play page without a
    title is either a stale package or an experiment HTML response).
    """
    title_m = _OG_TITLE_RE.search(html)
    if not title_m:
        return None
    title = html_module.unescape(title_m.group(1)).strip()
    # Title often looks like "App Name - Apps on Google Play" — strip
    # the marketing suffix.
    for suffix in (" - Apps on Google Play", " - Google Play"):
        if title.endswith(suffix):
            title = title[: -len(suffix)]
            break
    if not title:
        return None

    desc_m = _OG_DESC_RE.search(html)
    description = html_module.unescape(desc_m.group(1)).strip() if desc_m else None

    dev_m = _DEV_LINK_RE.search(html)
    publisher = (
        html_module.unescape(dev_m.group(2)).strip() if dev_m else None
    )

    icon_m = _OG_IMAGE_RE.search(html)
    icon_url = icon_m.group(1) if icon_m else None

    install_m = _INSTALL_COUNT_RE.search(html)
    install_estimate = (
        html_module.unescape(install_m.group(1)).strip()
        if install_m
        else None
    )

    return AppCandidate(
        store=MobileAppStore.GOOGLE_PLAY,
        app_id=package_id,
        title=title,
        publisher=publisher,
        description=description,
        url=f"{GOOGLE_PLAY_DETAIL_URL}?id={package_id}",
        rating=None,  # rating is rendered client-side via JS; not in static HTML
        install_estimate=install_estimate,
        raw={"icon_url": icon_url, "package_id": package_id},
    )


async def _google_play_search(
    session: aiohttp.ClientSession, query: str, *, limit: int
) -> list[AppCandidate]:
    """Native Play Store search via aiohttp + HTML parse.

    Two-stage: (1) fetch the search results page, regex-extract package
    IDs from ``/store/apps/details?id=...`` links, (2) fetch each
    detail page in parallel and parse Open Graph metadata.

    Two-stage is unavoidable: the search-results HTML carries package
    IDs but no clean title / publisher per row (those live in a JSON
    blob whose shape Google rotates). Detail pages carry stable OG
    meta. We bound concurrency so we don't get rate-limited.
    """
    if not query:
        return []
    search_url = (
        f"{GOOGLE_PLAY_SEARCH_URL}?q={quote_plus(query)}&c=apps&hl=en&gl=us"
    )
    search_html = await _gp_fetch(session, search_url)
    if search_html is None:
        return []

    seen: set[str] = set()
    package_ids: list[str] = []
    for m in _GP_PACKAGE_RE.finditer(search_html):
        pkg = m.group(1)
        if pkg in seen:
            continue
        seen.add(pkg)
        package_ids.append(pkg)
        if len(package_ids) >= limit:
            break
    if not package_ids:
        return []

    sem = asyncio.Semaphore(GOOGLE_PLAY_DETAIL_CONCURRENCY)

    async def _one(pkg: str) -> AppCandidate | None:
        async with sem:
            url = f"{GOOGLE_PLAY_DETAIL_URL}?id={pkg}&hl=en&gl=us"
            html = await _gp_fetch(session, url)
            if html is None:
                return None
            try:
                return _gp_parse_detail(html, pkg)
            except Exception as exc:  # noqa: BLE001 — one bad page shouldn't break scan
                _logger.warning(
                    "google_play parse failed for %s: %s", pkg, exc
                )
                return None

    results = await asyncio.gather(*[_one(p) for p in package_ids])
    return [r for r in results if r is not None]


async def _itunes_search(
    session: aiohttp.ClientSession,
    query: str,
    *,
    country: str = ITUNES_DEFAULT_COUNTRY,
    limit: int = ITUNES_RESULT_LIMIT,
) -> list[AppCandidate]:
    """Apple's public iTunes Search API — no key, no SDK.

    Docs: https://performance-partners.apple.com/search-api

    Hardened in the same shape as the native Google Play scraper:
    typed exception catches (we know exactly which structural failures
    can occur — Apple sometimes returns ``resultCount`` only with no
    ``results`` key on edge queries), and explicit per-row validation
    so a malformed entry is dropped instead of crashing the parse.
    """
    if not query:
        return []
    params = {
        "term": query,
        "country": country,
        "media": "software",
        "entity": "software,iPadSoftware",
        "limit": str(limit),
    }
    try:
        async with session.get(
            ITUNES_SEARCH_URL,
            params=params,
            headers=_BROWSER_HEADERS,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                _logger.warning(
                    "itunes search %r → HTTP %d", query, resp.status
                )
                return []
            payload = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        _logger.warning("itunes search %r → network: %s", query, exc)
        return []
    except (json.JSONDecodeError, ValueError) as exc:
        _logger.warning("itunes search %r → JSON parse: %s", query, exc)
        return []
    except Exception as exc:  # noqa: BLE001 — keep scan alive
        _logger.warning("itunes search %r → unexpected: %s", query, exc)
        return []

    if not isinstance(payload, dict):
        _logger.warning(
            "itunes search %r → unexpected payload type %s",
            query, type(payload).__name__,
        )
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    out: list[AppCandidate] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        app_id = r.get("trackId")
        title = r.get("trackName")
        if not app_id or not title:
            continue
        # Numeric fields are sometimes returned as strings on edge
        # queries; coerce defensively.
        try:
            rating = float(r["averageUserRating"]) if r.get("averageUserRating") is not None else None
        except (TypeError, ValueError):
            rating = None
        out.append(
            AppCandidate(
                store=MobileAppStore.APPLE,
                app_id=str(app_id),
                title=str(title),
                publisher=r.get("sellerName") or r.get("artistName"),
                description=r.get("description"),
                url=r.get("trackViewUrl"),
                rating=rating,
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


async def _record_store_health(
    db: AsyncSession,
    *,
    store_label: str,
    brand: str,
    hits: list[AppCandidate] | BaseException,
    organization_id: uuid.UUID,
) -> None:
    """Record one feed_health row per (store, term) attempt.

    Called by scan_organization after every gather() so a sustained
    parse failure (Google ToS-blocking us, Apple changing a field
    name, our regex going stale) becomes visible in the dashboard
    Feed Health panel instead of presenting as silent zero-findings.

    Status is classified as:
    * ``ok`` — adapter returned a list, even an empty one (queries
      legitimately have zero hits).
    * ``parse_error`` — adapter raised. Detail string carries the
      exception type + message so operators can triage from the UI.
    """
    feed_name = f"mobile_apps.{store_label}"
    if isinstance(hits, BaseException):
        try:
            await feed_health.mark_failure(
                db,
                feed_name=feed_name,
                organization_id=organization_id,
                error=hits,
                duration_ms=None,
                classify=FeedHealthStatus.PARSE_ERROR.value,
            )
        except Exception:
            _logger.exception(
                "feed_health record failed for %s/%s", feed_name, brand,
            )
        return
    try:
        await feed_health.mark_ok(
            db,
            feed_name=feed_name,
            organization_id=organization_id,
            rows_ingested=len(hits),
            duration_ms=None,
            detail=f"brand={brand}",
        )
    except Exception:
        _logger.exception(
            "feed_health record failed for %s/%s", feed_name, brand,
        )


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
                # Both adapters are now async-native (Google Play
                # switched off the third-party sync lib in this commit).
                gp_task = google_play_search(http, brand, limit=GOOGLE_PLAY_RESULT_LIMIT)
                ios_task = itunes_search(http, brand)
                gp_hits, ios_hits = await asyncio.gather(
                    gp_task, ios_task, return_exceptions=True
                )
            except Exception as e:  # noqa: BLE001
                errors.append(f"{brand}: {type(e).__name__}: {e}")
                continue

            # Per-store Feed Health snapshot. We record once per
            # (term, store) so a sustained failure for one term shows
            # up immediately in /feeds rather than waiting for an
            # operator to wonder why findings stopped landing.
            await _record_store_health(
                db, store_label="google_play", brand=brand,
                hits=gp_hits, organization_id=organization_id,
            )
            await _record_store_health(
                db, store_label="apple", brand=brand,
                hits=ios_hits, organization_id=organization_id,
            )

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
