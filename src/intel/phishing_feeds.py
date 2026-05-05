"""Public phishing-feed adapters (Audit B3 — Netcraft replacement).

Pull authoritative "this URL is phishing" signal from three free
public feeds, extract the apex domain from each URL, match against
every active organization's brand terms, and persist hits as
:class:`SuspectDomain` rows tagged with the upstream feed.

Feeds wired
-----------
- **PhishTank** (``data.phishtank.com``) — community-vetted DB, JSON.
- **OpenPhish** (``openphish.com``) — actionable feed, plain-text URL list.
- **URLhaus** (``urlhaus.abuse.ch``) — malicious URL DB, CSV.

Why these and not Netcraft
--------------------------
- All three are free and licence-permitting for commercial users.
- Each is independent so coverage barely overlaps; running them all
  is the closest free-tier equivalent of Netcraft's brand-monitoring
  feed without paying ~$10k/year for an Argus-friendly volume tier.
- Each adapter returns a uniform :class:`PhishingFeedEntry` so the
  scoring + persistence path is shared.

Design
------
- Module-level fetcher per feed; tests inject canned payloads.
- One ingest cycle per worker tick — fetch, parse, filter to apex
  domains, match per-org via the same brand-feed matcher CertStream
  uses, persist as SuspectDomain (idempotent via the existing unique
  constraint on org+domain+matched_term_value).
- Per-org failures isolated; per-feed failures isolated.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Iterable
from urllib.parse import urlparse

import aiohttp
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.brand.feed import ingest_candidates
from src.models.brand import BrandTerm, SuspectDomainSource


_logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Feed URLs — overridable per deploy.
# ----------------------------------------------------------------------

PHISHTANK_DEFAULT_URL = (
    "http://data.phishtank.com/data/online-valid.json"
)
# OpenPhish moved their canonical free feed in 2025 from
# ``openphish.com/feed.txt`` (now a 302 redirect) to a static raw file
# on GitHub. We point at the GitHub source directly so we don't rely
# on the redirect surviving — no extra network hop, no silent failure
# if they retire the redirect.
OPENPHISH_DEFAULT_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
)
URLHAUS_DEFAULT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Apple/Google/MS hosts that show up in feeds when an attacker hosts
# the phish ON a legit cloud — they're not domain-of-interest for
# brand matching, so we strip them at the source. The same hosts get
# stripped by the existing brand-feed matcher's ``_DOMAIN_SAFE_RE``,
# but pre-filtering here keeps DB round-trips down at scale.
_NOISY_INFRA_HOSTS = frozenset(
    {
        "amazonaws.com",
        "appspot.com",
        "azurewebsites.net",
        "blob.core.windows.net",
        "bloggers.com",
        "blogspot.com",
        "cloudfront.net",
        "firebaseapp.com",
        "github.io",
        "googleapis.com",
        "googleusercontent.com",
        "herokuapp.com",
        "ipfs.io",
        "netlify.app",
        "pages.dev",
        "r2.dev",
        "vercel.app",
        "weeblysite.com",
        "wixsite.com",
        "wordpress.com",
        "workers.dev",
    }
)


@dataclass
class PhishingFeedEntry:
    """Normalized signal across all feeds.

    ``domain`` is the registrable apex extracted from the upstream URL
    (best-effort — phishing infra is often deeply nested; we keep the
    raw URL in ``raw`` so analysts can drill in).
    """

    domain: str
    url: str
    feed: SuspectDomainSource
    detected_at: datetime
    raw: dict = field(default_factory=dict)


@dataclass
class FeedReport:
    feed: str
    fetched_entries: int
    skipped_invalid: int
    matches_org_count: int
    suspects_created: int
    suspects_seen_again: int
    error: str | None = None


@dataclass
class IngestReport:
    organization_id: uuid.UUID | None
    feeds: list[FeedReport]


# ----------------------------------------------------------------------
# Feed fetchers — each returns a list of PhishingFeedEntry.
# ----------------------------------------------------------------------


async def _fetch_phishtank(
    session: aiohttp.ClientSession, url: str
) -> list[PhishingFeedEntry]:
    """PhishTank online-valid feed (JSON).

    Each record carries ``url``, ``submission_time``, and a
    ``verification_time`` that flags it as community-vetted. We only
    take ``verified=='yes'`` rows so we don't seed the SOC with a flood
    of unconfirmed submissions.
    """
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            if resp.status != 200:
                _logger.warning("phishtank fetch HTTP %s", resp.status)
                return []
            body = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        _logger.warning("phishtank fetch failed: %s", e)
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        _logger.warning("phishtank parse failed: %s", e)
        return []

    out: list[PhishingFeedEntry] = []
    for r in data:
        if r.get("verified") != "yes":
            continue
        u = r.get("url")
        if not u:
            continue
        domain = _extract_apex(u)
        if not domain:
            continue
        ts = _parse_iso(r.get("submission_time"))
        out.append(
            PhishingFeedEntry(
                domain=domain,
                url=u,
                feed=SuspectDomainSource.PHISHTANK,
                detected_at=ts,
                raw={
                    "phish_id": r.get("phish_id"),
                    "target": r.get("target"),
                    "submission_time": r.get("submission_time"),
                    "verification_time": r.get("verification_time"),
                },
            )
        )
    return out


async def _fetch_openphish(
    session: aiohttp.ClientSession, url: str
) -> list[PhishingFeedEntry]:
    """OpenPhish community feed (one URL per line, plain text)."""
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            if resp.status != 200:
                _logger.warning("openphish fetch HTTP %s", resp.status)
                return []
            body = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        _logger.warning("openphish fetch failed: %s", e)
        return []

    out: list[PhishingFeedEntry] = []
    now = datetime.now(timezone.utc)
    for line in body.splitlines():
        u = line.strip()
        if not u or u.startswith("#"):
            continue
        domain = _extract_apex(u)
        if not domain:
            continue
        out.append(
            PhishingFeedEntry(
                domain=domain,
                url=u,
                feed=SuspectDomainSource.OPENPHISH,
                detected_at=now,
                raw={},
            )
        )
    return out


async def _fetch_urlhaus(
    session: aiohttp.ClientSession, url: str
) -> list[PhishingFeedEntry]:
    """URLhaus recent CSV feed.

    The header has 8 ``#`` comment lines then a CSV row. Columns:
    id, dateadded, url, url_status, last_online, threat, tags,
    urlhaus_link, reporter.
    """
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            if resp.status != 200:
                _logger.warning("urlhaus fetch HTTP %s", resp.status)
                return []
            body = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        _logger.warning("urlhaus fetch failed: %s", e)
        return []

    # Strip preamble lines starting with "#"
    cleaned = "\n".join(
        line for line in body.splitlines() if not line.startswith("#") and line.strip()
    )
    out: list[PhishingFeedEntry] = []
    reader = csv.reader(io.StringIO(cleaned))
    for row in reader:
        if len(row) < 6:
            continue
        # id, dateadded, url, url_status, last_online, threat, …
        try:
            _, dateadded, u, url_status, _last_online, threat, *rest = row
        except ValueError:
            continue
        # Only "online" entries — offline rows are usually de-fanged.
        if url_status and url_status.lower() not in ("online", ""):
            continue
        domain = _extract_apex(u)
        if not domain:
            continue
        ts = _parse_iso(dateadded) or datetime.now(timezone.utc)
        out.append(
            PhishingFeedEntry(
                domain=domain,
                url=u,
                feed=SuspectDomainSource.URLHAUS,
                detected_at=ts,
                raw={
                    "url_status": url_status,
                    "threat": threat,
                    "tags": rest[0] if rest else None,
                },
            )
        )
    return out


# ----------------------------------------------------------------------
# URL → apex helper.
# ----------------------------------------------------------------------


_DOMAIN_SAFE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")


def _extract_apex(url_or_domain: str) -> str | None:
    """Return the host part of a URL, lower-cased and de-fanged.

    We deliberately don't try to compute the *registrable* apex
    (publicsuffixlist) here because the brand-feed matcher already
    handles ``_label_no_subdomain`` for similarity scoring. Strips
    obvious cloud-host noise.
    """
    raw = (url_or_domain or "").strip()
    if not raw:
        return None
    # De-fanging / common artefacts
    raw = raw.replace("[.]", ".").replace("hxxp://", "http://").replace(
        "hxxps://", "https://"
    )
    # Allow plain "evil.example" without a scheme
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or "." not in host:
        return None
    if not _DOMAIN_SAFE_RE.match(host):
        return None
    # Filter cloud platforms — we don't want to alert on AWS or Vercel.
    for noisy in _NOISY_INFRA_HOSTS:
        if host.endswith("." + noisy) or host == noisy:
            return None
    return host


def _parse_iso(s: str | None) -> datetime:
    if not s:
        return datetime.now(timezone.utc)
    s = s.replace(" ", "T") if "T" not in s else s
    if s.endswith("Z"):
        s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(timezone.utc)


# ----------------------------------------------------------------------
# Per-org ingest.
# ----------------------------------------------------------------------


_FEED_REGISTRY: dict[
    str,
    tuple[
        SuspectDomainSource,
        Callable[
            [aiohttp.ClientSession, str], Awaitable[list[PhishingFeedEntry]]
        ],
        str,
    ],
] = {
    "phishtank": (
        SuspectDomainSource.PHISHTANK,
        _fetch_phishtank,
        PHISHTANK_DEFAULT_URL,
    ),
    "openphish": (
        SuspectDomainSource.OPENPHISH,
        _fetch_openphish,
        OPENPHISH_DEFAULT_URL,
    ),
    "urlhaus": (
        SuspectDomainSource.URLHAUS,
        _fetch_urlhaus,
        URLHAUS_DEFAULT_URL,
    ),
}


async def fetch_all_feeds(
    *,
    feed_urls: dict[str, str] | None = None,
    fetchers: dict[str, Callable] | None = None,
) -> dict[str, list[PhishingFeedEntry]]:
    """Run every wired feed fetcher and return entries keyed by feed.

    ``feed_urls`` overrides the default URL per feed name; ``fetchers``
    overrides the fetcher itself (tests). Per-feed failures isolated;
    a missing feed key returns an empty list rather than raising.
    """
    feed_urls = feed_urls or {}
    fetchers = fetchers or {}
    out: dict[str, list[PhishingFeedEntry]] = {}
    async with aiohttp.ClientSession() as http:
        for name, (_src, default_fetcher, default_url) in _FEED_REGISTRY.items():
            url = feed_urls.get(name, default_url)
            fn = fetchers.get(name, default_fetcher)
            try:
                entries = await fn(http, url)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as e:
                # Per-feed isolation — one broken feed must not abort
                # the others. ValueError covers JSON / CSV parse errors
                # that the per-feed fetchers re-raise.
                _logger.exception("phishing feed %s fetch crashed: %s", name, e)
                entries = []
            out[name] = entries
    return out


def _entries_to_domains(entries: Iterable[PhishingFeedEntry]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for e in entries:
        if e.domain not in seen:
            seen.add(e.domain)
            out.append(e.domain)
    return out


async def ingest_for_organization(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    feeds: dict[str, list[PhishingFeedEntry]],
) -> list[FeedReport]:
    """Run a pre-fetched feeds dict against one organization's brand
    terms. The fetch is hoisted to the worker tick because every org
    in the fleet shares the same feed payload — re-fetching per org
    would burn the same bytes N times.
    """
    reports: list[FeedReport] = []
    for name, entries in feeds.items():
        src, _fn, _url = _FEED_REGISTRY[name]
        domains = _entries_to_domains(entries)
        try:
            ingest_report = await ingest_candidates(
                db,
                organization_id,
                domains,
                source=src,
            )
            reports.append(
                FeedReport(
                    feed=name,
                    fetched_entries=len(entries),
                    skipped_invalid=ingest_report.skipped_invalid,
                    matches_org_count=ingest_report.matches,
                    suspects_created=ingest_report.suspects_created,
                    suspects_seen_again=ingest_report.suspects_seen_again,
                )
            )
        except Exception as e:  # noqa: BLE001
            await db.rollback()
            _logger.exception(
                "phishing feed %s ingest failed for org %s", name, organization_id
            )
            reports.append(
                FeedReport(
                    feed=name,
                    fetched_entries=len(entries),
                    skipped_invalid=0,
                    matches_org_count=0,
                    suspects_created=0,
                    suspects_seen_again=0,
                    error=f"{type(e).__name__}: {e}",
                )
            )
    return reports


async def orgs_with_active_brand_terms(
    db: AsyncSession,
) -> list[uuid.UUID]:
    """Same pre-filter the CertStream daemon uses: only orgs that
    actually have brand terms can produce matches, so don't burn
    round-trips on the rest of the fleet."""
    rows = await db.execute(
        select(BrandTerm.organization_id)
        .where(BrandTerm.is_active == True)  # noqa: E712
        .distinct()
    )
    return [r for r in rows.scalars().all()]


__all__ = [
    "PhishingFeedEntry",
    "FeedReport",
    "IngestReport",
    "fetch_all_feeds",
    "ingest_for_organization",
    "orgs_with_active_brand_terms",
    "PHISHTANK_DEFAULT_URL",
    "OPENPHISH_DEFAULT_URL",
    "URLHAUS_DEFAULT_URL",
]
