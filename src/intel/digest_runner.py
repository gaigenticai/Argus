"""Run saved searches + render markdown digests + record deliveries.

Email actually leaves the system via the project's existing notification
dispatcher (or whichever SMTP provider is wired). This module *renders
the digest content + persists a delivery row*. The dispatcher reads
unsent rows from ``intel_digest_deliveries`` (delivered=false).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.intel_polish import CveRecord
from src.models.news import Advisory, NewsArticle
from src.models.saved_searches import IntelDigestDelivery, SavedSearch

_logger = logging.getLogger(__name__)


async def _match_articles(db: AsyncSession, filters: dict[str, Any], since: datetime) -> list[NewsArticle]:
    q = select(NewsArticle).where(NewsArticle.fetched_at >= since)
    cve = filters.get("cve")
    keyword = (filters.get("q") or "").strip()
    technique = filters.get("technique")
    if cve:
        q = q.where(NewsArticle.cve_ids.any(cve))
    if technique:
        q = q.where(NewsArticle.techniques_extracted.any(technique))
    if keyword:
        like = f"%{keyword}%"
        from sqlalchemy import or_
        q = q.where(or_(NewsArticle.title.ilike(like), NewsArticle.summary.ilike(like)))
    return list((await db.execute(q.order_by(NewsArticle.published_at.desc()).limit(50))).scalars().all())


async def _match_cves(db: AsyncSession, filters: dict[str, Any], since: datetime) -> list[CveRecord]:
    q = select(CveRecord).where(CveRecord.published_at >= since)
    sev = filters.get("severity")
    min_epss = filters.get("min_epss")
    is_kev = filters.get("is_kev")
    if sev:
        q = q.where(CveRecord.cvss_severity == sev)
    if min_epss is not None:
        q = q.where(CveRecord.epss_score >= float(min_epss))
    if is_kev is True:
        q = q.where(CveRecord.is_kev.is_(True))
    return list(
        (await db.execute(q.order_by(CveRecord.published_at.desc()).limit(50))).scalars().all()
    )


async def _match_advisories(db: AsyncSession, filters: dict[str, Any], since: datetime) -> list[Advisory]:
    q = select(Advisory).where(Advisory.published_at >= since)
    sev = filters.get("severity")
    src = filters.get("source")
    is_kev = filters.get("is_kev")
    if sev:
        q = q.where(Advisory.severity == sev)
    if src:
        q = q.where(Advisory.source == src)
    if is_kev is True:
        q = q.where(Advisory.is_kev.is_(True))
    return list(
        (await db.execute(q.order_by(Advisory.published_at.desc()).limit(50))).scalars().all()
    )


def _render_articles(rows: list[NewsArticle]) -> str:
    if not rows:
        return "_No new articles in this window._\n"
    out = []
    for r in rows:
        out.append(f"- **[{r.title}]({r.url})**")
        if r.summary_generated:
            out.append(f"  {r.summary_generated.splitlines()[0][:200]}")
        if r.cve_ids:
            out.append(f"  _CVEs:_ {', '.join(r.cve_ids[:5])}")
        if r.techniques_extracted:
            out.append(f"  _ATT&CK:_ {', '.join(r.techniques_extracted[:5])}")
    return "\n".join(out) + "\n"


def _render_cves(rows: list[CveRecord]) -> str:
    if not rows:
        return "_No new CVEs in this window._\n"
    out = []
    for c in rows:
        flags = []
        if c.is_kev:
            flags.append("**KEV**")
        if c.cvss3_score is not None:
            flags.append(f"CVSS {c.cvss3_score:.1f}")
        if c.epss_score is not None:
            flags.append(f"EPSS {c.epss_score:.0%}")
        flag_str = " · ".join(flags)
        out.append(f"- `{c.cve_id}` — {c.title or '(no title)'} ({flag_str})")
    return "\n".join(out) + "\n"


def _render_advisories(rows: list[Advisory]) -> str:
    if not rows:
        return "_No new advisories in this window._\n"
    out = []
    for a in rows:
        flags = []
        if a.is_kev:
            flags.append("**KEV**")
        if a.cvss3_score is not None:
            flags.append(f"CVSS {a.cvss3_score:.1f}")
        flag_str = " · ".join(flags) or a.severity.upper()
        out.append(f"- [{a.title}](#) ({a.source} · {flag_str})")
    return "\n".join(out) + "\n"


async def run_saved_search(
    db: AsyncSession, search: SavedSearch
) -> IntelDigestDelivery | None:
    """Render the digest body for a search; persist + return the delivery."""
    now = datetime.now(timezone.utc)
    days = 1 if search.digest_frequency == "daily" else 7
    since = now - timedelta(days=days)

    if search.scope == "article":
        rows = await _match_articles(db, search.filters or {}, since)
        body = (
            f"# {search.name}\n\n"
            f"Articles since {since.date()} matching your filters:\n\n"
            + _render_articles(rows)
        )
        match_count = len(rows)
    elif search.scope == "cve":
        cves = await _match_cves(db, search.filters or {}, since)
        body = (
            f"# {search.name}\n\nCVEs since {since.date()}:\n\n"
            + _render_cves(cves)
        )
        match_count = len(cves)
    elif search.scope == "advisory":
        advs = await _match_advisories(db, search.filters or {}, since)
        body = (
            f"# {search.name}\n\nAdvisories since {since.date()}:\n\n"
            + _render_advisories(advs)
        )
        match_count = len(advs)
    else:
        return None

    if match_count == 0 and search.digest_frequency == "daily":
        # Don't spam empty digests on daily cadence; still record last_run.
        search.last_run_at = now
        await db.commit()
        return None

    delivery = IntelDigestDelivery(
        saved_search_id=search.id,
        recipient_email=search.digest_email or "",
        match_count=match_count,
        body_markdown=body,
        delivered=False,
    )
    db.add(delivery)
    search.last_run_at = now
    await db.commit()
    await db.refresh(delivery)
    return delivery


async def run_due_digests(db: AsyncSession) -> dict[str, int]:
    """Iterate every active saved search whose interval has elapsed."""
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(SavedSearch).where(
                and_(
                    SavedSearch.active.is_(True),
                    SavedSearch.digest_frequency != "off",
                )
            )
        )
    ).scalars().all()
    written = 0
    for s in rows:
        if s.last_run_at is not None:
            interval = timedelta(days=1) if s.digest_frequency == "daily" else timedelta(days=7)
            if s.last_run_at + interval > now:
                continue
        d = await run_saved_search(db, s)
        if d is not None:
            written += 1
    return {"deliveries": written, "candidates": len(rows)}


__all__ = ["run_saved_search", "run_due_digests"]
