"""Unified RSS/Atom/JSON-feed pipeline worker.

Fetches every enabled feed (respecting per-feed `fetch_interval_seconds`),
parses, dedups by URL SHA-256, optionally fetches the article body, runs
entity extraction, and persists:

  * news_articles (with body/summary/extracted-entities)
  * iocs           (canonical upsert by (type, value), with sighting bump)
  * news_article_iocs (link table)
  * attack_technique_attachments (each T#### → article)
  * news_article_relevance (per-org)

Health bookkeeping:
  * consecutive_failures, health_score, last_status_at
  * health_score = max(0, 100 − 10·consecutive_failures)
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.intel import IOC, IocSighting, IOCType, ThreatActor
from src.models.mitre import (
    AttackTechniqueAttachment,
    AttachmentSource,
    MitreGroup,
    MitreMatrix,
    MitreTechnique,
)
from src.models.news import (
    NewsArticle,
    NewsArticleIoc,
    NewsFeed,
)
from src.models.threat import Organization
from src.news.body_extractor import fetch_and_extract
from src.news.entity_extractor import extract_entities
from src.news.parser import parse_any

_logger = logging.getLogger(__name__)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


_TYPE_MAP = {
    "ip": IOCType.IPV4,
    "ipv6": IOCType.IPV6,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5": IOCType.MD5,
    "sha1": IOCType.SHA1,
    "sha256": IOCType.SHA256,
    "email": IOCType.EMAIL,
}


async def _http_get(url: str) -> bytes | None:
    timeout = aiohttp.ClientTimeout(total=30)
    headers = {
        "User-Agent": "Argus-CTI/1.0 (+https://argus.security)",
        "Accept": "application/rss+xml, application/atom+xml, application/json, */*",
    }
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as s:
            async with s.get(url, allow_redirects=True) as resp:
                if resp.status >= 400:
                    return None
                return await resp.read()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        _logger.info("feed fetch failed %s: %s", url, e)
        return None


async def _build_actor_lookup(
    db: AsyncSession, *, organization_id: uuid.UUID | None
) -> list[tuple[str, str]]:
    """Aliases (lowercase) → 'group:G####' or 'actor:<id>' canonical id."""
    out: list[tuple[str, str]] = []
    # MITRE Groups (catalog-wide).
    groups = (
        await db.execute(
            select(MitreGroup.external_id, MitreGroup.name, MitreGroup.aliases)
        )
    ).all()
    for ext_id, name, aliases in groups:
        canonical = f"group:{ext_id}"
        if name:
            out.append((name.lower(), canonical))
        for a in aliases or []:
            out.append((a.lower(), canonical))
    # Global ThreatActor aliases (catalog table).
    actors = (
        await db.execute(
            select(ThreatActor.id, ThreatActor.primary_alias, ThreatActor.aliases)
        )
    ).all()
    for aid, primary, aliases in actors:
        canonical = f"actor:{aid}"
        if primary:
            out.append((primary.lower(), canonical))
        for a in aliases or []:
            out.append((a.lower(), canonical))
    # Dedup.
    seen = set()
    deduped: list[tuple[str, str]] = []
    for k, v in out:
        if not k or len(k) < 4:
            continue
        if (k, v) in seen:
            continue
        seen.add((k, v))
        deduped.append((k, v))
    return deduped


async def _upsert_ioc(
    db: AsyncSession,
    *,
    ioc_type: str,
    value: str,
    article_id: uuid.UUID,
    article_url: str | None = None,
    source_alert_id: uuid.UUID | None = None,
) -> uuid.UUID | None:
    enum_type = _TYPE_MAP.get(ioc_type)
    if enum_type is None:
        return None
    now = datetime.now(timezone.utc)
    # Canonical upsert by (ioc_type, value) — IOC is a global catalog.
    existing = (
        await db.execute(
            select(IOC).where(
                IOC.ioc_type == enum_type.value,
                IOC.value == value,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = IOC(
            ioc_type=enum_type.value,
            value=value[:2048],
            confidence=0.5,
            first_seen=now,
            last_seen=now,
            sighting_count=1,
            source_alert_id=source_alert_id,
            source_feed="news_pipeline",
        )
        db.add(existing)
        await db.flush()
    else:
        existing.last_seen = now
        existing.sighting_count = (existing.sighting_count or 1) + 1

    # Link to the article (idempotent).
    link_exists = (
        await db.execute(
            select(NewsArticleIoc).where(
                NewsArticleIoc.article_id == article_id,
                NewsArticleIoc.ioc_id == existing.id,
            )
        )
    ).scalar_one_or_none()
    if not link_exists:
        db.add(NewsArticleIoc(article_id=article_id, ioc_id=existing.id))

    # Per-occurrence sighting row — idempotent on
    # (ioc_id, source='news_article', source_id=article_id, seen_at=now).
    sighting_exists = (
        await db.execute(
            select(IocSighting).where(
                IocSighting.ioc_id == existing.id,
                IocSighting.source == "news_article",
                IocSighting.source_id == article_id,
            )
        )
    ).scalar_one_or_none()
    if not sighting_exists:
        db.add(
            IocSighting(
                ioc_id=existing.id,
                source="news_article",
                source_id=article_id,
                source_url=article_url,
                seen_at=now,
                context={"feed": "news_pipeline"},
            )
        )
    return existing.id


async def _attach_technique(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    article_id: uuid.UUID,
    technique_external_id: str,
) -> None:
    # Determine matrix by lookup.
    tech = (
        await db.execute(
            select(MitreTechnique).where(
                MitreTechnique.external_id == technique_external_id
            ).limit(1)
        )
    ).scalar_one_or_none()
    if tech is None:
        return
    existing = (
        await db.execute(
            select(AttackTechniqueAttachment).where(
                AttackTechniqueAttachment.organization_id == organization_id,
                AttackTechniqueAttachment.entity_type == "alert",  # closest stable type
                AttackTechniqueAttachment.entity_id == article_id,
                AttackTechniqueAttachment.technique_external_id == technique_external_id,
            )
        )
    ).scalar_one_or_none()
    if existing:
        return
    db.add(
        AttackTechniqueAttachment(
            organization_id=organization_id,
            entity_type="alert",
            entity_id=article_id,
            matrix=tech.matrix,
            technique_external_id=technique_external_id,
            confidence=0.7,
            source=AttachmentSource.IMPORT.value,
            note="auto-extracted from news article",
        )
    )


_BRIDGE_SINGLETON: "Optional[object]" = None


async def _bridge() -> "object | None":
    """Lazy singleton for the LLM bridge. Returns None if Redis is down."""
    global _BRIDGE_SINGLETON
    if _BRIDGE_SINGLETON is not None:
        return _BRIDGE_SINGLETON
    try:
        from src.llm.bridge_client import BridgeLLM, BridgeError, BridgeNotConnected  # noqa: F401
        b = BridgeLLM()
        await b.connect()
        _BRIDGE_SINGLETON = b
        return b
    except Exception as e:  # noqa: BLE001
        _logger.info("LLM bridge unavailable, skipping LLM summary/translation: %s", e)
        return None


_SUMMARY_SYSTEM = (
    "You are a senior cyber-threat-intelligence analyst. Summarise the article "
    "concisely. Output exactly:\nTL;DR: <one sentence>\n- bullet 1\n- bullet 2\n- bullet 3\n"
    "No extra prose. Bullets must be specific and load-bearing — actor names, CVEs, "
    "techniques, affected products, dates. Skip the bullets only if absent in the source."
)


_TRANSLATE_SYSTEM = (
    "You are a translation engine. Translate the user-supplied article text "
    "into English. Preserve named entities, CVEs, IPs, domains and quoted "
    "strings exactly. Output the translation only — no preamble, no notes."
)


def _looks_non_english(text: str) -> bool:
    """Quick heuristic: more than 12% non-ASCII letters → likely non-English."""
    if not text:
        return False
    sample = text[:4000]
    if not sample:
        return False
    nonascii = sum(1 for ch in sample if ord(ch) > 127 and ch.isalpha())
    letters = sum(1 for ch in sample if ch.isalpha())
    if letters < 200:
        return False
    return (nonascii / letters) > 0.12


async def _maybe_summarise(article: NewsArticle) -> tuple[str, str] | None:
    """Return (summary_text, source) when LLM summary succeeds, else None."""
    body = article.body_text or article.summary or ""
    if not body or len(body) < 200:
        return None
    bridge = await _bridge()
    if bridge is None:
        return None
    user = body[:8000]
    try:
        out = await bridge.call(_SUMMARY_SYSTEM, user)  # type: ignore[union-attr]
    except Exception as e:  # noqa: BLE001
        _logger.info("LLM summary failed: %s", e)
        return None
    out = (out or "").strip()
    if not out:
        return None
    return out[:2000], "llm"


async def _maybe_translate(article: NewsArticle) -> str | None:
    body = article.body_text or article.summary or ""
    if not body or len(body) < 200:
        return None
    if not _looks_non_english(article.title or "") and not _looks_non_english(body):
        return None
    bridge = await _bridge()
    if bridge is None:
        return None
    try:
        return (await bridge.call(_TRANSLATE_SYSTEM, body[:8000]))[:200_000].strip() or None  # type: ignore[union-attr]
    except Exception as e:  # noqa: BLE001
        _logger.info("LLM translate failed: %s", e)
        return None


async def process_article(
    db: AsyncSession,
    article: NewsArticle,
    *,
    organization_ids: Iterable[uuid.UUID],
    actor_lookup: list[tuple[str, str]],
    fetch_body: bool = True,
    summarise: bool = True,
    translate: bool = True,
) -> dict[str, int]:
    """Run body extraction + entity extraction + cross-page persistence."""
    stats = {"body": 0, "iocs": 0, "techniques": 0, "actors": 0, "summary": 0, "translated": 0}

    # 1) Body extraction (cached by hash so re-runs are cheap).
    if fetch_body and not article.body_text:
        body = await fetch_and_extract(article.url)
        if body:
            article.body_text = body[:200_000]
            article.body_text_hash = _sha(body)
            stats["body"] = 1

    blob = " ".join(
        x for x in [article.title, article.summary, article.body_text] if x
    )
    if not blob:
        return stats

    # 1b) LLM summary (only if not already populated).
    if summarise and not article.summary_generated:
        summarised = await _maybe_summarise(article)
        if summarised:
            article.summary_generated, article.summary_source = summarised
            stats["summary"] = 1

    # 1c) Translate non-English articles into English for the analyst pane.
    if translate and not article.body_translated:
        t = await _maybe_translate(article)
        if t:
            article.body_translated = t
            article.summary_translated = (
                article.summary_generated or article.summary
            )
            article.language = article.language or "auto"
            stats["translated"] = 1

    # 2) Entity extraction.
    res = extract_entities(blob, actor_alias_lookup=actor_lookup)
    article.iocs_extracted = [i.as_dict() for i in res.iocs]
    article.actors_extracted = res.actor_names
    article.techniques_extracted = res.techniques

    # Merge CVE ids back onto the article column.
    merged_cves = sorted(set((article.cve_ids or []) + res.cves))
    article.cve_ids = merged_cves

    # 3) Persist IOCs (global catalog) + per-org technique attachments.
    for ioc in res.iocs:
        await _upsert_ioc(
            db,
            ioc_type=ioc.type,
            value=ioc.value,
            article_id=article.id,
            article_url=article.url,
        )
        stats["iocs"] += 1
    for org_id in organization_ids:
        for tid in res.techniques:
            await _attach_technique(
                db,
                organization_id=org_id,
                article_id=article.id,
                technique_external_id=tid,
            )
            stats["techniques"] += 1
    stats["actors"] = len(res.actor_names)
    return stats


async def fetch_and_ingest_feed(
    db: AsyncSession,
    feed: NewsFeed,
    *,
    process_bodies: bool = True,
) -> dict[str, int]:
    """Fetch a single feed, parse, dedupe, run the full pipeline."""
    stats = {"parsed": 0, "new": 0, "dup": 0, "iocs": 0, "techniques": 0, "errors": 0}
    raw = await _http_get(feed.url)
    now = datetime.now(timezone.utc)
    if raw is None:
        feed.consecutive_failures = (feed.consecutive_failures or 0) + 1
        feed.health_score = max(0, 100 - 10 * feed.consecutive_failures)
        feed.last_status = "fetch_error"
        feed.last_status_at = now
        feed.last_error = f"http get returned no body for {feed.url}"
        stats["errors"] = 1
        return stats

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        feed.consecutive_failures = (feed.consecutive_failures or 0) + 1
        feed.health_score = max(0, 100 - 10 * feed.consecutive_failures)
        feed.last_status = "decode_error"
        feed.last_status_at = now
        feed.last_error = str(e)[:500]
        stats["errors"] = 1
        return stats

    parsed = parse_any(text, kind_hint=feed.kind)
    stats["parsed"] = len(parsed)

    if feed.organization_id is not None:
        org_ids: list[uuid.UUID] = [feed.organization_id]
    else:
        org_ids = list(
            (await db.execute(select(Organization.id))).scalars().all()
        )

    actor_lookup = await _build_actor_lookup(db, organization_id=org_ids[0] if org_ids else None)

    for art in parsed:
        url_sha = _sha(art.url)
        existing = (
            await db.execute(
                select(NewsArticle).where(NewsArticle.url_sha256 == url_sha)
            )
        ).scalar_one_or_none()
        if existing is not None:
            stats["dup"] += 1
            article = existing
        else:
            article = NewsArticle(
                url_sha256=url_sha,
                url=art.url,
                feed_id=feed.id,
                title=(art.title or "")[:500],
                summary=art.summary,
                author=art.author,
                published_at=art.published_at,
                fetched_at=now,
                cve_ids=art.cve_ids or [],
                tags=(art.tags or [])[:25],
                language=feed.language or "en",
            )
            db.add(article)
            await db.flush()
            stats["new"] += 1

        if process_bodies:
            try:
                sub_stats = await process_article(
                    db,
                    article,
                    organization_ids=org_ids,
                    actor_lookup=actor_lookup,
                    fetch_body=feed.category in ("intel", "news"),
                )
                stats["iocs"] += sub_stats["iocs"]
                stats["techniques"] += sub_stats["techniques"]
            except Exception:  # noqa: BLE001
                _logger.exception("article post-processing failed: %s", article.url)
                stats["errors"] += 1

        # Per-org relevance scoring uses the existing helper in
        # src.api.routes.news; lazy-import to avoid cycles.
        try:
            from src.api.routes.news import _score_for_organization  # type: ignore
            for org_id in org_ids:
                try:
                    await _score_for_organization(db, org_id, article)
                except Exception:  # noqa: BLE001
                    _logger.exception("relevance scoring failed")
        except ImportError:
            pass

    # Health bookkeeping on success.
    feed.last_fetched_at = now
    feed.last_status = "ok"
    feed.last_status_at = now
    feed.last_error = None
    feed.consecutive_failures = 0
    feed.health_score = 100
    return stats


async def fetch_due_feeds(
    db: AsyncSession,
    *,
    process_bodies: bool = True,
    max_feeds: int | None = None,
) -> dict[str, int]:
    """Iterate every feed whose interval has elapsed and run the pipeline."""
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(select(NewsFeed).where(NewsFeed.enabled.is_(True)))
    ).scalars().all()
    due = [
        f
        for f in rows
        if (
            f.last_fetched_at is None
            or f.last_fetched_at + timedelta(seconds=f.fetch_interval_seconds or 14400)
            <= now
        )
    ]
    if max_feeds is not None:
        due = due[:max_feeds]
    totals = {"feeds": 0, "parsed": 0, "new": 0, "dup": 0, "iocs": 0, "techniques": 0, "errors": 0}
    for feed in due:
        s = await fetch_and_ingest_feed(db, feed, process_bodies=process_bodies)
        totals["feeds"] += 1
        for k in ("parsed", "new", "dup", "iocs", "techniques", "errors"):
            totals[k] += s.get(k, 0)
        await db.commit()
    return totals


__all__ = [
    "fetch_and_ingest_feed",
    "fetch_due_feeds",
    "process_article",
]
