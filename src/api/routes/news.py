"""Phase 8 — News & Advisories API.

Endpoints
---------
    POST  /news/feeds                       register a feed
    GET   /news/feeds                       list
    POST  /news/feeds/{id}/ingest           manual ingest (raw body or upload)
    GET   /news/articles                    cross-feed list
    GET   /news/articles/{id}               detail

    POST  /news/relevance/recompute         (admin) recompute org relevance
    GET   /news/relevance?organization_id=… list relevant articles per tenant
    POST  /news/relevance/{id}/read         mark as read
    POST  /news/relevance/{id}/bookmark     toggle bookmark

    POST  /news/advisories                  create draft advisory
    POST  /news/advisories/{id}/publish     publish
    POST  /news/advisories/{id}/revoke      revoke
    GET   /news/advisories                  list
    GET   /news/advisories/{id}             detail
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.brand import BrandTerm
from src.models.intel_polish import CveRecord
from src.models.news import (
    Advisory,
    AdvisorySeverity,
    AdvisoryState,
    ArticleRelevance,
    FeedKind,
    NewsArticle,
    NewsFeed,
)
from src.models.threat import Asset, Organization
from src.news.parser import parse_any
from src.news.relevance import score_article
from src.storage.database import get_session

router = APIRouter(prefix="/news", tags=["Threat Intelligence"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --- Feeds ------------------------------------------------------------


class FeedCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=4, max_length=500)
    kind: FeedKind = FeedKind.RSS
    tags: list[str] = Field(default_factory=list)


class FeedResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    name: str
    url: str
    kind: str
    enabled: bool
    last_fetched_at: datetime | None
    last_status: str | None
    last_error: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FeedIngestRequest(BaseModel):
    body: str = Field(min_length=1)
    kind_hint: str | None = None


class FeedIngestResult(BaseModel):
    parsed: int
    new_articles: int
    duplicates: int
    relevance_rows_created: int


@router.post("/feeds", response_model=FeedResponse, status_code=201)
async def register_feed(
    body: FeedCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    if body.organization_id is not None:
        org = await db.get(Organization, body.organization_id)
        if not org:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    feed = NewsFeed(
        organization_id=body.organization_id,
        name=body.name.strip(),
        url=body.url.strip(),
        kind=body.kind.value,
        tags=body.tags,
    )
    db.add(feed)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Feed URL already registered in this scope"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.NEWS_FEED_REGISTER,
        user=analyst,
        resource_type="news_feed",
        resource_id=str(feed.id),
        details={"name": feed.name, "url": feed.url},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(feed)
    return feed


@router.get("/feeds", response_model=list[FeedResponse])
async def list_feeds(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    enabled: bool | None = None,
):
    q = select(NewsFeed)
    if organization_id is not None:
        q = q.where(
            or_(
                NewsFeed.organization_id == organization_id,
                NewsFeed.organization_id.is_(None),
            )
        )
    if enabled is not None:
        q = q.where(NewsFeed.enabled == enabled)
    return list((await db.execute(q.order_by(NewsFeed.created_at.desc()))).scalars().all())


async def _score_for_organization(
    db: AsyncSession, organization_id: uuid.UUID, article: NewsArticle
) -> int:
    brand_terms = (
        await db.execute(
            select(BrandTerm.value).where(
                and_(
                    BrandTerm.organization_id == organization_id,
                    BrandTerm.is_active == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()

    org = await db.get(Organization, organization_id)
    asset_keywords: set[str] = set()
    for kw in (org.keywords or []):
        asset_keywords.add(kw)
    if isinstance(org.tech_stack, dict):
        for v in org.tech_stack.values():
            if isinstance(v, str):
                asset_keywords.add(v)
            elif isinstance(v, list):
                asset_keywords.update(x for x in v if isinstance(x, str))

    asset_rows = (
        await db.execute(
            select(Asset.tags).where(
                and_(
                    Asset.organization_id == organization_id,
                    Asset.is_active == True,  # noqa: E712
                )
            )
        )
    ).all()
    for row in asset_rows:
        for t in row[0] or []:
            asset_keywords.add(t)

    kev_cves = (
        await db.execute(
            select(CveRecord.cve_id).where(CveRecord.is_kev == True)  # noqa: E712
        )
    ).scalars().all()

    score = score_article(
        title=article.title,
        summary=article.summary,
        cve_ids=article.cve_ids,
        brand_terms=brand_terms,
        asset_keywords=asset_keywords,
        kev_cves=kev_cves,
    )
    if score.score <= 0.0:
        return 0
    existing = (
        await db.execute(
            select(ArticleRelevance).where(
                and_(
                    ArticleRelevance.organization_id == organization_id,
                    ArticleRelevance.article_id == article.id,
                )
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.relevance_score = score.score
        existing.matched_brand_terms = score.matched_brand_terms
        existing.matched_cves = score.matched_cves
        existing.matched_tech_keywords = score.matched_tech_keywords
        return 0
    db.add(
        ArticleRelevance(
            organization_id=organization_id,
            article_id=article.id,
            relevance_score=score.score,
            matched_brand_terms=score.matched_brand_terms,
            matched_cves=score.matched_cves,
            matched_tech_keywords=score.matched_tech_keywords,
        )
    )
    return 1


@router.post(
    "/feeds/{feed_id}/ingest", response_model=FeedIngestResult
)
async def ingest_feed(
    feed_id: uuid.UUID,
    body: FeedIngestRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    feed = await db.get(NewsFeed, feed_id)
    if not feed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Feed not found")

    parsed = parse_any(body.body, kind_hint=body.kind_hint or feed.kind)
    new_count = 0
    dup_count = 0
    rel_count = 0
    fetched_at = datetime.now(timezone.utc)

    # Org list to score against — feed-bound org if present, else all orgs.
    if feed.organization_id is not None:
        org_ids = [feed.organization_id]
    else:
        org_ids = (
            await db.execute(select(Organization.id))
        ).scalars().all()

    for art in parsed:
        url_sha = _sha(art.url)
        existing = (
            await db.execute(
                select(NewsArticle).where(NewsArticle.url_sha256 == url_sha)
            )
        ).scalar_one_or_none()
        if existing is not None:
            dup_count += 1
            article = existing
        else:
            article = NewsArticle(
                url_sha256=url_sha,
                url=art.url,
                feed_id=feed.id,
                title=art.title[:500],
                summary=art.summary,
                author=art.author,
                published_at=art.published_at,
                fetched_at=fetched_at,
                cve_ids=art.cve_ids,
                tags=art.tags[:25],
            )
            db.add(article)
            await db.flush()
            new_count += 1

        for org_id in org_ids:
            rel_count += await _score_for_organization(db, org_id, article)

    feed.last_fetched_at = fetched_at
    # Audit C3 — distinguish "successfully parsed empty feed" from
    # "parser returned [] because the body was malformed". A real
    # empty feed has whitespace; anything substantive that yields
    # zero items is a parse error worth surfacing.
    if not parsed and len((body.body or "").strip()) > 64:
        feed.last_status = "parse_error"
        feed.last_error = (
            f"parser returned no items for {len(body.body)}-byte body "
            f"(kind_hint={body.kind_hint or feed.kind!r})"
        )
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "news: parse_error feed=%s url=%s body_size=%d",
            feed.id, feed.url, len(body.body),
        )
    else:
        feed.last_status = "ok"
        feed.last_error = None

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.NEWS_FEED_FETCH,
        user=analyst,
        resource_type="news_feed",
        resource_id=str(feed.id),
        details={
            "parsed": len(parsed),
            "new_articles": new_count,
            "duplicates": dup_count,
            "relevance_rows": rel_count,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return FeedIngestResult(
        parsed=len(parsed),
        new_articles=new_count,
        duplicates=dup_count,
        relevance_rows_created=rel_count,
    )


# --- Articles ---------------------------------------------------------


class ArticleResponse(BaseModel):
    id: uuid.UUID
    url: str
    feed_id: uuid.UUID | None
    title: str
    summary: str | None
    author: str | None
    published_at: datetime | None
    fetched_at: datetime
    cve_ids: list[str]
    tags: list[str]

    model_config = {"from_attributes": True}


@router.get("/articles", response_model=list[ArticleResponse])
async def list_articles(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    feed_id: uuid.UUID | None = None,
    cve: str | None = None,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    qq = select(NewsArticle)
    if feed_id is not None:
        qq = qq.where(NewsArticle.feed_id == feed_id)
    if cve:
        qq = qq.where(NewsArticle.cve_ids.any(cve.upper()))
    if q:
        qq = qq.where(NewsArticle.title.ilike(f"%{q}%"))
    qq = qq.order_by(NewsArticle.published_at.desc().nulls_last(), NewsArticle.fetched_at.desc()).limit(limit)
    return list((await db.execute(qq)).scalars().all())


@router.get("/articles/{article_id}", response_model=ArticleResponse)
async def get_article(
    article_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    a = await db.get(NewsArticle, article_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Article not found")
    return a


# --- Relevance --------------------------------------------------------


class RelevanceResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    article_id: uuid.UUID
    article: ArticleResponse
    relevance_score: float
    matched_brand_terms: list[str]
    matched_cves: list[str]
    matched_tech_keywords: list[str]
    is_read: bool
    bookmarked: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/relevance/recompute")
async def recompute_relevance(
    organization_id: uuid.UUID,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    articles = (
        await db.execute(select(NewsArticle))
    ).scalars().all()
    new_rows = 0
    for a in articles:
        new_rows += await _score_for_organization(db, organization_id, a)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ARTICLE_RELEVANCE_RECOMPUTE,
        user=admin,
        resource_type="organization",
        resource_id=str(organization_id),
        details={"articles_scanned": len(articles), "new_relevance_rows": new_rows},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {
        "organization_id": str(organization_id),
        "articles_scanned": len(articles),
        "new_relevance_rows": new_rows,
    }


@router.get("/relevance", response_model=list[RelevanceResponse])
async def list_relevance(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    min_score: Annotated[float, Query(ge=0, le=1)] = 0.0,
    bookmarked: bool | None = None,
    is_read: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(ArticleRelevance, NewsArticle).join(
        NewsArticle, NewsArticle.id == ArticleRelevance.article_id
    ).where(
        and_(
            ArticleRelevance.organization_id == organization_id,
            ArticleRelevance.relevance_score >= min_score,
        )
    )
    if bookmarked is not None:
        q = q.where(ArticleRelevance.bookmarked == bookmarked)
    if is_read is not None:
        q = q.where(ArticleRelevance.is_read == is_read)
    q = q.order_by(
        ArticleRelevance.relevance_score.desc(),
        NewsArticle.published_at.desc().nulls_last(),
    ).limit(limit)
    rows = (await db.execute(q)).all()
    return [
        RelevanceResponse(
            id=r.id,
            organization_id=r.organization_id,
            article_id=r.article_id,
            article=ArticleResponse.model_validate(a),
            relevance_score=r.relevance_score,
            matched_brand_terms=r.matched_brand_terms,
            matched_cves=r.matched_cves,
            matched_tech_keywords=r.matched_tech_keywords,
            is_read=r.is_read,
            bookmarked=r.bookmarked,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for (r, a) in rows
    ]


@router.post(
    "/relevance/{relevance_id}/read", response_model=RelevanceResponse
)
async def mark_read(
    relevance_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    r = await db.get(ArticleRelevance, relevance_id)
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Relevance row not found")
    r.is_read = True
    a = await db.get(NewsArticle, r.article_id)
    await db.commit()
    return RelevanceResponse(
        id=r.id,
        organization_id=r.organization_id,
        article_id=r.article_id,
        article=ArticleResponse.model_validate(a),
        relevance_score=r.relevance_score,
        matched_brand_terms=r.matched_brand_terms,
        matched_cves=r.matched_cves,
        matched_tech_keywords=r.matched_tech_keywords,
        is_read=r.is_read,
        bookmarked=r.bookmarked,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


@router.post(
    "/relevance/{relevance_id}/bookmark", response_model=RelevanceResponse
)
async def toggle_bookmark(
    relevance_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    r = await db.get(ArticleRelevance, relevance_id)
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Relevance row not found")
    r.bookmarked = not r.bookmarked
    a = await db.get(NewsArticle, r.article_id)
    await db.commit()
    return RelevanceResponse(
        id=r.id,
        organization_id=r.organization_id,
        article_id=r.article_id,
        article=ArticleResponse.model_validate(a),
        relevance_score=r.relevance_score,
        matched_brand_terms=r.matched_brand_terms,
        matched_cves=r.matched_cves,
        matched_tech_keywords=r.matched_tech_keywords,
        is_read=r.is_read,
        bookmarked=r.bookmarked,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


# --- Advisories -------------------------------------------------------


class AdvisoryCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    slug: str = Field(min_length=1, max_length=200, pattern="^[a-z0-9][a-z0-9\\-]*$")
    title: str = Field(min_length=1, max_length=500)
    body_markdown: str = Field(min_length=1)
    severity: AdvisorySeverity = AdvisorySeverity.INFO
    tags: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class AdvisoryUpdate(BaseModel):
    title: str | None = None
    body_markdown: str | None = None
    severity: AdvisorySeverity | None = None
    tags: list[str] | None = None
    cve_ids: list[str] | None = None
    references: list[str] | None = None


class AdvisoryResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    slug: str
    title: str
    body_markdown: str
    severity: str
    state: str
    tags: list[str]
    cve_ids: list[str]
    references: list[str]
    published_at: datetime | None
    revoked_at: datetime | None
    revoked_reason: str | None
    author_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=1)


@router.post("/advisories", response_model=AdvisoryResponse, status_code=201)
async def create_advisory(
    body: AdvisoryCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    if body.organization_id is not None:
        org = await db.get(Organization, body.organization_id)
        if not org:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    adv = Advisory(
        organization_id=body.organization_id,
        slug=body.slug,
        title=body.title.strip(),
        body_markdown=body.body_markdown,
        severity=body.severity.value,
        state=AdvisoryState.DRAFT.value,
        tags=body.tags,
        cve_ids=[c.upper() for c in body.cve_ids],
        references=body.references,
        author_user_id=analyst.id,
    )
    db.add(adv)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Advisory slug already used in this scope"
        )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ADVISORY_CREATE,
        user=analyst,
        resource_type="advisory",
        resource_id=str(adv.id),
        details={"slug": adv.slug, "severity": adv.severity},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(adv)
    return adv


@router.patch("/advisories/{advisory_id}", response_model=AdvisoryResponse)
async def update_advisory(
    advisory_id: uuid.UUID,
    body: AdvisoryUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    adv = await db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Advisory not found")
    if adv.state == AdvisoryState.REVOKED.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Revoked advisories cannot be edited",
        )
    for field_name in (
        "title",
        "body_markdown",
        "tags",
        "cve_ids",
        "references",
    ):
        v = getattr(body, field_name)
        if v is not None:
            setattr(adv, field_name, v)
    if body.severity is not None:
        adv.severity = body.severity.value
    if body.cve_ids is not None:
        adv.cve_ids = [c.upper() for c in body.cve_ids]
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ADVISORY_UPDATE,
        user=analyst,
        resource_type="advisory",
        resource_id=str(adv.id),
        details={},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(adv)
    return adv


@router.post(
    "/advisories/{advisory_id}/publish", response_model=AdvisoryResponse
)
async def publish_advisory(
    advisory_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    adv = await db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Advisory not found")
    if adv.state == AdvisoryState.PUBLISHED.value:
        return adv
    if adv.state == AdvisoryState.REVOKED.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Revoked advisories cannot be republished"
        )
    adv.state = AdvisoryState.PUBLISHED.value
    adv.published_at = datetime.now(timezone.utc)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ADVISORY_PUBLISH,
        user=analyst,
        resource_type="advisory",
        resource_id=str(adv.id),
        details={"slug": adv.slug},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(adv)
    return adv


@router.post(
    "/advisories/{advisory_id}/revoke", response_model=AdvisoryResponse
)
async def revoke_advisory(
    advisory_id: uuid.UUID,
    body: RevokeRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    adv = await db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Advisory not found")
    if adv.state == AdvisoryState.REVOKED.value:
        return adv
    adv.state = AdvisoryState.REVOKED.value
    adv.revoked_at = datetime.now(timezone.utc)
    adv.revoked_reason = body.reason
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ADVISORY_REVOKE,
        user=analyst,
        resource_type="advisory",
        resource_id=str(adv.id),
        details={"reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(adv)
    return adv


@router.get("/advisories", response_model=list[AdvisoryResponse])
async def list_advisories(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    state: AdvisoryState | None = None,
    severity: AdvisorySeverity | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(Advisory)
    if organization_id is not None:
        q = q.where(
            or_(
                Advisory.organization_id == organization_id,
                Advisory.organization_id.is_(None),
            )
        )
    if state is not None:
        q = q.where(Advisory.state == state.value)
    if severity is not None:
        q = q.where(Advisory.severity == severity.value)
    q = q.order_by(
        Advisory.published_at.desc().nulls_last(), Advisory.created_at.desc()
    ).limit(limit)
    return list((await db.execute(q)).scalars().all())


@router.get("/advisories/{advisory_id}", response_model=AdvisoryResponse)
async def get_advisory(
    advisory_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    a = await db.get(Advisory, advisory_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Advisory not found")
    return a
