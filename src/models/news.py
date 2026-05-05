"""News & Advisories (Phase 8).

NewsFeed
    A registered RSS / Atom / JSON feed source. Tenants can subscribe to
    a curated catalog (CISA, NCSC, vendor PSIRTs, security blogs) plus
    add their own.

NewsArticle
    One ingested article. Stored once globally (hashed by URL) and
    soft-tagged with relevance scores per organization.

ArticleRelevance
    Per-(article, organization) row that records how well the article
    matches the org's brand terms / asset tech stack / KEV CVEs.

Advisory
    A first-party advisory authored by the Argus team (or an org's
    security team). Stored as a versioned content item with publication
    state.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class FeedKind(str, enum.Enum):
    RSS = "rss"
    ATOM = "atom"
    JSON_FEED = "json_feed"


class AdvisoryState(str, enum.Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    REVOKED = "revoked"


# Audit D5 — alias to the canonical Severity (see src/models/common.py).
from src.models.common import Severity as AdvisorySeverity  # noqa: E402


class NewsFeed(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "news_feeds"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,  # nullable = global / catalog feed
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    kind: Mapped[str] = mapped_column(
        Enum(
            FeedKind,
            name="feed_kind",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=FeedKind.RSS.value,
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_status: Mapped[str | None] = mapped_column(String(40))
    last_status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    # Pipeline metadata
    category: Mapped[str] = mapped_column(
        String(20), nullable=False, default="news"
    )  # news | intel | advisories
    credibility_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50
    )  # 0-100
    language: Mapped[str] = mapped_column(String(10), nullable=False, default="en")
    description: Mapped[str | None] = mapped_column(Text)
    fetch_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=14400
    )
    health_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "url", name="uq_news_feed_org_url"
        ),
        Index("ix_news_feed_enabled", "enabled"),
        Index("ix_news_feed_category", "category"),
    )


class NewsArticle(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "news_articles"

    url_sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    feed_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("news_feeds.id", ondelete="SET NULL"),
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(255))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    cve_ids: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    tags: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    raw: Mapped[dict | None] = mapped_column(JSONB)

    # Pipeline outputs
    body_text: Mapped[str | None] = mapped_column(Text)
    body_text_hash: Mapped[str | None] = mapped_column(String(64))
    summary_generated: Mapped[str | None] = mapped_column(Text)
    summary_source: Mapped[str] = mapped_column(
        String(20), nullable=False, default="feed"
    )  # feed | extraction | llm
    language: Mapped[str] = mapped_column(String(10), nullable=False, default="en")
    body_translated: Mapped[str | None] = mapped_column(Text)
    summary_translated: Mapped[str | None] = mapped_column(Text)
    iocs_extracted: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    actors_extracted: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    techniques_extracted: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )

    __table_args__ = (
        Index("ix_news_articles_published", "published_at"),
        Index("ix_news_articles_cves", "cve_ids", postgresql_using="gin"),
        Index(
            "ix_news_articles_techniques",
            "techniques_extracted",
            postgresql_using="gin",
        ),
    )


class NewsArticleIoc(Base, UUIDMixin):
    """Junction table linking articles to canonical IOC rows.

    Created when the article entity-extractor finds an IP/domain/hash and
    the global /iocs upsert succeeds. Lets the article detail panel
    surface "Indicators in this article" and lets /iocs surface "Seen in
    these articles".
    """

    __tablename__ = "news_article_iocs"

    article_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("news_articles.id", ondelete="CASCADE"),
        nullable=False,
    )
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint("article_id", "ioc_id", name="uq_article_ioc"),
    )


class ArticleRelevance(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "news_article_relevance"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    article_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("news_articles.id", ondelete="CASCADE"),
        nullable=False,
    )
    relevance_score: Mapped[float] = mapped_column(Float, nullable=False)
    matched_brand_terms: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    matched_cves: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    matched_tech_keywords: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    bookmarked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "article_id",
            name="uq_relevance_org_article",
        ),
        CheckConstraint(
            "relevance_score >= 0 AND relevance_score <= 1",
            name="ck_relevance_score_range",
        ),
        Index(
            "ix_relevance_org_score",
            "organization_id",
            "relevance_score",
        ),
    )


class Advisory(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "advisories"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,  # null = global Argus advisory
    )
    slug: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body_markdown: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        Enum(
            AdvisorySeverity,
            name="advisory_severity",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=AdvisorySeverity.INFO.value,
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        Enum(
            AdvisoryState,
            name="advisory_state",
            values_callable=lambda x: [m.value for m in x],
        ),
        default=AdvisoryState.DRAFT.value,
        nullable=False,
    )
    tags: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    cve_ids: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)
    references: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(Text)
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    # Pipeline / ingestion-source metadata
    source: Mapped[str] = mapped_column(
        String(40), nullable=False, default="manual"
    )  # manual | cisa_kev | msrc | ghsa | redhat | adobe | cisco | oracle | vmware | ...
    external_id: Mapped[str | None] = mapped_column(String(100))
    cvss3_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    affected_products: Mapped[list] = mapped_column(
        JSONB, default=list, nullable=False
    )
    remediation_steps: Mapped[list] = mapped_column(
        JSONB, default=list, nullable=False
    )
    triage_state: Mapped[str] = mapped_column(
        String(30), nullable=False, default="new"
    )  # new | acknowledged | in_remediation | resolved | dismissed
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "slug", name="uq_advisory_org_slug"
        ),
        UniqueConstraint(
            "source", "external_id", name="uq_advisory_source_external_id"
        ),
        Index("ix_advisory_state", "state", "severity"),
        Index("ix_advisory_source", "source"),
        Index("ix_advisory_kev", "is_kev"),
        Index("ix_advisory_triage", "triage_state"),
    )


class AdvisorySubscription(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "advisory_subscriptions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity_threshold: Mapped[str] = mapped_column(
        String(20), nullable=False, default="high"
    )
    kev_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sources: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    keyword_filters: Mapped[list] = mapped_column(
        ARRAY(String), default=list, nullable=False
    )
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index(
            "ix_advisory_sub_org_active", "organization_id", "active"
        ),
    )


class AdvisoryComment(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "advisory_comments"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("advisories.id", ondelete="CASCADE"),
        nullable=False,
    )
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (Index("ix_advisory_comments_advisory", "advisory_id"),)


class AdvisoryIocLink(Base, UUIDMixin):
    __tablename__ = "advisory_ioc_links"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("advisories.id", ondelete="CASCADE"),
        nullable=False,
    )
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint("advisory_id", "ioc_id", name="uq_advisory_ioc"),
    )


__all__ = [
    "FeedKind",
    "AdvisoryState",
    "AdvisorySeverity",
    "NewsFeed",
    "NewsArticle",
    "NewsArticleIoc",
    "ArticleRelevance",
    "Advisory",
    "AdvisorySubscription",
    "AdvisoryComment",
    "AdvisoryIocLink",
]
