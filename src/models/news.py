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
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
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
    last_error: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list] = mapped_column(ARRAY(String), default=list, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "url", name="uq_news_feed_org_url"
        ),
        Index("ix_news_feed_enabled", "enabled"),
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

    __table_args__ = (
        Index("ix_news_articles_published", "published_at"),
        Index("ix_news_articles_cves", "cve_ids", postgresql_using="gin"),
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

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "slug", name="uq_advisory_org_slug"
        ),
        Index("ix_advisory_state", "state", "severity"),
    )


__all__ = [
    "FeedKind",
    "AdvisoryState",
    "AdvisorySeverity",
    "NewsFeed",
    "NewsArticle",
    "ArticleRelevance",
    "Advisory",
]
