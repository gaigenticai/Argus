"""rss/cti pipeline + advisory enrichment + feed health

Adds:
  * news_feeds.category (news|intel|advisories) + credibility + language
    + description + fetch_interval_seconds + health_score
  * news_articles.body_text / summary_generated / summary_source
    + iocs_extracted / actors_extracted / techniques_extracted
    + language + body_text_hash + body_translated/summary_translated
  * advisories.source / cvss3_score / epss_score / is_kev
    + external_id / affected_products / remediation_steps
    + acknowledged_state + assigned_to
  * advisory_subscriptions table
  * advisory_comments table
  * advisory_ioc_links table
  * news_article_iocs link table

Revision ID: fc2d3e4f5a6b
Revises: fb1c2d3e4f5a
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fc2d3e4f5a6b"
down_revision = "fb1c2d3e4f5a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------- news_feeds: category + credibility + descriptive metadata ---
    op.add_column(
        "news_feeds",
        sa.Column(
            "category",
            sa.String(20),
            nullable=False,
            server_default="news",
        ),
    )
    op.add_column(
        "news_feeds",
        sa.Column("credibility_score", sa.Integer, nullable=False, server_default="50"),
    )
    op.add_column(
        "news_feeds",
        sa.Column("language", sa.String(10), nullable=False, server_default="en"),
    )
    op.add_column(
        "news_feeds",
        sa.Column("description", sa.Text),
    )
    op.add_column(
        "news_feeds",
        sa.Column(
            "fetch_interval_seconds",
            sa.Integer,
            nullable=False,
            server_default="14400",  # 4h
        ),
    )
    op.add_column(
        "news_feeds",
        sa.Column("last_status_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "news_feeds",
        sa.Column("health_score", sa.Integer, nullable=False, server_default="100"),
    )
    op.add_column(
        "news_feeds",
        sa.Column(
            "consecutive_failures",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
    )
    op.create_index("ix_news_feed_category", "news_feeds", ["category"])

    # ------- news_articles: body + summary + extraction outputs ---------
    op.add_column("news_articles", sa.Column("body_text", sa.Text))
    op.add_column("news_articles", sa.Column("body_text_hash", sa.String(64)))
    op.add_column("news_articles", sa.Column("summary_generated", sa.Text))
    op.add_column(
        "news_articles",
        sa.Column(
            "summary_source",
            sa.String(20),
            nullable=False,
            server_default="feed",
        ),
    )
    op.add_column(
        "news_articles",
        sa.Column("language", sa.String(10), nullable=False, server_default="en"),
    )
    op.add_column("news_articles", sa.Column("body_translated", sa.Text))
    op.add_column("news_articles", sa.Column("summary_translated", sa.Text))
    op.add_column(
        "news_articles",
        sa.Column(
            "iocs_extracted",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "news_articles",
        sa.Column(
            "actors_extracted",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "news_articles",
        sa.Column(
            "techniques_extracted",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
    )
    op.create_index(
        "ix_news_articles_techniques",
        "news_articles",
        ["techniques_extracted"],
        postgresql_using="gin",
    )

    # ------- news_article_iocs (link table to canonical IOC rows) ------
    op.create_table(
        "news_article_iocs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "article_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("news_articles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ioc_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("iocs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("article_id", "ioc_id", name="uq_article_ioc"),
    )

    # ------- advisories: source + scoring + workflow + remediation ----
    op.add_column(
        "advisories",
        sa.Column("source", sa.String(40), nullable=False, server_default="manual"),
    )
    op.add_column(
        "advisories",
        sa.Column("external_id", sa.String(100)),
    )
    op.add_column(
        "advisories",
        sa.Column("cvss3_score", sa.Float),
    )
    op.add_column(
        "advisories",
        sa.Column("epss_score", sa.Float),
    )
    op.add_column(
        "advisories",
        sa.Column(
            "is_kev",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "advisories",
        sa.Column(
            "affected_products",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "advisories",
        sa.Column(
            "remediation_steps",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "advisories",
        sa.Column(
            "triage_state",
            sa.String(30),
            nullable=False,
            server_default="new",
        ),
    )
    op.add_column(
        "advisories",
        sa.Column(
            "assigned_to_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
    )
    op.create_index("ix_advisory_source", "advisories", ["source"])
    op.create_index("ix_advisory_kev", "advisories", ["is_kev"])
    op.create_index("ix_advisory_triage", "advisories", ["triage_state"])
    # Allow per-source idempotent ingestion (CISA-2024-001 unique within source).
    op.create_unique_constraint(
        "uq_advisory_source_external_id",
        "advisories",
        ["source", "external_id"],
    )

    # ------- advisory_subscriptions ---------------------------------
    op.create_table(
        "advisory_subscriptions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "severity_threshold",
            sa.String(20),
            nullable=False,
            server_default="high",
        ),
        sa.Column(
            "kev_only",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "sources",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "keyword_filters",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "active",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_advisory_sub_org_active",
        "advisory_subscriptions",
        ["organization_id", "active"],
    )

    # ------- advisory_comments --------------------------------------
    op.create_table(
        "advisory_comments",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "advisory_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("advisories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_advisory_comments_advisory", "advisory_comments", ["advisory_id"]
    )

    # ------- advisory_ioc_links --------------------------------------
    op.create_table(
        "advisory_ioc_links",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "advisory_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("advisories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ioc_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("iocs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("advisory_id", "ioc_id", name="uq_advisory_ioc"),
    )


def downgrade() -> None:
    op.drop_table("advisory_ioc_links")
    op.drop_index("ix_advisory_comments_advisory", table_name="advisory_comments")
    op.drop_table("advisory_comments")
    op.drop_index("ix_advisory_sub_org_active", table_name="advisory_subscriptions")
    op.drop_table("advisory_subscriptions")
    op.drop_constraint("uq_advisory_source_external_id", "advisories", type_="unique")
    op.drop_index("ix_advisory_triage", table_name="advisories")
    op.drop_index("ix_advisory_kev", table_name="advisories")
    op.drop_index("ix_advisory_source", table_name="advisories")
    for col in [
        "assigned_to_user_id",
        "triage_state",
        "remediation_steps",
        "affected_products",
        "is_kev",
        "epss_score",
        "cvss3_score",
        "external_id",
        "source",
    ]:
        op.drop_column("advisories", col)
    op.drop_table("news_article_iocs")
    op.drop_index("ix_news_articles_techniques", table_name="news_articles")
    for col in [
        "techniques_extracted",
        "actors_extracted",
        "iocs_extracted",
        "summary_translated",
        "body_translated",
        "language",
        "summary_source",
        "summary_generated",
        "body_text_hash",
        "body_text",
    ]:
        op.drop_column("news_articles", col)
    op.drop_index("ix_news_feed_category", table_name="news_feeds")
    for col in [
        "consecutive_failures",
        "health_score",
        "last_status_at",
        "fetch_interval_seconds",
        "description",
        "language",
        "credibility_score",
        "category",
    ]:
        op.drop_column("news_feeds", col)
