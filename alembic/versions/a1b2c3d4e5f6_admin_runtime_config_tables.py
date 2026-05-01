"""admin runtime config tables — app_settings, crawler_targets, feed_health, subsidiary_allowlist

Revision ID: a1b2c3d4e5f6
Revises: 9b4e5f33c1d2
Create Date: 2026-04-29

These four tables move tuning out of code/env and into the database:

    app_settings           per-org key/typed-value rows for fraud
                           thresholds, rating weights, brand
                           similarity, classifier confidence, and
                           auto-case severity.
    crawler_targets        per-org per-kind crawler targets so the
                           scheduler stops running with empty configs.
    feed_health            per-feed-run health rows so silent zeros
                           on missing API keys / network errors
                           surface in the UI as "feed unhealthy".
    subsidiary_allowlist   domains/brand names that legitimately
                           belong to the customer; brand scanner
                           consults the list before creating
                           SuspectDomain rows.

The migration also seeds a minimum set of AppSetting rows so a fresh
install has working defaults for every tunable. Operators can then edit
values via the admin dashboard without touching env vars.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = "a1b2c3d4e5f6"
down_revision = "9b4e5f33c1d2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(160), nullable=False),
        sa.Column("category", sa.String(40), nullable=False, server_default="general"),
        sa.Column("value_type", sa.String(16), nullable=False, server_default="json"),
        sa.Column("value", JSONB, nullable=False),
        sa.Column("description", sa.String(1024)),
        sa.Column("minimum", sa.Float),
        sa.Column("maximum", sa.Float),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("organization_id", "key", name="uq_app_settings_org_key"),
        sa.CheckConstraint(
            "value_type IN ('string','integer','float','boolean','json')",
            name="ck_app_settings_value_type",
        ),
    )
    op.create_index("ix_app_settings_organization_id", "app_settings", ["organization_id"])

    op.create_table(
        "crawler_targets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("identifier", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(255)),
        sa.Column("config", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_status", sa.String(40)),
        sa.Column("last_run_summary", JSONB),
        sa.Column("consecutive_failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "organization_id", "kind", "identifier",
            name="uq_crawler_targets_org_kind_identifier",
        ),
        sa.CheckConstraint(
            "kind IN ('tor_forum','tor_marketplace','i2p_eepsite','lokinet_site',"
            "'telegram_channel','matrix_room','forum','ransomware_leak_group',"
            "'stealer_marketplace')",
            name="ck_crawler_targets_kind",
        ),
    )
    op.create_index("ix_crawler_targets_organization_id", "crawler_targets", ["organization_id"])
    op.create_index("ix_crawler_targets_kind", "crawler_targets", ["kind"])

    op.create_table(
        "feed_health",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("feed_name", sa.String(80), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("detail", sa.String(1024)),
        sa.Column("rows_ingested", sa.Integer, nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint(
            "status IN ('ok','unconfigured','auth_error','network_error',"
            "'rate_limited','parse_error','disabled')",
            name="ck_feed_health_status",
        ),
    )
    op.create_index("ix_feed_health_organization_id", "feed_health", ["organization_id"])
    op.create_index("ix_feed_health_feed_name", "feed_health", ["feed_name"])
    op.create_index("ix_feed_health_status", "feed_health", ["status"])
    op.create_index("ix_feed_health_observed_at", "feed_health", ["observed_at"])
    op.create_index("ix_feed_health_feed_observed", "feed_health", ["feed_name", "observed_at"])

    op.create_table(
        "subsidiary_allowlist",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("note", sa.String(1024)),
        sa.Column("added_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "organization_id", "kind", "value",
            name="uq_subsidiary_allowlist_org_kind_value",
        ),
        sa.CheckConstraint(
            "kind IN ('domain','brand_name','email_domain')",
            name="ck_subsidiary_allowlist_kind",
        ),
    )
    op.create_index(
        "ix_subsidiary_allowlist_organization_id",
        "subsidiary_allowlist",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_subsidiary_allowlist_organization_id", table_name="subsidiary_allowlist")
    op.drop_table("subsidiary_allowlist")

    op.drop_index("ix_feed_health_feed_observed", table_name="feed_health")
    op.drop_index("ix_feed_health_observed_at", table_name="feed_health")
    op.drop_index("ix_feed_health_status", table_name="feed_health")
    op.drop_index("ix_feed_health_feed_name", table_name="feed_health")
    op.drop_index("ix_feed_health_organization_id", table_name="feed_health")
    op.drop_table("feed_health")

    op.drop_index("ix_crawler_targets_kind", table_name="crawler_targets")
    op.drop_index("ix_crawler_targets_organization_id", table_name="crawler_targets")
    op.drop_table("crawler_targets")

    op.drop_index("ix_app_settings_organization_id", table_name="app_settings")
    op.drop_table("app_settings")
