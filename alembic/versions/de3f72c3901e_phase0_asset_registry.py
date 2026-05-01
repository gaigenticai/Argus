"""phase 0 — asset registry

Extends the ``assets`` table into a polymorphic registry covering domains,
subdomains, IPs, ranges, services, email-domains, executives, brands,
mobile apps, social handles, vendors, code repos, and cloud accounts.

Adds columns: criticality, tags, monitoring_profile, owner_user_id,
parent_asset_id, discovery_method, discovered_at, verified_at,
last_change_at, monitoring_enabled. Adds GIN index on tags and a
unique constraint on (organization_id, asset_type, value).

Adds new ``audit_action`` enum values for asset lifecycle.

Revision ID: de3f72c3901e
Revises: ee318fa0cd70
Create Date: 2026-04-28
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "de3f72c3901e"
down_revision: Union[str, None] = "ee318fa0cd70"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NEW_AUDIT_ACTIONS = (
    "asset_create",
    "asset_update",
    "asset_delete",
    "asset_bulk_import",
    "asset_discover",
)


def upgrade() -> None:
    bind = op.get_bind()

    # 1) Add new audit_action enum values, but only if the enum already
    #    exists. On fresh installs the enum is created later by SQLAlchemy
    #    metadata.create_all() with the full value list (the auth tables
    #    are not yet in alembic — pre-existing repo state).
    enum_exists = bind.execute(
        sa.text("SELECT 1 FROM pg_type WHERE typname = 'audit_action'")
    ).scalar()
    if enum_exists:
        for action in _NEW_AUDIT_ACTIONS:
            op.execute(
                sa.text(
                    f"ALTER TYPE audit_action ADD VALUE IF NOT EXISTS '{action}'"
                )
            )

    # 2) Add new columns to assets. All nullable=True initially so the migration
    #    is safe on a populated table; we then backfill defaults and tighten.
    op.add_column(
        "assets",
        sa.Column("criticality", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.String()),
            nullable=True,
        ),
    )
    op.add_column(
        "assets",
        sa.Column("monitoring_profile", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column(
            "owner_user_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    # FK to users.id added by the Phase 1-11 catch-up migration which
    # creates the auth tables. Keeping the column FK-less here so Phase 0.1
    # can run before the auth tables exist (pre-existing repo gap).
    op.add_column(
        "assets",
        sa.Column(
            "parent_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.add_column(
        "assets",
        sa.Column("discovery_method", sa.String(length=40), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("last_change_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column(
            "monitoring_enabled",
            sa.Boolean(),
            nullable=True,
            server_default=sa.text("true"),
        ),
    )

    # 3) Backfill defaults for any rows that pre-date the registry.
    op.execute(
        sa.text(
            "UPDATE assets SET "
            "criticality = COALESCE(criticality, 'medium'), "
            "tags = COALESCE(tags, ARRAY[]::text[]), "
            "discovery_method = COALESCE(discovery_method, 'manual'), "
            "monitoring_enabled = COALESCE(monitoring_enabled, TRUE), "
            "discovered_at = COALESCE(discovered_at, created_at)"
        )
    )

    # 4) Tighten constraints now that data is consistent.
    op.alter_column("assets", "criticality", nullable=False)
    op.alter_column("assets", "tags", nullable=False)
    op.alter_column("assets", "discovery_method", nullable=False)
    op.alter_column("assets", "monitoring_enabled", nullable=False)
    op.alter_column("assets", "asset_type", nullable=False)

    # 5) CHECK constraints for enums (Postgres-side defense in depth).
    op.create_check_constraint(
        "ck_assets_criticality",
        "assets",
        "criticality IN ('crown_jewel','high','medium','low')",
    )
    op.create_check_constraint(
        "ck_assets_asset_type",
        "assets",
        "asset_type IN ("
        "'domain','subdomain','ip_address','ip_range','service',"
        "'email_domain','executive','brand','mobile_app','social_handle',"
        "'vendor','code_repository','cloud_account'"
        ")",
    )

    # 6) Unique (organization_id, asset_type, value) — prevents duplicates.
    op.create_index(
        "ix_assets_org_value_type",
        "assets",
        ["organization_id", "asset_type", "value"],
        unique=True,
    )
    op.create_index("ix_assets_criticality", "assets", ["criticality"])
    op.create_index("ix_assets_parent", "assets", ["parent_asset_id"])
    op.create_index(
        "ix_assets_tags",
        "assets",
        ["tags"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_assets_tags", table_name="assets")
    op.drop_index("ix_assets_parent", table_name="assets")
    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_index("ix_assets_org_value_type", table_name="assets")
    op.drop_constraint("ck_assets_asset_type", "assets", type_="check")
    op.drop_constraint("ck_assets_criticality", "assets", type_="check")
    op.drop_column("assets", "monitoring_enabled")
    op.drop_column("assets", "last_change_at")
    op.drop_column("assets", "verified_at")
    op.drop_column("assets", "discovered_at")
    op.drop_column("assets", "discovery_method")
    op.drop_column("assets", "parent_asset_id")
    op.drop_column("assets", "owner_user_id")
    op.drop_column("assets", "monitoring_profile")
    op.drop_column("assets", "tags")
    op.drop_column("assets", "criticality")
    # Note: Postgres doesn't support removing enum values; leave audit_action
    # values in place. They are forward-compatible.
