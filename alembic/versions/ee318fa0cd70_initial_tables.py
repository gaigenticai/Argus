"""initial tables

Revision ID: ee318fa0cd70
Revises:
Create Date: 2026-03-09

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "ee318fa0cd70"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable pgvector extension
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # Enum types
    source_type = postgresql.ENUM(
        "tor_forum",
        "tor_marketplace",
        "paste_site",
        "telegram",
        "github",
        "cve_feed",
        "surface_web",
        "social_media",
        name="source_type",
        create_type=False,
    )
    threat_category = postgresql.ENUM(
        "credential_leak",
        "data_breach",
        "vulnerability",
        "exploit",
        "ransomware",
        "phishing",
        "impersonation",
        "doxxing",
        "insider_threat",
        "brand_abuse",
        "dark_web_mention",
        "paste_leak",
        "code_leak",
        name="threat_category",
        create_type=False,
    )
    threat_severity = postgresql.ENUM(
        "critical",
        "high",
        "medium",
        "low",
        "info",
        name="threat_severity",
        create_type=False,
    )
    alert_status = postgresql.ENUM(
        "new",
        "triaged",
        "investigating",
        "confirmed",
        "false_positive",
        "resolved",
        name="alert_status",
        create_type=False,
    )

    source_type.create(op.get_bind(), checkfirst=True)
    threat_category.create(op.get_bind(), checkfirst=True)
    threat_severity.create(op.get_bind(), checkfirst=True)
    alert_status.create(op.get_bind(), checkfirst=True)

    # --- organizations ---
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("domains", postgresql.ARRAY(sa.String), server_default="{}"),
        sa.Column("keywords", postgresql.ARRAY(sa.String), server_default="{}"),
        sa.Column("industry", sa.String(100), nullable=True),
        sa.Column("tech_stack", postgresql.JSONB, nullable=True),
        sa.Column("settings", postgresql.JSONB, nullable=True),
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

    # --- vip_targets ---
    op.create_table(
        "vip_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("emails", postgresql.ARRAY(sa.String), server_default="{}"),
        sa.Column("usernames", postgresql.ARRAY(sa.String), server_default="{}"),
        sa.Column("phone_numbers", postgresql.ARRAY(sa.String), server_default="{}"),
        sa.Column("keywords", postgresql.ARRAY(sa.String), server_default="{}"),
        sa.Column("social_profiles", postgresql.JSONB, nullable=True),
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

    # --- assets ---
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("asset_type", sa.String(50), nullable=True),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("true")),
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
    op.create_index("ix_assets_org_type", "assets", ["organization_id", "asset_type"])
    op.create_index("ix_assets_value", "assets", ["value"])

    # --- raw_intel ---
    op.create_table(
        "raw_intel",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_type", source_type, nullable=False),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("source_name", sa.String(255), nullable=True),
        sa.Column("title", sa.Text, nullable=True),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("author", sa.String(255), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_data", postgresql.JSONB, nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("is_processed", sa.Boolean, server_default=sa.text("false")),
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

    # pgvector column — use raw SQL since alembic doesn't natively know the vector type
    op.execute("ALTER TABLE raw_intel ADD COLUMN IF NOT EXISTS embedding vector(1536)")

    op.create_index("ix_raw_intel_source", "raw_intel", ["source_type", "is_processed"])
    op.create_index("ix_raw_intel_hash", "raw_intel", ["content_hash"])

    # --- alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column(
            "raw_intel_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("raw_intel.id"),
            nullable=True,
        ),
        sa.Column("category", threat_category, nullable=False),
        sa.Column("severity", threat_severity, nullable=False),
        sa.Column("status", alert_status, server_default=sa.text("'new'")),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("details", postgresql.JSONB, nullable=True),
        sa.Column("matched_entities", postgresql.JSONB, nullable=True),
        sa.Column("confidence", sa.Float, server_default=sa.text("0.0")),
        sa.Column("agent_reasoning", sa.Text, nullable=True),
        sa.Column("recommended_actions", postgresql.JSONB, nullable=True),
        sa.Column("analyst_notes", sa.Text, nullable=True),
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
    op.create_index("ix_alerts_org_severity", "alerts", ["organization_id", "severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("raw_intel")
    op.drop_table("assets")
    op.drop_table("vip_targets")
    op.drop_table("organizations")

    op.execute("DROP TYPE IF EXISTS alert_status")
    op.execute("DROP TYPE IF EXISTS threat_severity")
    op.execute("DROP TYPE IF EXISTS threat_category")
    op.execute("DROP TYPE IF EXISTS source_type")

    op.execute("DROP EXTENSION IF EXISTS vector")
