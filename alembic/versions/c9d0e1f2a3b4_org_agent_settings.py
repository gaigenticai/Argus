"""organization_agent_settings — per-org agent toggles

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-04-30
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_agent_settings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column(
            "investigation_enabled", sa.Boolean(), nullable=False, server_default="true"
        ),
        sa.Column(
            "brand_defender_enabled", sa.Boolean(), nullable=False, server_default="true"
        ),
        sa.Column(
            "case_copilot_enabled", sa.Boolean(), nullable=False, server_default="true"
        ),
        sa.Column(
            "threat_hunter_enabled", sa.Boolean(), nullable=False, server_default="true"
        ),
        sa.Column(
            "chain_investigation_to_hunt",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
        sa.Column(
            "auto_promote_critical",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "auto_takedown_high_confidence",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("threat_hunt_interval_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index(
        "ix_org_agent_settings_org",
        "organization_agent_settings",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_org_agent_settings_org",
        table_name="organization_agent_settings",
    )
    op.drop_table("organization_agent_settings")
