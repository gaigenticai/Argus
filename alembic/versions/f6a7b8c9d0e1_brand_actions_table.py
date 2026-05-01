"""brand_actions — Brand Defender agent runs

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-04-30

Second agentic loop: when a SuspectDomain lands with high similarity
to a registered brand term, the Brand Defender agent gathers signals
(live probe, logo match, WHOIS, subsidiary allowlist) and recommends
an action (``takedown_now`` / ``takedown_after_review`` / ``monitor`` /
``dismiss_subsidiary`` / ``insufficient_data``).

Same persistence shape as ``investigations`` so the dashboard renders
both with the same trace UI; difference is the recommendation column
replaces severity_assessment.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sa.Enum(
        "queued", "running", "completed", "failed",
        name="brand_action_status",
    ).create(op.get_bind(), checkfirst=True)
    sa.Enum(
        "takedown_now",
        "takedown_after_review",
        "dismiss_subsidiary",
        "monitor",
        "insufficient_data",
        name="brand_action_recommendation",
    ).create(op.get_bind(), checkfirst=True)

    op.create_table(
        "brand_actions",
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
            nullable=False,
        ),
        sa.Column(
            "suspect_domain_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("suspect_domains.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "takedown_ticket_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("takedown_tickets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                "queued", "running", "completed", "failed",
                name="brand_action_status",
                create_type=False,
            ),
            nullable=False,
            server_default="queued",
        ),
        sa.Column(
            "recommendation",
            postgresql.ENUM(
                "takedown_now",
                "takedown_after_review",
                "dismiss_subsidiary",
                "monitor",
                "insufficient_data",
                name="brand_action_recommendation",
                create_type=False,
            ),
            nullable=True,
        ),
        sa.Column("recommendation_reason", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "risk_signals",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default=sa.text("ARRAY[]::varchar[]"),
        ),
        sa.Column("suggested_partner", sa.String(80), nullable=True),
        sa.Column("iterations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("trace", postgresql.JSONB(), nullable=True),
        sa.Column("model_id", sa.String(100), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
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
    op.create_index("ix_brand_actions_suspect", "brand_actions", ["suspect_domain_id"])
    op.create_index(
        "ix_brand_actions_org_status",
        "brand_actions",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_brand_actions_status_created",
        "brand_actions",
        ["status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_brand_actions_status_created", table_name="brand_actions")
    op.drop_index("ix_brand_actions_org_status", table_name="brand_actions")
    op.drop_index("ix_brand_actions_suspect", table_name="brand_actions")
    op.drop_table("brand_actions")
    sa.Enum(name="brand_action_recommendation").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="brand_action_status").drop(op.get_bind(), checkfirst=True)
