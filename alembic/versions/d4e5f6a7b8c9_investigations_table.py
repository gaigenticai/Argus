"""Investigations — agentic investigation runs

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-04-30

Adds the ``investigations`` table that stores one row per execution of
``src.agents.investigation_agent.InvestigationAgent``. The agent is the
first genuinely tool-calling, multi-step feature in Argus; persisting
the run means analysts can audit what the agent did, replay traces,
and (later) feed corrections back to a retrained classifier.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Status enum is shared with the model; keep the values in sync.
    investigation_status = postgresql.ENUM(
        "queued", "running", "completed", "failed",
        name="investigation_status",
        create_type=False,  # we create it explicitly below for clean rollback
    )
    sa.Enum(
        "queued", "running", "completed", "failed",
        name="investigation_status",
    ).create(op.get_bind(), checkfirst=True)

    op.create_table(
        "investigations",
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
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "status",
            investigation_status,
            nullable=False,
            server_default="queued",
        ),
        sa.Column("final_assessment", sa.Text(), nullable=True),
        sa.Column("severity_assessment", sa.String(20), nullable=True),
        sa.Column(
            "correlated_iocs",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default=sa.text("ARRAY[]::varchar[]"),
        ),
        sa.Column(
            "correlated_actors",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default=sa.text("ARRAY[]::varchar[]"),
        ),
        sa.Column(
            "recommended_actions",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default=sa.text("ARRAY[]::varchar[]"),
        ),
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
    op.create_index("ix_investigations_alert", "investigations", ["alert_id"])
    op.create_index(
        "ix_investigations_org_status",
        "investigations",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_investigations_status_created",
        "investigations",
        ["status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_investigations_status_created", table_name="investigations")
    op.drop_index("ix_investigations_org_status", table_name="investigations")
    op.drop_index("ix_investigations_alert", table_name="investigations")
    op.drop_table("investigations")
    sa.Enum(name="investigation_status").drop(op.get_bind(), checkfirst=True)
