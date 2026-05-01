"""threat_hunt_runs — Threat Hunter agent runs

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-04-30

Fourth agentic loop. Scheduler-triggered weekly hunt that picks an
active threat-actor cluster and asks "is the org seeing any of their
TTPs?" Findings persist as a JSONB list on the run.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sa.Enum(
        "queued", "running", "completed", "failed",
        name="threat_hunt_status",
    ).create(op.get_bind(), checkfirst=True)

    op.create_table(
        "threat_hunt_runs",
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
            "primary_actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_actors.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("primary_actor_alias", sa.String(255), nullable=True),
        sa.Column(
            "status",
            postgresql.ENUM(
                "queued", "running", "completed", "failed",
                name="threat_hunt_status",
                create_type=False,
            ),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("findings", postgresql.JSONB(), nullable=True),
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
    op.create_index(
        "ix_threat_hunt_org_status",
        "threat_hunt_runs",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_threat_hunt_status_created",
        "threat_hunt_runs",
        ["status", "created_at"],
    )
    op.create_index(
        "ix_threat_hunt_actor",
        "threat_hunt_runs",
        ["primary_actor_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_threat_hunt_actor", table_name="threat_hunt_runs")
    op.drop_index("ix_threat_hunt_status_created", table_name="threat_hunt_runs")
    op.drop_index("ix_threat_hunt_org_status", table_name="threat_hunt_runs")
    op.drop_table("threat_hunt_runs")
    sa.Enum(name="threat_hunt_status").drop(op.get_bind(), checkfirst=True)
