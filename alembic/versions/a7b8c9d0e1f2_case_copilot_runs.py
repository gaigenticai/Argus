"""case_copilot_runs — Case Copilot agent runs

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-04-30

Third agentic loop. Triggered manually by an analyst opening a case;
the agent suggests a starter timeline, MITRE attachments, and
playbook next steps. Output stays advisory until the analyst clicks
"Apply" — the agent never edits the case directly.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sa.Enum(
        "queued", "running", "completed", "failed",
        name="case_copilot_status",
    ).create(op.get_bind(), checkfirst=True)

    op.create_table(
        "case_copilot_runs",
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
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                "queued", "running", "completed", "failed",
                name="case_copilot_status",
                create_type=False,
            ),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("timeline_events", postgresql.JSONB(), nullable=True),
        sa.Column("suggested_mitre_ids", postgresql.JSONB(), nullable=True),
        sa.Column("draft_next_steps", postgresql.JSONB(), nullable=True),
        sa.Column("similar_case_ids", postgresql.JSONB(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "applied_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
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
    op.create_index("ix_case_copilot_case", "case_copilot_runs", ["case_id"])
    op.create_index(
        "ix_case_copilot_org_status",
        "case_copilot_runs",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_case_copilot_status_created",
        "case_copilot_runs",
        ["status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_case_copilot_status_created", table_name="case_copilot_runs")
    op.drop_index("ix_case_copilot_org_status", table_name="case_copilot_runs")
    op.drop_index("ix_case_copilot_case", table_name="case_copilot_runs")
    op.drop_table("case_copilot_runs")
    sa.Enum(name="case_copilot_status").drop(op.get_bind(), checkfirst=True)
