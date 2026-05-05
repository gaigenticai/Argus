"""Create ``playbook_executions`` for the AI exec-briefing action layer.

Revision ID: b1c2d3e4f5a6
Revises: a9b0c1d2e3f4
Create Date: 2026-05-04

Adds the durable record for operator-initiated runs of catalogued
playbooks (defined in ``src.core.exec_playbooks``). The model lives in
``src.models.playbooks``; this migration creates the two postgres
enums (``playbook_status``, ``playbook_trigger``) plus the table with
its indices.

The catalog itself is in code — there is no ``playbooks`` table. This
matches our existing pattern: ``src.core.service_inventory`` is the
service catalog, which is also code-only.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "b1c2d3e4f5a6"
down_revision = "a9b0c1d2e3f4"
branch_labels = None
depends_on = None


PLAYBOOK_STATUSES = (
    "pending_approval",
    "approved",
    "in_progress",
    "step_complete",
    "completed",
    "failed",
    "denied",
    "cancelled",
)

PLAYBOOK_TRIGGERS = (
    "exec_briefing",
    "manual",
)


def upgrade() -> None:
    playbook_status = postgresql.ENUM(
        *PLAYBOOK_STATUSES, name="playbook_status", create_type=False
    )
    playbook_trigger = postgresql.ENUM(
        *PLAYBOOK_TRIGGERS, name="playbook_trigger", create_type=False
    )

    bind = op.get_bind()
    playbook_status.create(bind, checkfirst=True)
    playbook_trigger.create(bind, checkfirst=True)

    op.create_table(
        "playbook_executions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("playbook_id", sa.String(100), nullable=False),
        sa.Column(
            "status",
            playbook_status,
            nullable=False,
            server_default="pending_approval",
        ),
        sa.Column(
            "params",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("preview_snapshot", postgresql.JSONB, nullable=True),
        sa.Column(
            "current_step_index",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "total_steps",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column(
            "step_results",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "requested_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "approver_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approval_note", sa.Text(), nullable=True),
        sa.Column("denial_reason", sa.Text(), nullable=True),
        sa.Column("idempotency_key", sa.String(100), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "triggered_from",
            playbook_trigger,
            nullable=False,
            server_default="manual",
        ),
        sa.Column("briefing_action_index", sa.Integer(), nullable=True),
        sa.Column(
            "approved_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "completed_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "failed_at", sa.DateTime(timezone=True), nullable=True
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
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_playbook_exec_org_idem",
        ),
    )
    op.create_index(
        "ix_playbook_exec_org_status_created",
        "playbook_executions",
        ["organization_id", "status", "created_at"],
    )
    op.create_index(
        "ix_playbook_exec_org_playbook",
        "playbook_executions",
        ["organization_id", "playbook_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_playbook_exec_org_playbook",
        table_name="playbook_executions",
    )
    op.drop_index(
        "ix_playbook_exec_org_status_created",
        table_name="playbook_executions",
    )
    op.drop_table("playbook_executions")

    bind = op.get_bind()
    postgresql.ENUM(name="playbook_trigger").drop(bind, checkfirst=True)
    postgresql.ENUM(name="playbook_status").drop(bind, checkfirst=True)
