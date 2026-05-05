"""Link PlaybookExecution to a case + copilot run.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-05-04

The Case Copilot needs to queue investigation playbooks (whois,
live_probe, cert_transparency, single-domain takedown, siem_pivot)
against an open case. To surface those queued runs in the case detail
view we add ``case_id`` + ``copilot_run_id`` foreign keys plus a
``case_copilot`` value on the ``playbook_trigger`` enum so an auditor
can later filter "every execution that came from a copilot run."

Both new columns are nullable — existing org-scoped briefing/manual
runs keep ``case_id=NULL`` and ``copilot_run_id=NULL``. ``ON DELETE
SET NULL`` so deleting a case (or a copilot run) doesn't take its
audit trail with it.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # 1) Extend the trigger enum.
    bind.exec_driver_sql(
        "ALTER TYPE playbook_trigger ADD VALUE IF NOT EXISTS 'case_copilot'"
    )

    # 2) Add FK columns. We use SET NULL so deleting a case doesn't
    # destroy the immutable audit trail of what was attempted on it.
    op.add_column(
        "playbook_executions",
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "playbook_executions",
        sa.Column(
            "copilot_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "case_copilot_runs.id", ondelete="SET NULL"
            ),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_playbook_exec_case_created",
        "playbook_executions",
        ["case_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_playbook_exec_case_created",
        table_name="playbook_executions",
    )
    op.drop_column("playbook_executions", "copilot_run_id")
    op.drop_column("playbook_executions", "case_id")
    # Postgres has no DROP VALUE on enums; the case_copilot label
    # stays in the type and is harmless if no rows reference it.
