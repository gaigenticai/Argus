"""Add playbook_* values to the ``audit_action`` enum.

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-05-04

The Python ``AuditAction`` enum gained 6 values for the exec-briefing
playbook execution layer (preview / execute / approve / deny /
step_advance / cancel) but the Postgres enum was created back at
``ee318fa0cd70`` and didn't know about them. Without this migration,
every audit_log write from the playbook routes blows up with::

    invalid input value for enum audit_action: "playbook_preview"

``ADD VALUE IF NOT EXISTS`` is idempotent, so re-running this is a
no-op on a DB that already has the values.
"""
from __future__ import annotations

from alembic import op


revision = "c2d3e4f5a6b7"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


_NEW_VALUES = (
    "playbook_preview",
    "playbook_execute",
    "playbook_approve",
    "playbook_deny",
    "playbook_step_advance",
    "playbook_cancel",
)


def upgrade() -> None:
    conn = op.get_bind()
    for v in _NEW_VALUES:
        # Each ALTER TYPE ADD VALUE must be its own statement under
        # asyncpg/psycopg — Postgres disallows multiple in a single
        # transactional batch.
        conn.exec_driver_sql(
            f"ALTER TYPE audit_action ADD VALUE IF NOT EXISTS '{v}'"
        )


def downgrade() -> None:
    # Postgres has no DROP VALUE for enum types; removing a value
    # requires recreating the enum and casting every column referencing
    # it. Done by hand if ever needed.
    pass
