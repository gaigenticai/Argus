"""Investigations — link to Case via case_id FK

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-04-30

Add nullable ``case_id`` to ``investigations`` so a completed
investigation verdict can be promoted into a Case. ``ON DELETE SET
NULL`` keeps the historical investigation visible even if the
analyst eventually deletes the case.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("case_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "investigations_case_id_fkey",
        "investigations",
        "cases",
        ["case_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_investigations_case", "investigations", ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_investigations_case", table_name="investigations")
    op.drop_constraint(
        "investigations_case_id_fkey", "investigations", type_="foreignkey"
    )
    op.drop_column("investigations", "case_id")
