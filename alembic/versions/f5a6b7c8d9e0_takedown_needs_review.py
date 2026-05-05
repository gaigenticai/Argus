"""Add ``needs_review`` + ``last_partner_state`` to ``takedown_tickets``.

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-05-04

When the ``/takedown/tickets/{id}/sync`` endpoint receives a
partner_state string the heuristic mapper doesn't recognise, the
ticket's main ``state`` stays unchanged and only a note line gets
appended — silent stall in production. With this migration the sync
endpoint flips ``needs_review=True`` and stores the raw partner
state in ``last_partner_state`` so the dashboard can render a
yellow "needs review" badge that the analyst can act on without
having to read the notes column.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "f5a6b7c8d9e0"
down_revision = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "takedown_tickets",
        sa.Column(
            "needs_review",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "takedown_tickets",
        sa.Column("last_partner_state", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("takedown_tickets", "last_partner_state")
    op.drop_column("takedown_tickets", "needs_review")
