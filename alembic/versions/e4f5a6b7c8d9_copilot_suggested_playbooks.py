"""Add ``suggested_playbooks`` JSONB column to ``case_copilot_runs``.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-05-04

The Case Copilot prompt now emits playbook IDs from the investigation
catalog (whois_lookup, live_probe_capture, cert_transparency_pivot,
submit_takedown_for_suspect, siem_pivot) instead of free-form text in
``draft_next_steps``. ``apply_suggestions`` materialises each entry
as a ``PlaybookExecution`` linked back to the case via the FKs added
in revision d3e4f5a6b7c8.

``draft_next_steps`` stays as the human-readable narrative the
operator can scan ("we'll do X, Y, then Z") — actions live in the
new column. Older runs leave the new column NULL and the apply path
keeps the legacy comment-only behaviour, so backfilling is not needed.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "e4f5a6b7c8d9"
down_revision = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "case_copilot_runs",
        sa.Column(
            "suggested_playbooks",
            postgresql.JSONB,
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("case_copilot_runs", "suggested_playbooks")
