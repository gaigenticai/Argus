"""audit_logs before/after columns + extended legal-hold coverage

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-04-29

Two related changes that together close audit findings #21 and #22:

1. ``audit_logs.before_state`` and ``audit_logs.after_state`` JSONB
   columns. The previous ``details`` blob was where mutators stuffed
   ``{"before": …, "after": …}``, which works but doesn't let
   compliance auditors run an indexed query for "every change to row
   X". Dedicated columns fix that.

2. ``legal_hold`` BOOLEAN columns on the high-volume detector tables
   that were previously unprotected: ``alerts``, ``raw_intel``,
   ``iocs``, ``exposure_findings``, ``suspect_domains``,
   ``impersonation_findings``, ``mobile_app_findings``,
   ``fraud_findings``, ``card_leakage_findings``, ``dlp_findings``,
   ``dmarc_reports``, ``sla_breach_events``, ``news_articles``,
   ``live_probes``. Partial indices (WHERE legal_hold = true) keep
   the lookup cheap. The retention engine consults these on every
   delete so a held row survives even when its retention window
   would otherwise prune it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


_HOLD_TABLES = (
    "alerts",
    "raw_intel",
    "iocs",
    "exposure_findings",
    "suspect_domains",
    "impersonation_findings",
    "mobile_app_findings",
    "fraud_findings",
    "card_leakage_findings",
    "dlp_findings",
    "dmarc_reports",
    "sla_breach_events",
    "news_articles",
    "live_probes",
)


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("before_state", JSONB, nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("after_state", JSONB, nullable=True),
    )
    # Note: ``ix_audit_logs_resource`` (resource_type, resource_id) is
    # already created by migration 4c5412a6bada. The duplicate
    # ``op.create_index`` here used to fail on a fresh DB with
    # "relation already exists" — removed.

    for table in _HOLD_TABLES:
        op.add_column(
            table,
            sa.Column(
                "legal_hold",
                sa.Boolean,
                nullable=False,
                server_default=sa.false(),
            ),
        )
        op.create_index(
            f"ix_{table}_legal_hold",
            table,
            ["legal_hold"],
            postgresql_where=sa.text("legal_hold = true"),
        )


def downgrade() -> None:
    for table in _HOLD_TABLES:
        op.drop_index(f"ix_{table}_legal_hold", table_name=table)
        op.drop_column(table, "legal_hold")
    # ``ix_audit_logs_resource`` is owned by 4c5412a6bada — leave it.
    op.drop_column("audit_logs", "after_state")
    op.drop_column("audit_logs", "before_state")
