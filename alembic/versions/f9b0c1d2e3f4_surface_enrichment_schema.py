"""Surface enrichment schema: add SCREENSHOT/DNS_DETAIL job kinds + asset
risk-score columns + asset auto-classification fields.

Revision ID: f9b0c1d2e3f4
Revises: f8a9b0c1d2e3
Create Date: 2026-05-04

Adds:
  * Two new ``discovery_job_kind`` enum values for the gowitness +
    dnsx runners.
  * ``assets.risk_score`` (Float, nullable) — composite of
    exploitability × accessibility × age × criticality, written by the
    risk-score sweep.
  * ``assets.risk_score_updated_at`` — when the score was last computed.
  * ``assets.ai_classification`` — JSONB; auto-classifier agent output
    (env=prod/staging, role=admin/marketing, etc.) plus confidence.
  * ``assets.ai_classified_at`` — timestamp.

All columns nullable; existing assets read as NULL until the sweep
populates them.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "f9b0c1d2e3f4"
down_revision = "f8a9b0c1d2e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # New job kinds for the post-discovery pipeline.
    op.execute(
        "ALTER TYPE discovery_job_kind ADD VALUE IF NOT EXISTS 'screenshot'"
    )
    op.execute(
        "ALTER TYPE discovery_job_kind ADD VALUE IF NOT EXISTS 'dns_detail'"
    )

    # Asset risk score + AI classification fields.
    op.add_column(
        "assets",
        sa.Column("risk_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("risk_score_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column(
            "ai_classification",
            sa.dialects.postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.add_column(
        "assets",
        sa.Column("ai_classified_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_index("ix_assets_risk_score", "assets", ["risk_score"])


def downgrade() -> None:
    op.drop_index("ix_assets_risk_score", table_name="assets")
    op.drop_column("assets", "ai_classified_at")
    op.drop_column("assets", "ai_classification")
    op.drop_column("assets", "risk_score_updated_at")
    op.drop_column("assets", "risk_score")
    # Note: Postgres can't drop enum values without recreating the type,
    # so down-migration leaves screenshot/dns_detail in the enum. Safe —
    # they won't be referenced once the column drops.
