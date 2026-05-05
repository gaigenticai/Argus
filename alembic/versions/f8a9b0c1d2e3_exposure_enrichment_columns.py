"""Exposure enrichment columns: EPSS / KEV / structured remediation / AI triage.

Revision ID: f8a9b0c1d2e3
Revises: e2f3a4b5c6d7
Create Date: 2026-05-04

Adds columns to ``exposure_findings`` so the /exposures page can render
real risk signals (EPSS exploit probability, CISA KEV exploited-in-the-wild
flag), capture structured remediation evidence on state transitions, and
persist outputs from the new AI triage / false-positive-suppression agents.

All columns are nullable (or have safe defaults) so existing rows remain
valid; the worker + endpoints backfill them lazily.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "f8a9b0c1d2e3"
down_revision = "e2f3a4b5c6d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- EPSS / KEV enrichment (P0) ----------------------------------
    op.add_column(
        "exposure_findings",
        sa.Column("epss_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "exposure_findings",
        sa.Column("epss_percentile", sa.Float(), nullable=True),
    )
    op.add_column(
        "exposure_findings",
        sa.Column(
            "is_kev",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "exposure_findings",
        sa.Column("kev_added_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- Structured remediation (P1) ---------------------------------
    op.add_column(
        "exposure_findings",
        sa.Column("remediation_action", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "exposure_findings",
        sa.Column("remediation_patch_version", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "exposure_findings",
        sa.Column("remediation_owner", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "exposure_findings",
        sa.Column("remediation_notes", sa.Text(), nullable=True),
    )

    # --- AI triage outputs (P2) --------------------------------------
    # ai_priority: 0..100 composite score (EPSS × CVSS × KEV × age × asset criticality)
    op.add_column(
        "exposure_findings",
        sa.Column("ai_priority", sa.Float(), nullable=True),
    )
    op.add_column(
        "exposure_findings",
        sa.Column("ai_rationale", sa.Text(), nullable=True),
    )
    op.add_column(
        "exposure_findings",
        sa.Column(
            "ai_triaged_at", sa.DateTime(timezone=True), nullable=True
        ),
    )

    # --- AI false-positive suppression (P2) --------------------------
    op.add_column(
        "exposure_findings",
        sa.Column(
            "ai_suggest_dismiss",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "exposure_findings",
        sa.Column("ai_dismiss_reason", sa.Text(), nullable=True),
    )

    # Indexes for the new sort/filter dimensions.
    op.create_index(
        "ix_exposure_is_kev", "exposure_findings", ["is_kev"]
    )
    op.create_index(
        "ix_exposure_epss_score", "exposure_findings", ["epss_score"]
    )
    op.create_index(
        "ix_exposure_ai_priority", "exposure_findings", ["ai_priority"]
    )

    # Drop server defaults so future inserts go through the model layer's
    # logic without server-side coercion (matches the pattern used by other
    # boolean columns added in past migrations).
    op.alter_column("exposure_findings", "is_kev", server_default=None)
    op.alter_column(
        "exposure_findings", "ai_suggest_dismiss", server_default=None
    )


def downgrade() -> None:
    op.drop_index("ix_exposure_ai_priority", table_name="exposure_findings")
    op.drop_index("ix_exposure_epss_score", table_name="exposure_findings")
    op.drop_index("ix_exposure_is_kev", table_name="exposure_findings")
    op.drop_column("exposure_findings", "ai_dismiss_reason")
    op.drop_column("exposure_findings", "ai_suggest_dismiss")
    op.drop_column("exposure_findings", "ai_triaged_at")
    op.drop_column("exposure_findings", "ai_rationale")
    op.drop_column("exposure_findings", "ai_priority")
    op.drop_column("exposure_findings", "remediation_notes")
    op.drop_column("exposure_findings", "remediation_owner")
    op.drop_column("exposure_findings", "remediation_patch_version")
    op.drop_column("exposure_findings", "remediation_action")
    op.drop_column("exposure_findings", "kev_added_at")
    op.drop_column("exposure_findings", "is_kev")
    op.drop_column("exposure_findings", "epss_percentile")
    op.drop_column("exposure_findings", "epss_score")
