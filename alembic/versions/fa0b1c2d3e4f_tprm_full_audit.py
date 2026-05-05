"""TPRM full audit: tier/category, evidence vault, contracts, score history,
sanctions, posture signals, immutable questionnaire snapshots.

Revision ID: fa0b1c2d3e4f
Revises: f9b0c1d2e3f4
Create Date: 2026-05-04

Adds the schema needed for the third-party risk audit's prio-1..3 fixes:

  * ``questionnaire_instances.template_version`` + ``template_hash`` for
    immutable per-instance template snapshots (audit reproducibility).
  * ``vendor_evidence_files`` — uploaded PDFs / SOC2 reports keyed by
    vendor + question, with SHA256 + MinIO key.
  * ``vendor_contracts`` — uploaded contracts + extracted clauses.
  * ``vendor_sanctions_checks`` — OFAC / OFSI / EU lookups with verdict.
  * ``vendor_posture_signals`` — DMARC / GitHub leaks / HIBP / nuclei
    findings rolled up per vendor for the scorecard's evidence dict.
  * ``vendor_scorecard_snapshots`` — historical scores for trend lines.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "fa0b1c2d3e4f"
down_revision = "f9b0c1d2e3f4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Questionnaire immutability snapshot --------------------------
    op.add_column(
        "questionnaire_instances",
        sa.Column("template_version", sa.Integer(), nullable=True),
    )
    op.add_column(
        "questionnaire_instances",
        sa.Column("template_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "questionnaire_instances",
        sa.Column(
            "template_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )

    # --- Evidence files vault -----------------------------------------
    op.create_table(
        "vendor_evidence_files",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vendor_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "questionnaire_instance_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("question_id", sa.String(length=80), nullable=True),
        sa.Column("file_name", sa.String(length=500), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("mime_type", sa.String(length=120), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_key", sa.String(length=500), nullable=False),
        sa.Column("uploaded_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "extracted",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["vendor_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["questionnaire_instance_id"],
            ["questionnaire_instances.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_vendor_evidence_vendor",
        "vendor_evidence_files",
        ["vendor_asset_id"],
    )
    op.create_index(
        "ix_vendor_evidence_sha",
        "vendor_evidence_files",
        ["sha256"],
    )

    # --- Contract vault -----------------------------------------------
    op.create_table(
        "vendor_contracts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vendor_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("contract_kind", sa.String(length=64), nullable=True),
        sa.Column("file_name", sa.String(length=500), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_key", sa.String(length=500), nullable=False),
        sa.Column("effective_date", sa.Date(), nullable=True),
        sa.Column("expiration_date", sa.Date(), nullable=True),
        sa.Column(
            "extracted_clauses",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("uploaded_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["vendor_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["uploaded_by_user_id"], ["users.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_vendor_contracts_vendor",
        "vendor_contracts",
        ["vendor_asset_id"],
    )

    # --- Sanctions checks ---------------------------------------------
    op.create_table(
        "vendor_sanctions_checks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vendor_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        # source = ofac | ofsi | eu_consolidated | un
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("matched", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("match_score", sa.Float(), nullable=True),  # 0..1 fuzzy
        sa.Column(
            "match_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["vendor_asset_id"], ["assets.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_vendor_sanctions_vendor",
        "vendor_sanctions_checks",
        ["vendor_asset_id"],
    )
    op.create_index(
        "ix_vendor_sanctions_matched",
        "vendor_sanctions_checks",
        ["matched"],
    )

    # --- Posture signals (DMARC/GitHub/HIBP/typosquat rollup) --------
    op.create_table(
        "vendor_posture_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vendor_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        # kind = dmarc | spf | dkim | hibp | github_leak | nuclei | typosquat | sanctions
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),  # 0..100
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["vendor_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "vendor_asset_id", "kind", name="uq_vendor_posture_kind"
        ),
    )
    op.create_index(
        "ix_vendor_posture_vendor",
        "vendor_posture_signals",
        ["vendor_asset_id"],
    )

    # --- Scorecard snapshots (historical) -----------------------------
    op.create_table(
        "vendor_scorecard_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vendor_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("grade", sa.String(length=4), nullable=False),
        sa.Column(
            "pillar_scores",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["vendor_asset_id"], ["assets.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_vendor_snapshot_vendor_at",
        "vendor_scorecard_snapshots",
        ["vendor_asset_id", "snapshot_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_vendor_snapshot_vendor_at", table_name="vendor_scorecard_snapshots")
    op.drop_table("vendor_scorecard_snapshots")
    op.drop_index("ix_vendor_posture_vendor", table_name="vendor_posture_signals")
    op.drop_table("vendor_posture_signals")
    op.drop_index("ix_vendor_sanctions_matched", table_name="vendor_sanctions_checks")
    op.drop_index("ix_vendor_sanctions_vendor", table_name="vendor_sanctions_checks")
    op.drop_table("vendor_sanctions_checks")
    op.drop_index("ix_vendor_contracts_vendor", table_name="vendor_contracts")
    op.drop_table("vendor_contracts")
    op.drop_index("ix_vendor_evidence_sha", table_name="vendor_evidence_files")
    op.drop_index("ix_vendor_evidence_vendor", table_name="vendor_evidence_files")
    op.drop_table("vendor_evidence_files")
    op.drop_column("questionnaire_instances", "template_snapshot")
    op.drop_column("questionnaire_instances", "template_hash")
    op.drop_column("questionnaire_instances", "template_version")
