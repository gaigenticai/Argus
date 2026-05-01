"""D3FEND defensive techniques + OSCAL machine-readable controls (P2 #2.12).

Two global lookup tables (no organization_id, no RLS) for the
authoritative MITRE D3FEND defense catalog and the NIST OSCAL control
catalog. Both are append-only ingestion targets — the loader modules in
``src/intel/d3fend.py`` and ``src/compliance/oscal_catalog.py`` upsert
on (catalog, identifier).

Pairs the curated P1 #1.3 framework controls with authoritative source
data so a regulator-facing OSCAL export references the canonical NIST
control identifiers, and an alert detail page can recommend D3FEND
defensive techniques against each attached ATT&CK technique.

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-05-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "a2b3c4d5e6f7"
down_revision: Union[str, None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "d3fend_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("d3fend_id", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("definition", sa.Text(), nullable=True),
        # The defensive-technique tactic in D3FEND's parlance: harden,
        # detect, isolate, deceive, evict, restore, model.
        sa.Column("tactic", sa.String(32), nullable=True),
        # JSON array of MITRE ATT&CK technique IDs this defense
        # counters. Used by the alert detail page to recommend
        # D3FEND defenses given the alert's attached ATT&CK techniques.
        sa.Column("counters_attack_ids", postgresql.JSONB(), nullable=True),
        sa.Column("source_url", sa.String(512), nullable=True),
        sa.Column("source_version", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_d3fend_techniques_tactic",
                    "d3fend_techniques", ["tactic"])

    op.create_table(
        "oscal_catalog_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        # Catalog identifier — e.g. "NIST_SP-800-53_rev5", "NIST_CSF_2.0".
        sa.Column("catalog", sa.String(64), nullable=False),
        # Control identifier within the catalog — "AC-2", "CM-7", etc.
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("statement", sa.Text(), nullable=True),
        # JSON object preserving the full OSCAL control structure
        # (parameters, parts, props) so an exporter can round-trip.
        sa.Column("oscal", postgresql.JSONB(), nullable=True),
        sa.Column("source_url", sa.String(512), nullable=True),
        sa.Column("source_version", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("catalog", "control_id",
                            name="uq_oscal_catalog_control"),
    )
    op.create_index("ix_oscal_catalog_catalog",
                    "oscal_catalog_entries", ["catalog"])


def downgrade() -> None:
    op.drop_index("ix_oscal_catalog_catalog",
                  table_name="oscal_catalog_entries")
    op.drop_table("oscal_catalog_entries")
    op.drop_index("ix_d3fend_techniques_tactic",
                  table_name="d3fend_techniques")
    op.drop_table("d3fend_techniques")
