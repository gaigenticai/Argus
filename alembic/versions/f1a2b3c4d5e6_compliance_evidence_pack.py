"""Compliance Evidence Pack tables (P1 #1.3).

Five tables backing the OSCAL-based Compliance Evidence Pack exporter:

Global lookup (no organization_id, no RLS):
  - compliance_frameworks       — NCA-ECC, SAMA-CSF, ISO 27001 A.5.7, NIST CSF 2.0, …
  - compliance_controls         — individual controls per framework, hierarchical
  - compliance_control_mappings — links signal types (alert_category /
                                  mitre_technique / case_state / tag) to controls

Tenant-scoped (organization_id, RLS via app.current_org GUC):
  - compliance_evidence         — captured evidence entries linking a tenant's
                                  alerts/cases/findings to a control
  - compliance_exports          — tenant-requested OSCAL/PDF export jobs and
                                  their generated artifact metadata

Retention:
  - compliance_exports: hard expiry via expires_at column (default 365
    days, set in src/api/routes/compliance.py at create-export time).
    The artifact bytes live in MinIO under
    compliance/<org_id>/<export_id>.<ext>; lifecycle is operator-managed
    rather than swept by the time-based retention worker — regulators
    require deliberate retention of compliance evidence (NCA-ECC,
    SAMA-CSF 2y for regulated banks).
  - compliance_evidence: rows are deduped on (org, framework, control,
    source_kind, source_id) by the mapper at export time and otherwise
    untouched. ``source_id`` is polymorphic (alerts / cases / findings)
    so cross-row purge would need either a polymorphic FK CASCADE (not
    portable) or a dedicated retention bucket — both deferred to a
    future phase. Today the table grows monotonically; the row count is
    bounded by (alerts_in_window × controls_per_alert) per export.

Revision ID: f1a2b3c4d5e6
Revises: e9f0a1b2c3d4
Create Date: 2026-05-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, None] = "e9f0a1b2c3d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TENANT_TABLES = ("compliance_evidence", "compliance_exports")


def upgrade() -> None:
    op.create_table(
        "compliance_frameworks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name_en", sa.String(255), nullable=False),
        sa.Column("name_ar", sa.String(255), nullable=True),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("source_url", sa.String(512), nullable=True),
        sa.Column("source_version_date", sa.Date(), nullable=True),
        sa.Column("description_en", sa.Text(), nullable=True),
        sa.Column("description_ar", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )

    op.create_table(
        "compliance_controls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("parent_control_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("compliance_controls.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("title_en", sa.Text(), nullable=False),
        sa.Column("title_ar", sa.Text(), nullable=True),
        sa.Column("description_en", sa.Text(), nullable=True),
        sa.Column("description_ar", sa.Text(), nullable=True),
        sa.Column("weight", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("framework_id", "control_id",
                            name="uq_compliance_controls_framework_ctrl"),
    )
    op.create_index("ix_compliance_controls_framework_sort",
                    "compliance_controls", ["framework_id", "sort_order"])

    op.create_table(
        "compliance_control_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("control_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("signal_kind", sa.String(32), nullable=False),
        sa.Column("signal_value", sa.String(128), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("control_id", "signal_kind", "signal_value",
                            name="uq_compliance_mappings_ctrl_kind_val"),
        sa.CheckConstraint(
            "signal_kind IN ('alert_category','mitre_technique','case_state','tag')",
            name="ck_compliance_mappings_signal_kind",
        ),
    )
    op.create_index("ix_compliance_mappings_signal",
                    "compliance_control_mappings", ["signal_kind", "signal_value"])

    op.create_table(
        "compliance_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary_en", sa.Text(), nullable=True),
        sa.Column("summary_ar", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'active'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint(
            "source_kind IN ('alert','case','finding','manual')",
            name="ck_compliance_evidence_source_kind",
        ),
        sa.CheckConstraint(
            "status IN ('active','archived','superseded')",
            name="ck_compliance_evidence_status",
        ),
    )
    op.create_index(
        "ix_compliance_evidence_org_framework_captured",
        "compliance_evidence",
        ["organization_id", "framework_id", sa.text("captured_at DESC")],
    )
    op.create_index(
        "ix_compliance_evidence_org_control",
        "compliance_evidence",
        ["organization_id", "control_id"],
    )
    op.create_index(
        "ix_compliance_evidence_source",
        "compliance_evidence",
        ["source_kind", "source_id"],
    )

    op.create_table(
        "compliance_exports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("framework_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("compliance_frameworks.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("language_mode", sa.String(16), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("period_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("period_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("object_storage_key", sa.String(512), nullable=True),
        sa.Column("hash_sha256", sa.String(64), nullable=True),
        sa.Column("byte_size", sa.BigInteger(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now() + interval '365 days'")),
        sa.CheckConstraint(
            "language_mode IN ('en','ar','bilingual')",
            name="ck_compliance_exports_language_mode",
        ),
        sa.CheckConstraint(
            "format IN ('pdf','json')",
            name="ck_compliance_exports_format",
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','completed','failed','expired')",
            name="ck_compliance_exports_status",
        ),
    )
    op.create_index(
        "ix_compliance_exports_org_created",
        "compliance_exports",
        ["organization_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "ix_compliance_exports_active_status",
        "compliance_exports",
        ["status"],
        postgresql_where=sa.text("status IN ('pending','running')"),
    )
    op.create_index(
        "ix_compliance_exports_expires",
        "compliance_exports",
        ["expires_at"],
        postgresql_where=sa.text("status NOT IN ('expired','failed')"),
    )

    # RLS — mirrors pattern in 7f9c1b22a8e3_rls_tenant_scoped_tables.py.
    # Policy is permissive when the GUC is unset (allows migrations,
    # tests, admin SQL) and constrains to the GUC org otherwise.
    for t in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY {t}_tenant_isolation ON {t}
                USING (
                    NULLIF(current_setting('app.current_org', true), '') IS NULL
                    OR organization_id = NULLIF(current_setting('app.current_org', true), '')::uuid
                )
                WITH CHECK (
                    NULLIF(current_setting('app.current_org', true), '') IS NULL
                    OR organization_id = NULLIF(current_setting('app.current_org', true), '')::uuid
                );
            """
        )


def downgrade() -> None:
    for t in _TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t};")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY;")

    op.drop_index("ix_compliance_exports_expires", table_name="compliance_exports")
    op.drop_index("ix_compliance_exports_active_status", table_name="compliance_exports")
    op.drop_index("ix_compliance_exports_org_created", table_name="compliance_exports")
    op.drop_table("compliance_exports")

    op.drop_index("ix_compliance_evidence_source", table_name="compliance_evidence")
    op.drop_index("ix_compliance_evidence_org_control", table_name="compliance_evidence")
    op.drop_index("ix_compliance_evidence_org_framework_captured",
                  table_name="compliance_evidence")
    op.drop_table("compliance_evidence")

    op.drop_index("ix_compliance_mappings_signal",
                  table_name="compliance_control_mappings")
    op.drop_table("compliance_control_mappings")

    op.drop_index("ix_compliance_controls_framework_sort",
                  table_name="compliance_controls")
    op.drop_table("compliance_controls")

    op.drop_table("compliance_frameworks")
