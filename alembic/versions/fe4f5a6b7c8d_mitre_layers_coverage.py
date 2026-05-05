"""mitre layer persistence + per-org technique coverage

Adds:
  * mitre_layers — saved Navigator-style layers (custom scores per technique)
  * mitre_technique_coverage — per-org coverage state for the heatmap
                               (covered_by: sigma|yara|edr|manual)

Revision ID: fe4f5a6b7c8d
Revises: fd3e4f5a6b7c
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fe4f5a6b7c8d"
down_revision = "fd3e4f5a6b7c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mitre_layers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("matrix", sa.String(20), nullable=False, server_default="enterprise"),
        sa.Column(
            "technique_scores",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "color_palette",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{\"low\": \"#FFE0B2\", \"med\": \"#FFAB00\", \"high\": \"#FF5630\"}'::jsonb"),
        ),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_mitre_layers_org", "mitre_layers", ["organization_id"])

    op.create_table(
        "mitre_technique_coverage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("matrix", sa.String(20), nullable=False, server_default="enterprise"),
        sa.Column("technique_external_id", sa.String(20), nullable=False),
        sa.Column(
            "covered_by",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("notes", sa.Text),
        sa.Column("updated_by_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "organization_id", "matrix", "technique_external_id",
            name="uq_mitre_coverage_org_tech",
        ),
    )
    op.create_index(
        "ix_mitre_coverage_org_tech",
        "mitre_technique_coverage",
        ["organization_id", "technique_external_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_mitre_coverage_org_tech", table_name="mitre_technique_coverage")
    op.drop_table("mitre_technique_coverage")
    op.drop_index("ix_mitre_layers_org", table_name="mitre_layers")
    op.drop_table("mitre_layers")
