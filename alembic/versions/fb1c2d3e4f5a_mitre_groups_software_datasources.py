"""mitre groups + software + datasources + campaigns

Adds first-class tables for the rest of the ATT&CK STIX bundle so we can
power /actors auto-import, /mitre group/software/datasource pivots, and
/threat-hunter technique-to-actor lookups from a single sync.

Revision ID: fb1c2d3e4f5a
Revises: fa0b1c2d3e4f
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fb1c2d3e4f5a"
down_revision = "fa0b1c2d3e4f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # mitre_groups (G####)
    op.create_table(
        "mitre_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("matrix", sa.String(20), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("description", sa.Text),
        sa.Column("country_codes", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("sectors_targeted", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("regions_targeted", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("references", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("deprecated", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("url", sa.String(500)),
        sa.Column("sync_version", sa.String(50)),
        sa.Column("raw", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("matrix", "external_id", name="uq_mitre_group_matrix_id"),
    )
    op.create_index("ix_mitre_group_external_id", "mitre_groups", ["external_id"])
    op.create_index("ix_mitre_group_aliases", "mitre_groups", ["aliases"],
                    postgresql_using="gin")
    op.create_index("ix_mitre_group_sectors", "mitre_groups", ["sectors_targeted"],
                    postgresql_using="gin")
    op.create_index("ix_mitre_group_regions", "mitre_groups", ["regions_targeted"],
                    postgresql_using="gin")

    # mitre_software (S#### — malware + tools)
    op.create_table(
        "mitre_software",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("matrix", sa.String(20), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("software_type", sa.String(20), nullable=False),  # malware|tool
        sa.Column("description", sa.Text),
        sa.Column("platforms", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("labels", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("references", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("deprecated", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("url", sa.String(500)),
        sa.Column("sync_version", sa.String(50)),
        sa.Column("raw", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("matrix", "external_id", name="uq_mitre_software_matrix_id"),
    )
    op.create_index("ix_mitre_software_external_id", "mitre_software", ["external_id"])
    op.create_index("ix_mitre_software_name", "mitre_software", ["name"])
    op.create_index("ix_mitre_software_aliases", "mitre_software", ["aliases"],
                    postgresql_using="gin")

    # mitre_data_sources (DS####)
    op.create_table(
        "mitre_data_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("matrix", sa.String(20), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("platforms", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("collection_layers", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("data_components", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("url", sa.String(500)),
        sa.Column("sync_version", sa.String(50)),
        sa.Column("raw", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("matrix", "external_id", name="uq_mitre_ds_matrix_id"),
    )

    # mitre_campaigns (C####)
    op.create_table(
        "mitre_campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("matrix", sa.String(20), nullable=False),
        sa.Column("external_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
        sa.Column("description", sa.Text),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("references", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("url", sa.String(500)),
        sa.Column("sync_version", sa.String(50)),
        sa.Column("raw", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("matrix", "external_id", name="uq_mitre_camp_matrix_id"),
    )

    # Relationship tables — unified single junction with relationship_type
    op.create_table(
        "mitre_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("matrix", sa.String(20), nullable=False),
        sa.Column("source_type", sa.String(40), nullable=False),
        sa.Column("source_external_id", sa.String(20), nullable=False),
        sa.Column("relationship_type", sa.String(40), nullable=False),
        sa.Column("target_type", sa.String(40), nullable=False),
        sa.Column("target_external_id", sa.String(20), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("references", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("sync_version", sa.String(50)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "matrix", "source_type", "source_external_id",
            "relationship_type", "target_type", "target_external_id",
            name="uq_mitre_rel_full",
        ),
    )
    op.create_index("ix_mitre_rel_source", "mitre_relationships",
                    ["source_type", "source_external_id"])
    op.create_index("ix_mitre_rel_target", "mitre_relationships",
                    ["target_type", "target_external_id"])
    op.create_index("ix_mitre_rel_type", "mitre_relationships",
                    ["relationship_type"])

    # Add mitre_group_id link on threat_actors so we can dedupe + auto-import
    op.add_column(
        "threat_actors",
        sa.Column("mitre_group_id", sa.String(20)),
    )
    op.add_column(
        "threat_actors",
        sa.Column("country_codes", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
    )
    op.add_column(
        "threat_actors",
        sa.Column("sectors_targeted", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
    )
    op.add_column(
        "threat_actors",
        sa.Column("regions_targeted", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
    )
    op.add_column(
        "threat_actors",
        sa.Column("malware_families", postgresql.ARRAY(sa.String), nullable=False,
                  server_default="{}"),
    )
    op.add_column(
        "threat_actors",
        sa.Column("references", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
    )
    op.add_column(
        "threat_actors",
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.7"),
    )
    op.create_index("ix_threat_actor_mitre_group_id", "threat_actors",
                    ["mitre_group_id"])
    op.create_index("ix_threat_actor_sectors", "threat_actors",
                    ["sectors_targeted"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_index("ix_threat_actor_sectors", table_name="threat_actors")
    op.drop_index("ix_threat_actor_mitre_group_id", table_name="threat_actors")
    op.drop_column("threat_actors", "confidence")
    op.drop_column("threat_actors", "references")
    op.drop_column("threat_actors", "malware_families")
    op.drop_column("threat_actors", "regions_targeted")
    op.drop_column("threat_actors", "sectors_targeted")
    op.drop_column("threat_actors", "country_codes")
    op.drop_column("threat_actors", "mitre_group_id")

    op.drop_index("ix_mitre_rel_type", table_name="mitre_relationships")
    op.drop_index("ix_mitre_rel_target", table_name="mitre_relationships")
    op.drop_index("ix_mitre_rel_source", table_name="mitre_relationships")
    op.drop_table("mitre_relationships")
    op.drop_table("mitre_campaigns")
    op.drop_table("mitre_data_sources")
    op.drop_index("ix_mitre_software_aliases", table_name="mitre_software")
    op.drop_index("ix_mitre_software_name", table_name="mitre_software")
    op.drop_index("ix_mitre_software_external_id", table_name="mitre_software")
    op.drop_table("mitre_software")
    op.drop_index("ix_mitre_group_regions", table_name="mitre_groups")
    op.drop_index("ix_mitre_group_sectors", table_name="mitre_groups")
    op.drop_index("ix_mitre_group_aliases", table_name="mitre_groups")
    op.drop_index("ix_mitre_group_external_id", table_name="mitre_groups")
    op.drop_table("mitre_groups")
