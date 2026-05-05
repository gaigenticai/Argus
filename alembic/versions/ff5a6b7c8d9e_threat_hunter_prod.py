"""threat-hunter prod-grade

Adds:
  * threat_hunt_runs.assigned_to_user_id (collaboration)
  * threat_hunt_runs.workflow_state (hypothesis|investigating|reporting|closed)
  * threat_hunt_runs.case_id (link to escalated case)
  * hunt_templates  — hypothesis-driven hunt library (PEAK)
  * hunt_notes      — comment thread on a hunt run

Revision ID: ff5a6b7c8d9e
Revises: fe4f5a6b7c8d
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "ff5a6b7c8d9e"
down_revision = "fe4f5a6b7c8d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "threat_hunt_runs",
        sa.Column(
            "assigned_to_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
    )
    op.add_column(
        "threat_hunt_runs",
        sa.Column(
            "workflow_state",
            sa.String(30),
            nullable=False,
            server_default="hypothesis",
        ),
    )
    op.add_column(
        "threat_hunt_runs",
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id", ondelete="SET NULL"),
        ),
    )
    op.add_column(
        "threat_hunt_runs",
        sa.Column("template_id", postgresql.UUID(as_uuid=True)),
    )
    op.add_column(
        "threat_hunt_runs",
        sa.Column(
            "transition_log",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.create_index("ix_hunt_workflow", "threat_hunt_runs", ["workflow_state"])

    op.create_table(
        "hunt_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("hypothesis", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("methodology", sa.String(40), nullable=False, server_default="PEAK"),
        sa.Column(
            "mitre_technique_ids",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "data_sources",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "filters",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("is_global", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("archived_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_hunt_template_org", "hunt_templates", ["organization_id"])
    op.create_index("ix_hunt_template_global", "hunt_templates", ["is_global"])
    op.create_index(
        "ix_hunt_template_techniques",
        "hunt_templates",
        ["mitre_technique_ids"],
        postgresql_using="gin",
    )

    op.create_table(
        "hunt_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "hunt_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_hunt_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_hunt_notes_run", "hunt_notes", ["hunt_run_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_hunt_notes_run", table_name="hunt_notes")
    op.drop_table("hunt_notes")
    op.drop_index("ix_hunt_template_techniques", table_name="hunt_templates")
    op.drop_index("ix_hunt_template_global", table_name="hunt_templates")
    op.drop_index("ix_hunt_template_org", table_name="hunt_templates")
    op.drop_table("hunt_templates")
    op.drop_index("ix_hunt_workflow", table_name="threat_hunt_runs")
    for col in ["transition_log", "template_id", "case_id", "workflow_state", "assigned_to_user_id"]:
        op.drop_column("threat_hunt_runs", col)
