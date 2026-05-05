"""sigma rules + per-rule technique link

Revision ID: fa6b7c8d9e0f
Revises: ff5a6b7c8d9e
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fa6b7c8d9e0f"
down_revision = "ff5a6b7c8d9e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sigma_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("rule_id", sa.String(64), nullable=False, unique=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("level", sa.String(20)),
        sa.Column("status", sa.String(40)),
        sa.Column("author", sa.String(255)),
        sa.Column("log_source", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("detection", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("falsepositives", postgresql.ARRAY(sa.String),
                  nullable=False, server_default="{}"),
        sa.Column("tags", postgresql.ARRAY(sa.String),
                  nullable=False, server_default="{}"),
        sa.Column(
            "technique_ids",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("references", postgresql.ARRAY(sa.String),
                  nullable=False, server_default="{}"),
        sa.Column("source_repo", sa.String(500)),
        sa.Column("source_path", sa.String(500)),
        sa.Column("sha256", sa.String(64)),
        sa.Column("raw_yaml", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_sigma_rules_techniques", "sigma_rules",
                    ["technique_ids"], postgresql_using="gin")
    op.create_index("ix_sigma_rules_tags", "sigma_rules",
                    ["tags"], postgresql_using="gin")
    op.create_index("ix_sigma_rules_level", "sigma_rules", ["level"])


def downgrade() -> None:
    op.drop_index("ix_sigma_rules_level", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_tags", table_name="sigma_rules")
    op.drop_index("ix_sigma_rules_techniques", table_name="sigma_rules")
    op.drop_table("sigma_rules")
