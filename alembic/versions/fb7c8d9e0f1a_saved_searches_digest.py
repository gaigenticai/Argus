"""saved searches + intel digest deliveries

Revision ID: fb7c8d9e0f1a
Revises: fa6b7c8d9e0f
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fb7c8d9e0f1a"
down_revision = "fa6b7c8d9e0f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saved_searches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(40), nullable=False),  # cve | article | advisory
        sa.Column(
            "filters",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "digest_frequency",
            sa.String(20),
            nullable=False,
            server_default="daily",
        ),  # off | daily | weekly
        sa.Column("digest_email", sa.String(255)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column(
            "active",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index(
        "ix_saved_search_org_active",
        "saved_searches",
        ["organization_id", "active"],
    )

    op.create_table(
        "intel_digest_deliveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "saved_search_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("saved_searches.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("recipient_email", sa.String(255), nullable=False),
        sa.Column(
            "match_count",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column("body_markdown", sa.Text, nullable=False),
        sa.Column("body_html", sa.Text),
        sa.Column(
            "delivered",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("delivery_error", sa.Text),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_intel_digest_delivered",
        "intel_digest_deliveries",
        ["delivered", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_intel_digest_delivered", table_name="intel_digest_deliveries")
    op.drop_table("intel_digest_deliveries")
    op.drop_index("ix_saved_search_org_active", table_name="saved_searches")
    op.drop_table("saved_searches")
