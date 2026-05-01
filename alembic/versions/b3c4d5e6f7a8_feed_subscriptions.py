"""feed_subscriptions table (P3 #3.4).

Per-user feed subscriptions: a saved alert filter + delivery channels
list. The user manages their own subscriptions through the SDK; the
existing org-scoped notification_rules system is unchanged.

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-05-01
"""

from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "b3c4d5e6f7a8"
down_revision: Union[str, None] = "a2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "feed_subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                   primary_key=True, nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("users.id", ondelete="CASCADE"),
                   nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                   nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("filter", postgresql.JSONB(),
                   server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("channels", postgresql.JSONB(),
                   server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("active", sa.Boolean(),
                   server_default=sa.text("true"), nullable=False),
        sa.Column("last_dispatched_at", sa.DateTime(timezone=True),
                   nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                   server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                   server_default=sa.text("now()"), nullable=False),
    )
    op.create_index(
        "ix_feed_subscriptions_user_active",
        "feed_subscriptions",
        ["user_id", "active"],
    )
    op.create_index(
        "ix_feed_subscriptions_org",
        "feed_subscriptions",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_feed_subscriptions_org", table_name="feed_subscriptions")
    op.drop_index(
        "ix_feed_subscriptions_user_active",
        table_name="feed_subscriptions",
    )
    op.drop_table("feed_subscriptions")
