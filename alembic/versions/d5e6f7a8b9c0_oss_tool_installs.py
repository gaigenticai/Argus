"""oss_tool_installs table — admin-onboarding OSS-tool install tracking.

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-05-01
"""

from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c4d5e6f7a8b9"
branch_labels = None
depends_on = None


_STATES = ("pending", "installing", "installed", "failed", "disabled")


def upgrade() -> None:
    bind = op.get_bind()
    enum_exists = bind.execute(sa.text(
        "SELECT 1 FROM pg_type WHERE typname = 'oss_tool_state'"
    )).scalar()
    if not enum_exists:
        op.execute(sa.text(
            "CREATE TYPE oss_tool_state AS ENUM ("
            + ", ".join(f"'{s}'" for s in _STATES)
            + ")"
        ))

    op.create_table(
        "oss_tool_installs",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                   primary_key=True, nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "state",
            postgresql.ENUM(
                *_STATES, name="oss_tool_state", create_type=False,
            ),
            server_default="disabled", nullable=False,
        ),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("users.id", ondelete="SET NULL"),
                   nullable=True),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("log_tail", sa.Text(), nullable=True),
        sa.Column("extras", postgresql.JSONB(),
                   server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                   server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                   server_default=sa.text("now()"), nullable=False),
    )
    op.create_index(
        "ix_oss_tool_installs_state",
        "oss_tool_installs",
        ["state"],
    )


def downgrade() -> None:
    op.drop_index("ix_oss_tool_installs_state",
                   table_name="oss_tool_installs")
    op.drop_table("oss_tool_installs")
    op.execute("DROP TYPE IF EXISTS oss_tool_state")
