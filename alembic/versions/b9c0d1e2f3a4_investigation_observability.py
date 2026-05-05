"""Investigation observability — stop_reason, final_confidence, tools_used, tokens, plan.

Adds the columns the dashboard needs to render the "stopped because…"
line + cumulative cost + tool chips, plus a new
``awaiting_plan_approval`` enum value and the ``plan`` column for the
plan-then-act gate.

Pure additive — every new column is nullable so existing rows stay
valid. The new enum value is added with the postgres-specific
``ALTER TYPE … ADD VALUE`` so we don't have to recreate the type.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "b9c0d1e2f3a4"
down_revision = "a8b9c0d1e2f3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # New stop-reason enum lives in its own type.
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE investigation_stop_reason AS ENUM (
                'high_confidence',
                'max_iterations',
                'no_new_evidence',
                'llm_error',
                'user_aborted'
            );
        EXCEPTION WHEN duplicate_object THEN NULL; END $$;
        """
    )
    # Extend the existing investigation_status enum with the new
    # awaiting_plan_approval value. ALTER TYPE … ADD VALUE is
    # idempotent with IF NOT EXISTS on PG ≥ 14.
    op.execute(
        "ALTER TYPE investigation_status "
        "ADD VALUE IF NOT EXISTS 'awaiting_plan_approval'"
    )

    op.add_column(
        "investigations",
        sa.Column(
            "stop_reason",
            sa.Enum(
                "high_confidence",
                "max_iterations",
                "no_new_evidence",
                "llm_error",
                "user_aborted",
                name="investigation_stop_reason",
                create_type=False,
            ),
            nullable=True,
        ),
    )
    op.add_column("investigations", sa.Column("final_confidence", sa.Float(), nullable=True))
    op.add_column(
        "investigations",
        sa.Column("tools_used", sa.ARRAY(sa.String()), nullable=True),
    )
    op.add_column("investigations", sa.Column("input_tokens", sa.Integer(), nullable=True))
    op.add_column("investigations", sa.Column("output_tokens", sa.Integer(), nullable=True))
    op.add_column(
        "investigations",
        sa.Column("plan", sa.dialects.postgresql.JSONB(), nullable=True),
    )

    op.add_column(
        "organization_agent_settings",
        sa.Column(
            "investigation_plan_approval",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("organization_agent_settings", "investigation_plan_approval")
    op.drop_column("investigations", "plan")
    op.drop_column("investigations", "output_tokens")
    op.drop_column("investigations", "input_tokens")
    op.drop_column("investigations", "tools_used")
    op.drop_column("investigations", "final_confidence")
    op.drop_column("investigations", "stop_reason")
    # Postgres can't drop enum values; leave the type extended.
    op.execute("DROP TYPE IF EXISTS investigation_stop_reason")
