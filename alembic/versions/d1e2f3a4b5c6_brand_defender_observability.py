"""Brand Defender observability + allowlist + plan-then-act.

Adds the schema the dashboard needs to render the Defender activity
panel (plan column on brand_actions, awaiting_plan_approval status),
the per-org defence threshold + plan-approval flag, and the editable
subsidiary allowlist that supersedes the agent's in-code list.

All new columns are nullable / have server defaults so existing rows
stay valid. The new enum value uses ``ALTER TYPE … ADD VALUE`` which
is idempotent on PG ≥ 14.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "d1e2f3a4b5c6"
down_revision = "c0d1e2f3a4b5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # New enum value for the brand-action plan-then-act gate.
    op.execute(
        "ALTER TYPE brand_action_status "
        "ADD VALUE IF NOT EXISTS 'awaiting_plan_approval'"
    )

    # brand_actions.plan
    op.add_column(
        "brand_actions",
        sa.Column("plan", sa.dialects.postgresql.JSONB(), nullable=True),
    )

    # Per-org defender knobs.
    op.add_column(
        "organization_agent_settings",
        sa.Column(
            "brand_defence_min_similarity",
            sa.Float(),
            nullable=False,
            server_default="0.8",
        ),
    )
    op.add_column(
        "organization_agent_settings",
        sa.Column(
            "brand_defence_plan_approval",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    # brand_subsidiary_allowlist
    op.create_table(
        "brand_subsidiary_allowlist",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("pattern", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "created_by_user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_brand_allowlist_org",
        "brand_subsidiary_allowlist",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_brand_allowlist_org", table_name="brand_subsidiary_allowlist")
    op.drop_table("brand_subsidiary_allowlist")
    op.drop_column("organization_agent_settings", "brand_defence_plan_approval")
    op.drop_column("organization_agent_settings", "brand_defence_min_similarity")
    op.drop_column("brand_actions", "plan")
    # Postgres can't drop enum values without recreating the type.
