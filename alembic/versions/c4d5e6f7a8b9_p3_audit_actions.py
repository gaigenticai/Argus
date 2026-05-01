"""Add P3 vendor-side / host-side audit_action enum values.

External-effect routes promoted to admin-only by the P3 audit
(audit-fix(P3) C6) need their own audit_action values so a regulator
can answer "who triggered the contain on host X?" in audit_logs.

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-05-01
"""

from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, None] = "b3c4d5e6f7a8"
branch_labels = None
depends_on = None


_NEW_ACTIONS = (
    "edr_ioc_push",
    "edr_host_isolate",
    "email_gateway_blocklist_push",
    "sandbox_submit",
    "soar_push",
    "velociraptor_schedule",
    "volatility_run",
    "caldera_operation_start",
    "telegram_fetch",
    "feed_subscription_create",
    "feed_subscription_update",
    "feed_subscription_delete",
)


def upgrade() -> None:
    bind = op.get_bind()
    enum_exists = bind.execute(
        sa.text("SELECT 1 FROM pg_type WHERE typname = 'audit_action'")
    ).scalar()
    if not enum_exists:
        # Fresh install — Base.metadata creates the enum with the full
        # value list already.
        return
    for action in _NEW_ACTIONS:
        op.execute(sa.text(
            f"ALTER TYPE audit_action ADD VALUE IF NOT EXISTS '{action}'"
        ))


def downgrade() -> None:
    # Postgres can't remove enum values in place. Downgrade is a no-op;
    # if you really need to drop these, drop+recreate the enum (which
    # also requires dropping every column referencing it).
    pass
