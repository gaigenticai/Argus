"""compliance_exports: add missing updated_at column

The ``ComplianceExport`` model inherits ``TimestampMixin`` which
provides ``updated_at``, but the original table-creation migration
omitted the column — so ``GET /compliance/exports`` 500'd with
``UndefinedColumnError`` the moment the dashboard's Compliance
Evidence Pack page tried to list past exports. Adds the column with
a sensible default so existing rows don't violate NOT NULL.

Revision ID: fe0a1b2c3d4e
Revises: fd9e0f1a2b3c
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "fe0a1b2c3d4e"
down_revision = "fd9e0f1a2b3c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent — production DBs may have had the column hot-patched
    # already by the operator before the migration shipped.
    bind = op.get_bind()
    exists = bind.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'compliance_exports' AND column_name = 'updated_at'"
        )
    ).scalar()
    if not exists:
        op.add_column(
            "compliance_exports",
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )


def downgrade() -> None:
    op.drop_column("compliance_exports", "updated_at")
