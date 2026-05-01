"""Legal-hold flag (Audit G4).

Adds a `legal_hold` boolean to the resources retention can prune.
When `true`, the retention engine MUST NOT delete the row regardless
of the configured day window. Used during regulator inquiries,
litigation, and breach investigations.

Revision ID: 8a3d4f55c0e1
Revises: 7f9c1b22a8e3
Create Date: 2026-04-28
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = '8a3d4f55c0e1'
down_revision: Union[str, None] = '7f9c1b22a8e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_HOLD_TABLES = ("evidence_blobs", "cases", "audit_logs")


def upgrade() -> None:
    for t in _HOLD_TABLES:
        op.add_column(
            t,
            sa.Column(
                "legal_hold",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
        op.create_index(
            f"ix_{t}_legal_hold",
            t,
            ["legal_hold"],
            postgresql_where=sa.text("legal_hold = true"),
        )


def downgrade() -> None:
    for t in _HOLD_TABLES:
        op.drop_index(f"ix_{t}_legal_hold", table_name=t)
        op.drop_column(t, "legal_hold")
