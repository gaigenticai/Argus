"""Brand-action token counting columns.

Mirrors the investigation-side columns added in b9c0d1e2f3a4. Both
nullable — the upstream provider may not surface usage data on every
iteration, and we want the dashboard to distinguish "not surfaced"
from "zero" rather than render a misleading $0.000.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "e2f3a4b5c6d7"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("brand_actions", sa.Column("input_tokens", sa.Integer(), nullable=True))
    op.add_column("brand_actions", sa.Column("output_tokens", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("brand_actions", "output_tokens")
    op.drop_column("brand_actions", "input_tokens")
