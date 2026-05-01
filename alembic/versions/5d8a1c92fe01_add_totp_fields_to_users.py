"""Add TOTP / 2FA fields to users (Audit D10).

Revision ID: 5d8a1c92fe01
Revises: 4c5412a6bada
Create Date: 2026-04-28
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = '5d8a1c92fe01'
down_revision: Union[str, None] = '4c5412a6bada'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('totp_secret', sa.String(length=64), nullable=True),
    )
    op.add_column(
        'users',
        sa.Column('mfa_enrolled_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'users',
        sa.Column(
            'recovery_codes_hashed',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column('users', 'recovery_codes_hashed')
    op.drop_column('users', 'mfa_enrolled_at')
    op.drop_column('users', 'totp_secret')
