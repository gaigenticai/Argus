"""Polymorphic case_findings (Audit D12).

Lets a CaseFinding row link to any phase-1+ finding (Exposure,
SuspectDomain, Impersonation, Fraud, CardLeakage, Dlp, LogoMatch,
LiveProbe) via ``finding_type`` + ``finding_id``. Existing
``alert_id`` rows are unaffected; the column becomes nullable so new
polymorphic rows don't have to fake an Alert linkage.

Revision ID: 6e1b2d44ab73
Revises: 5d8a1c92fe01
Create Date: 2026-04-28
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = '6e1b2d44ab73'
down_revision: Union[str, None] = '5d8a1c92fe01'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        'case_findings', 'alert_id',
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    op.add_column(
        'case_findings',
        sa.Column('finding_type', sa.String(length=64), nullable=True),
    )
    op.add_column(
        'case_findings',
        sa.Column(
            'finding_id',
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_index(
        'ix_case_findings_polymorphic',
        'case_findings',
        ['finding_type', 'finding_id'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index('ix_case_findings_polymorphic', table_name='case_findings')
    op.drop_column('case_findings', 'finding_id')
    op.drop_column('case_findings', 'finding_type')
    op.alter_column(
        'case_findings', 'alert_id',
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        nullable=False,
    )
