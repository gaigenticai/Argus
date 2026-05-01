"""Add phishing-feed values to suspect_domain_source enum (Audit B3).

Adds ``phishtank``, ``openphish``, and ``urlhaus`` to the
``suspect_domain_source`` Postgres enum so the new feed adapters can
tag their findings without a string-typed column.

Postgres enum ALTER values must run outside a transaction block, hence
the ``execute_if`` + autocommit dance.

Revision ID: 9b4e5f33c1d2
Revises: 8a3d4f55c0e1
Create Date: 2026-04-29
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "9b4e5f33c1d2"
down_revision: Union[str, None] = "8a3d4f55c0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NEW_VALUES = ("phishtank", "openphish", "urlhaus")


def upgrade() -> None:
    # Postgres ≥12 supports ``ADD VALUE`` inside a transaction; the
    # docs do warn the new value can't be used in the *same*
    # transaction, but alembic commits at end-of-migration which is
    # exactly what we want.
    bind = op.get_bind()
    for v in _NEW_VALUES:
        bind.exec_driver_sql(
            f"ALTER TYPE suspect_domain_source ADD VALUE IF NOT EXISTS '{v}'"
        )


def downgrade() -> None:
    # Postgres does not support removing values from an enum in place;
    # downgrade is a no-op. To roll back, drop the enum + recreate +
    # cast every existing row, which we do not want to script blindly.
    pass
