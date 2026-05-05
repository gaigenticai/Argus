"""Add `prowler` value to the exposure_source enum.

Revision ID: f7a8b9c0d1e2
Revises: d5e6f7a8b9c0
Create Date: 2026-05-03

The Prowler cloud-security auditor (AWS / Azure / GCP / K8s) is now a
scheduled worker (``src/workers/maintenance/prowler_audit.py``) that
persists ExposureFinding rows. The model already declares the enum
member; this migration just teaches the database about it.

``ADD VALUE IF NOT EXISTS`` is idempotent — re-running this against a
DB that already has the value is a safe no-op.
"""
from __future__ import annotations

from alembic import op


revision = "f7a8b9c0d1e2"
down_revision = "d5e6f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    conn.exec_driver_sql(
        "ALTER TYPE exposure_source ADD VALUE IF NOT EXISTS 'prowler'"
    )


def downgrade() -> None:
    # Postgres has no DROP VALUE; removing requires recreating the
    # enum and casting every column referencing it. Done by hand if
    # ever needed.
    pass
