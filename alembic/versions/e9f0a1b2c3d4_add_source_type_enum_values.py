"""Backfill enum types with the values the models now expect.

Revision ID: e9f0a1b2c3d4
Revises: d8e9f0a1b2c3
Create Date: 2026-04-30

The original ee318fa0cd70 migration created several enum types
(``source_type``, ``threat_category``, ``alert_status``) with the
values that existed in 2025-Q1. The corresponding model enums in
src/models/threat.py have grown since then — adding I2P / Lokinet /
Matrix / access-broker source kinds, ``stealer_log`` /
``ransomware_victim`` / ``access_sale`` / ``underground_chatter`` /
``initial_access`` threat categories, and the ``needs_review`` alert
state — but no migration ever added those strings to the postgres
enums. The realistic seed (and any production write that uses one of
the newer values) blew up with ``InvalidTextRepresentationError:
invalid input value for enum ...``.

This migration brings the database in line with the code. ``ADD VALUE
IF NOT EXISTS`` is idempotent, so re-running this against a database
that already has the values is a safe no-op.
"""
from __future__ import annotations

from alembic import op


revision = "e9f0a1b2c3d4"
down_revision = "d8e9f0a1b2c3"
branch_labels = None
depends_on = None


# (enum_name, value) pairs to backfill. Pulled from the corresponding
# enums in src/models/threat.py — keep this list in sync if a model
# enum gains another value. Existing values are unaffected.
_ADDITIONS: tuple[tuple[str, str], ...] = (
    # SourceType — gained dark-web channels and access-broker tagging.
    ("source_type", "i2p"),
    ("source_type", "lokinet"),
    ("source_type", "stealer_log"),
    ("source_type", "ransomware_leak"),
    ("source_type", "forum_underground"),
    ("source_type", "matrix"),
    ("source_type", "access_broker"),
    # ThreatCategory — added IAB, ransomware-victim split, and
    # underground-chatter / initial-access for triage.
    ("threat_category", "stealer_log"),
    ("threat_category", "ransomware_victim"),
    ("threat_category", "access_sale"),
    ("threat_category", "underground_chatter"),
    ("threat_category", "initial_access"),
    # AlertStatus — needs-review came in with the dual-control queue.
    ("alert_status", "needs_review"),
)


def upgrade() -> None:
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction block
    # in older postgres; the asyncpg driver autocommits each
    # ``exec_driver_sql`` so the IF NOT EXISTS variant is safe.
    conn = op.get_bind()
    for enum_name, value in _ADDITIONS:
        conn.exec_driver_sql(
            f"ALTER TYPE {enum_name} ADD VALUE IF NOT EXISTS '{value}'"
        )


def downgrade() -> None:
    # Postgres has no built-in DROP VALUE for enum types. Removing
    # entries would require recreating the type with a narrower set
    # and casting every column that references it — the kind of
    # destructive op that should be done by hand if ever needed.
    pass
