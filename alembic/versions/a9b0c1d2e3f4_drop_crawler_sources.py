"""Drop the orphaned ``crawler_sources`` table and its enums.

Revision ID: a9b0c1d2e3f4
Revises: f7a8b9c0d1e2
Create Date: 2026-05-03

The ``crawler_sources`` table backed the legacy ``/sources`` page — a
generic CRUD over crawler URLs that was superseded by the per-kind
``crawler_targets`` model used by the live scheduler. The dashboard
page now redirects to ``/crawlers`` and the only runtime callers
(``pipeline._update_source_health``, ``webhook_dispatcher.dispatch_health_alert``)
were never invoked because the scheduler stopped passing ``source_id``
into ``IngestionPipeline.ingest_from_crawler``.

This migration removes the table plus its two dedicated Postgres enums
(``crawler_source_type``, ``source_health_status``) which are not used
by any other table.
"""
from __future__ import annotations

from alembic import op


revision = "a9b0c1d2e3f4"
down_revision = "f7a8b9c0d1e2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP TABLE IF EXISTS crawler_sources CASCADE")
    op.execute("DROP TYPE IF EXISTS source_health_status")
    op.execute("DROP TYPE IF EXISTS crawler_source_type")


def downgrade() -> None:
    # The legacy /sources surface is gone from the codebase; recreating
    # the table would only restore an orphan with no readers or writers.
    # Downgrade is intentionally a no-op.
    pass
