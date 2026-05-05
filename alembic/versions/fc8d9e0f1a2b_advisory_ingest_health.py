"""advisory ingest health — per-source observability

Records every ingest attempt's outcome so operators can see per-source
state without grepping logs. Powers /news/advisories/ingest/health.

Revision ID: fc8d9e0f1a2b
Revises: fb7c8d9e0f1a
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fc8d9e0f1a2b"
down_revision = "fb7c8d9e0f1a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "advisory_ingest_health",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(20), nullable=False),  # ok | partial | error
        sa.Column("source_url", sa.String(500)),
        sa.Column("http_status", sa.Integer),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="1"),
        sa.Column("rows_seen", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rows_parsed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rows_inserted", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rows_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rows_skipped", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "schema_shape",
            sa.String(60),
            nullable=False,
            server_default="unknown",
        ),  # which payload shape we recognised
        sa.Column(
            "missing_fields",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error_message", sa.Text),
        sa.Column(
            "raw_sample",
            sa.Text,  # first ~2KB of payload on parse failure for forensics
        ),
    )
    op.create_index(
        "ix_advisory_health_source_started",
        "advisory_ingest_health",
        ["source", "started_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_advisory_health_source_started",
        table_name="advisory_ingest_health",
    )
    op.drop_table("advisory_ingest_health")
