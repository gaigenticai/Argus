"""iocs prod-grade — allowlist + decay + enrichment + sightings

Adds production fields the audit flagged:
  * iocs.is_allowlisted          (false-positive suppression)
  * iocs.allowlist_reason        (audit trail)
  * iocs.expires_at              (TTL / sunset)
  * iocs.confidence_half_life_days (decay rate)
  * iocs.enrichment_data         (VirusTotal/AbuseIPDB/OTX/URLhaus/ThreatFox cache)
  * iocs.enrichment_fetched_at   (cache freshness)
  * iocs.source_feed             (where it came from: feed/manual/article/case)

New tables:
  * ioc_sightings   (per-occurrence audit log: where seen, when, by what)
  * ioc_audit       (CRUD audit trail for compliance)

Revision ID: fd3e4f5a6b7c
Revises: fc2d3e4f5a6b
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "fd3e4f5a6b7c"
down_revision = "fc2d3e4f5a6b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "iocs",
        sa.Column("is_allowlisted", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )
    op.add_column("iocs", sa.Column("allowlist_reason", sa.Text))
    op.add_column("iocs", sa.Column("expires_at", sa.DateTime(timezone=True)))
    op.add_column(
        "iocs",
        sa.Column(
            "confidence_half_life_days",
            sa.Integer,
            nullable=False,
            server_default="365",
        ),
    )
    op.add_column(
        "iocs",
        sa.Column(
            "enrichment_data",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column(
        "iocs",
        sa.Column("enrichment_fetched_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "iocs",
        sa.Column("source_feed", sa.String(50)),
    )
    op.create_index("ix_iocs_allowlist", "iocs", ["is_allowlisted"])
    op.create_index("ix_iocs_expires", "iocs", ["expires_at"])
    op.create_index("ix_iocs_source_feed", "iocs", ["source_feed"])

    op.create_table(
        "ioc_sightings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "ioc_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("iocs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(60), nullable=False),  # feed/article/alert/case/manual
        sa.Column("source_id", postgresql.UUID(as_uuid=True)),  # ref to article/alert/case/feed row
        sa.Column("source_url", sa.String(2000)),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "context",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "ioc_id", "source", "source_id", "seen_at",
            name="uq_ioc_sighting",
        ),
    )
    op.create_index("ix_ioc_sightings_ioc", "ioc_sightings", ["ioc_id", "seen_at"])

    op.create_table(
        "ioc_audit",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "ioc_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("iocs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(40), nullable=False),  # create/edit/allowlist/delete/enrich
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "before",
            postgresql.JSONB,
        ),
        sa.Column(
            "after",
            postgresql.JSONB,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_ioc_audit_ioc", "ioc_audit", ["ioc_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_ioc_audit_ioc", table_name="ioc_audit")
    op.drop_table("ioc_audit")
    op.drop_index("ix_ioc_sightings_ioc", table_name="ioc_sightings")
    op.drop_table("ioc_sightings")
    op.drop_index("ix_iocs_source_feed", table_name="iocs")
    op.drop_index("ix_iocs_expires", table_name="iocs")
    op.drop_index("ix_iocs_allowlist", table_name="iocs")
    for col in [
        "source_feed",
        "enrichment_fetched_at",
        "enrichment_data",
        "confidence_half_life_days",
        "expires_at",
        "allowlist_reason",
        "is_allowlisted",
    ]:
        op.drop_column("iocs", col)
