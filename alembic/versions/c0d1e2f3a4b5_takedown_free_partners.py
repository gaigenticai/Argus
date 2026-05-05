"""Takedown enum: add free/self-service partners (urlhaus, threatfox, direct_registrar).

These three adapters need no commercial contract and no SMTP-only
mailbox dance — URLhaus + ThreatFox post to free abuse.ch APIs (with
optional auth keys) and DirectRegistrar does WHOIS-driven abuse@
emails over the operator's existing SMTP transport.

Postgres ALTER TYPE … ADD VALUE is idempotent with IF NOT EXISTS on
PG ≥ 14, so re-running this migration on an environment that already
applied it is a no-op.
"""
from __future__ import annotations

from alembic import op


revision = "c0d1e2f3a4b5"
down_revision = "b9c0d1e2f3a4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE takedown_partner ADD VALUE IF NOT EXISTS 'urlhaus'")
    op.execute("ALTER TYPE takedown_partner ADD VALUE IF NOT EXISTS 'threatfox'")
    op.execute(
        "ALTER TYPE takedown_partner ADD VALUE IF NOT EXISTS 'direct_registrar'"
    )


def downgrade() -> None:
    # Postgres can't drop enum values without recreating the type.
    # Leave the values in place on downgrade — they're harmless and
    # any tickets created against them would orphan.
    pass
