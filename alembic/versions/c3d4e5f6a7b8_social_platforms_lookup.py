"""Data-driven social platforms lookup

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-04-29

Replaces the hardcoded ``social_platform`` Postgres enum with a
lookup table. Adding a new platform (e.g. Threads, Bluesky variants,
a regional network like VK or Weibo) used to require an alembic
migration AND a code deploy because the enum was both a DB
constraint and a Python class.

After this migration:

    * ``social_platforms`` table holds one row per platform with
      machine name, display label, is_active flag, scraper_module
      hint, and timestamps.
    * ``social_accounts.platform`` and ``impersonation_findings.platform``
      become plain VARCHAR(64) referencing ``social_platforms.name``
      via a deferrable foreign key (deferrable so the seed below can
      run in the same transaction as the enum drop).
    * The Python ``SocialPlatform`` enum stays as a *suggested-defaults*
      seed list — ``src/social/platforms.py`` provides the runtime
      lookup that goes through the table.

The 13 default platforms (twitter, x, facebook, instagram, linkedin,
tiktok, youtube, telegram, discord, github, reddit, mastodon, bluesky)
are inserted as part of the migration so existing rows that reference
those values keep their FK validity.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


_DEFAULT_PLATFORMS = [
    ("twitter",   "Twitter (legacy)",      "src.social.twitter_monitor"),
    ("x",         "X / Twitter",           "src.social.twitter_monitor"),
    ("facebook",  "Facebook",              None),
    ("instagram", "Instagram",             "src.social.instagram_monitor"),
    ("linkedin",  "LinkedIn",              "src.social.linkedin_monitor"),
    ("tiktok",    "TikTok",                "src.social.tiktok_monitor"),
    ("youtube",   "YouTube",               None),
    ("telegram",  "Telegram",              "src.social.telegram_monitor"),
    ("discord",   "Discord",               None),
    ("github",    "GitHub",                None),
    ("reddit",    "Reddit",                None),
    ("mastodon",  "Mastodon",              None),
    ("bluesky",   "Bluesky",               None),
]


def upgrade() -> None:
    op.create_table(
        "social_platforms",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("scraper_module", sa.String(255)),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("config", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_social_platforms_name", "social_platforms", ["name"])

    # Seed defaults BEFORE we touch the columns so the FK has rows to
    # reference. Use raw SQL so we don't need the Python model class
    # imported in the migration.
    op.execute(sa.text(
        "INSERT INTO social_platforms (id, name, label, scraper_module, is_active) "
        "VALUES "
        + ", ".join(
            f"(gen_random_uuid(), '{name}', '{label}', "
            + (f"'{scraper}'" if scraper else "NULL")
            + ", true)"
            for name, label, scraper in _DEFAULT_PLATFORMS
        )
    ))

    # Switch social_accounts.platform from enum → varchar(64)
    op.alter_column(
        "social_accounts", "platform",
        existing_type=sa.Enum(name="social_platform"),
        type_=sa.String(64),
        postgresql_using="platform::text",
        existing_nullable=False,
    )
    # Same for impersonation_findings.platform
    op.alter_column(
        "impersonation_findings", "platform",
        existing_type=sa.Enum(name="social_platform"),
        type_=sa.String(64),
        postgresql_using="platform::text",
        existing_nullable=False,
    )

    # Drop the enum type — nothing references it any more.
    op.execute("DROP TYPE IF EXISTS social_platform")

    # Add FKs (deferrable so future bulk imports can land before the
    # platform row).
    op.create_foreign_key(
        "fk_social_accounts_platform",
        "social_accounts", "social_platforms",
        ["platform"], ["name"],
        deferrable=True, initially="DEFERRED",
    )
    op.create_foreign_key(
        "fk_impersonation_findings_platform",
        "impersonation_findings", "social_platforms",
        ["platform"], ["name"],
        deferrable=True, initially="DEFERRED",
    )


def downgrade() -> None:
    # Recreate the enum with the seeded values, then flip the columns
    # back. We refuse to downgrade if a custom platform has been added
    # at runtime — preserving customer data is non-negotiable.
    rows = op.get_bind().execute(
        sa.text("SELECT name FROM social_platforms ORDER BY name")
    ).fetchall()
    custom = [
        r[0] for r in rows
        if r[0] not in {p[0] for p in _DEFAULT_PLATFORMS}
    ]
    if custom:
        raise RuntimeError(
            f"Cannot downgrade: custom social platforms exist {custom}. "
            f"Either delete them or stay on the post-migration schema."
        )

    op.drop_constraint(
        "fk_impersonation_findings_platform",
        "impersonation_findings",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_social_accounts_platform",
        "social_accounts",
        type_="foreignkey",
    )

    enum_values = ",".join(f"'{p[0]}'" for p in _DEFAULT_PLATFORMS)
    op.execute(f"CREATE TYPE social_platform AS ENUM ({enum_values})")

    op.alter_column(
        "impersonation_findings", "platform",
        existing_type=sa.String(64),
        type_=sa.Enum(*[p[0] for p in _DEFAULT_PLATFORMS], name="social_platform"),
        postgresql_using="platform::social_platform",
        existing_nullable=False,
    )
    op.alter_column(
        "social_accounts", "platform",
        existing_type=sa.String(64),
        type_=sa.Enum(*[p[0] for p in _DEFAULT_PLATFORMS], name="social_platform"),
        postgresql_using="platform::social_platform",
        existing_nullable=False,
    )

    op.drop_index("ix_social_platforms_name", table_name="social_platforms")
    op.drop_table("social_platforms")
