"""Alembic async migration environment for Argus."""

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Import settings for database URL
from src.config.settings import settings

# Import Base and ALL models so Alembic can autogenerate every table.
# (Audit A3 — previously only `threat` was imported, so Phase 1-11 tables
# never appeared in migrations.)
from src.models.base import Base
import src.models.threat  # noqa: F401
import src.models.auth  # noqa: F401
import src.models.intel  # noqa: F401
import src.models.feeds  # noqa: F401
import src.models.onboarding  # noqa: F401
import src.models.evidence  # noqa: F401
import src.models.cases  # noqa: F401
import src.models.notifications  # noqa: F401
import src.models.mitre  # noqa: F401
import src.models.easm  # noqa: F401
import src.models.exposures  # noqa: F401
import src.models.ratings  # noqa: F401
import src.models.dmarc  # noqa: F401
import src.models.brand  # noqa: F401
import src.models.live_probe  # noqa: F401
import src.models.logo  # noqa: F401
import src.models.social  # noqa: F401
import src.models.fraud  # noqa: F401
import src.models.leakage  # noqa: F401
import src.models.intel_polish  # noqa: F401
import src.models.tprm  # noqa: F401
import src.models.news  # noqa: F401
import src.models.sla  # noqa: F401
import src.models.takedown  # noqa: F401
import src.models.playbooks  # noqa: F401

config = context.config

# Resolve sqlalchemy.url with caller-precedence:
#
#   1. If a caller (e.g. tests/conftest.py) already populated the
#      Config's sqlalchemy.url with a real URL, respect it. This is
#      what lets the test harness point alembic at ``argus_test``
#      instead of the dev ``argus`` database.
#   2. Otherwise — and ALWAYS for the alembic CLI — fall back to the
#      project's settings.db.url, which builds the URL from
#      ARGUS_DB_HOST / _PORT / _USER / _PASSWORD / _NAME or honours
#      the DATABASE_URL override.
#
# The placeholder string in alembic.ini ("driver://user:pass@localhost
# /dbname") is also treated as 'unset' so a fresh checkout's CLI
# invocation behaves identically to today.
_PLACEHOLDER_URL = "driver://user:pass@localhost/dbname"
_caller_url = (config.get_main_option("sqlalchemy.url") or "").strip()
if not _caller_url or _caller_url == _PLACEHOLDER_URL:
    config.set_main_option("sqlalchemy.url", settings.db.url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emits SQL to stdout."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode using async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations — delegates to async runner."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
