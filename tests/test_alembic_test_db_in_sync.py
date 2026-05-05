"""Regression test — the test database must always be at alembic head
after the conftest test_engine fixture runs.

This catches the class of bug where a new migration is added but
``tests/conftest.py`` silently fails to apply it to ``argus_test``
(seen historically because ``alembic/env.py`` was overriding the
caller-provided URL with ``settings.db.url``, which pointed at the
dev database).

If this test fails, every other test that relies on a column / table /
enum value from the un-applied migration will silently break in
confusing ways. Fail fast here instead.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio


def _alembic_heads_from_disk() -> set[str]:
    """Walk alembic/versions/ and return the set of revision IDs that
    are NOT a down_revision of any other migration. These are the
    head(s) the test DB should be at."""
    import re
    from pathlib import Path

    versions_dir = Path(__file__).resolve().parent.parent / "alembic" / "versions"
    revs: set[str] = set()
    parents: set[str] = set()
    for f in versions_dir.glob("*.py"):
        text_ = f.read_text()
        rev = re.search(
            r"^revision\s*[:\s]*[^=]*=\s*['\"](\w+)['\"]", text_, re.M,
        )
        down = re.search(
            r"^down_revision\s*[:\s]*[^=]*=\s*['\"](\w+)['\"]", text_, re.M,
        )
        if rev:
            revs.add(rev.group(1))
        if down:
            parents.add(down.group(1))
    return revs - parents


async def test_test_db_at_alembic_head(test_engine):
    """Read alembic_version from the test DB; assert it matches the
    set of revision-ids on disk that have no children."""
    expected_heads = _alembic_heads_from_disk()
    assert expected_heads, (
        "no alembic heads found on disk — alembic/versions/ may be empty "
        "or this regression check has a bug"
    )

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        result = await s.execute(text("SELECT version_num FROM alembic_version"))
        rows_in_db = {r[0] for r in result.fetchall()}

    assert rows_in_db == expected_heads, (
        f"test DB alembic_version ({rows_in_db}) does not match "
        f"on-disk heads ({expected_heads}). "
        "Did conftest.py fail to upgrade? See the docstring on "
        "alembic/env.py — the test_engine fixture must apply every "
        "migration to the test database, otherwise downstream tests "
        "will silently break on missing columns / enums / tables."
    )


async def test_known_recent_enum_value_present(test_engine):
    """Spot-check: the ``prowler`` value must exist in the
    ``exposure_source`` enum (added by migration f7a8b9c0d1e2).

    If this test fails, the test DB is at an older revision than
    expected — the conftest's alembic upgrade didn't reach the head."""
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        result = await s.execute(
            text("SELECT enum_range(NULL::exposure_source)::text"),
        )
        enum_text = result.scalar() or ""

    assert "prowler" in enum_text, (
        f"`prowler` missing from exposure_source enum: {enum_text!r}. "
        "Migration f7a8b9c0d1e2 must run; see "
        "tests/test_alembic_test_db_in_sync.py for context."
    )
