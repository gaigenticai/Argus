"""Audit E8 — every entry in the PII registry must reference a real
``(table, column)`` so the registry never goes stale silently.

Lives as an integration test (not a unit test) because we need the DB
schema applied to introspect column lists."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from src.core.pii_registry import all_fields

pytestmark = pytest.mark.asyncio


async def test_pii_registry_columns_exist(test_engine):
    async with test_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT table_name, column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public'"
                )
            )
        ).all()
    schema = {(t, c) for t, c in rows}

    missing = [
        f"{f.table}.{f.column}"
        for f in all_fields()
        if (f.table, f.column) not in schema
    ]
    assert not missing, (
        f"PII registry references columns that no longer exist: {missing}"
    )
