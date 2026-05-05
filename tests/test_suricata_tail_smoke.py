"""Suricata tail worker — first-ingest smoke test.

Writes a synthetic eve.json with 2 alert events to a temp file,
points ARGUS_SURICATA_EVE_PATH at it, mocks Redis offset storage,
calls suricata_tail.tick_once(), then asserts:

  * 2 Alert rows landed in the database (on the system org)
  * the Redis offset was advanced past the consumed bytes
  * a feed_health 'maintenance.suricata_tail' row exists with status=ok
  * unconfigured (no env var) → feed_health row with status=unconfigured
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.models.admin import FeedHealth
from src.models.threat import Alert
from src.workers.maintenance import suricata_tail
from src.workers.maintenance.suricata_tail import FEED_NAME

pytestmark = pytest.mark.asyncio


_EVE_ALERT_1 = {
    "timestamp": "2026-05-01T12:34:56.789012+0000",
    "flow_id": 1234567890,
    "in_iface": "eth0",
    "event_type": "alert",
    "src_ip": "10.0.0.5",
    "src_port": 49152,
    "dest_ip": "203.0.113.42",
    "dest_port": 443,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "signature_id": 2018959,
        "rev": 4,
        "signature": "ET TROJAN Suspicious activity",
        "category": "trojan-activity",
        "severity": 1,
    },
}


_EVE_ALERT_2 = {
    "timestamp": "2026-05-01T12:35:00.000+0000",
    "event_type": "alert",
    "src_ip": "203.0.113.99",
    "src_port": 50001,
    "dest_ip": "10.0.0.20",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "signature_id": 2200001,
        "signature": "ET POLICY SSH brute-force",
        "category": "attempted-admin",
        "severity": 2,
    },
}


_EVE_FLOW_NOT_ALERT = {"event_type": "flow", "src_ip": "1.1.1.1"}


@pytest_asyncio.fixture(loop_scope="session")
async def temp_eve_file():
    """Create a temp eve.json with 2 alerts + 1 non-alert event."""
    fd, path = tempfile.mkstemp(suffix=".eve.json")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(_EVE_FLOW_NOT_ALERT).encode() + b"\n")
            f.write(json.dumps(_EVE_ALERT_1).encode() + b"\n")
            f.write(json.dumps(_EVE_ALERT_2).encode() + b"\n")
        yield path
    finally:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass


@pytest_asyncio.fixture(loop_scope="session")
async def system_org_id(test_engine):
    """Resolve (or first-provision) the system org. ``get_system_org_id``
    refuses to invent one — it raises if no Organization rows exist
    (production-grade guard against silently mis-tagging tenant data).
    For a freshly-rebuilt test DB we provision a minimal one here."""
    from src.core.tenant import (
        SystemOrganizationMissing,
        get_system_org_id,
    )
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        try:
            return await get_system_org_id(s)
        except SystemOrganizationMissing:
            from src.models.threat import Organization
            org = Organization(
                name="argus-system",
                domains=["system.argus.local"],
                keywords=["system"],
                industry="security",
            )
            s.add(org)
            await s.commit()
            await s.refresh(org)
            return org.id


async def test_tick_once_ingests_alerts(test_engine, temp_eve_file, system_org_id, monkeypatch):
    """Happy path: configured eve.json with 2 alerts → 2 Alert rows
    persisted on system org + feed_health=ok."""
    monkeypatch.setenv("ARGUS_SURICATA_EVE_PATH", temp_eve_file)

    # Track which signature IDs we ingested so we can clean up after,
    # and cap the Redis offset round-trip with stubs (no real Redis
    # required for the smoke).
    saved_offset = {"v": 0}

    async def _fake_load(redis_url, key):
        return saved_offset["v"]

    async def _fake_save(redis_url, key, offset):
        saved_offset["v"] = offset

    with patch.object(suricata_tail, "_load_offset", _fake_load), \
         patch.object(suricata_tail, "_save_offset", _fake_save):
        await suricata_tail.tick_once()

    # Assert: 2 Alert rows for the system org with our signatures.
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    try:
        async with factory() as s:
            alerts = (await s.execute(
                select(Alert)
                .where(Alert.organization_id == system_org_id)
                .where(Alert.title.like("Suricata:%"))
            )).scalars().all()
            sigs = {a.matched_entities.get("signature_id") for a in alerts}
            assert 2018959 in sigs
            assert 2200001 in sigs
            assert len(alerts) >= 2  # ≥2 in case of prior test residue

            # feed_health row written status=ok
            health = (await s.execute(
                select(FeedHealth)
                .where(FeedHealth.feed_name == FEED_NAME)
                .order_by(FeedHealth.observed_at.desc())
                .limit(1)
            )).scalar_one_or_none()
            assert health is not None
            assert health.status == "ok"
            assert "alerts_persisted=2" in (health.detail or "")

            # Offset advanced past the file
            file_size = os.path.getsize(temp_eve_file)
            assert saved_offset["v"] == file_size
    finally:
        # Clean up the alerts we just inserted so they don't pollute
        # other tests that count Alert rows on system_org.
        async with factory() as s:
            await s.execute(delete(Alert).where(
                Alert.organization_id == system_org_id,
                Alert.matched_entities["signature_id"].astext.in_(["2018959", "2200001"]),
            ))
            await s.commit()


async def test_tick_once_unconfigured_when_env_missing(test_engine, monkeypatch):
    """No env var → feed_health=unconfigured + no DB writes."""
    monkeypatch.delenv("ARGUS_SURICATA_EVE_PATH", raising=False)

    await suricata_tail.tick_once()

    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        health = (await s.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name == FEED_NAME)
            .order_by(FeedHealth.observed_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        assert health is not None
        assert health.status == "unconfigured"
        assert "ARGUS_SURICATA_EVE_PATH" in (health.detail or "")


async def test_tick_once_unconfigured_when_path_missing(test_engine, monkeypatch):
    """Env var points at a file that doesn't exist → feed_health=unconfigured."""
    monkeypatch.setenv("ARGUS_SURICATA_EVE_PATH", "/nonexistent/path/eve.json")

    await suricata_tail.tick_once()

    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        health = (await s.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name == FEED_NAME)
            .order_by(FeedHealth.observed_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        assert health is not None
        assert health.status == "unconfigured"
        assert "does not exist" in (health.detail or "").lower()
