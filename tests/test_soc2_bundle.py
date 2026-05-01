"""Audit G1 — SOC2 evidence bundle end-to-end."""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


def _hdr(u): return u["headers"]


async def test_soc2_bundle_admin_only(client: AsyncClient, analyst_user):
    r = await client.get(
        "/api/v1/audit/export/soc2-bundle", headers=_hdr(analyst_user)
    )
    assert r.status_code == 403


async def test_soc2_bundle_returns_zip_with_expected_members(
    client: AsyncClient, admin_user
):
    r = await client.get(
        "/api/v1/audit/export/soc2-bundle", headers=_hdr(admin_user)
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    expected = {
        "audit_log.ndjson",
        "users.json",
        "retention_policies.json",
        "notification_channels.json",
        "evidence_inventory.json",
        "metadata.json",
    }
    assert expected <= names, f"missing: {expected - names}"

    meta = json.loads(z.read("metadata.json"))
    assert meta["audit_row_count"] >= 0
    assert meta["argus_version"] == "0.1.0"

    # users.json must NEVER carry plaintext emails — only sha256 hashes.
    users = json.loads(z.read("users.json"))
    for u in users:
        assert "email" not in u, "evidence bundle leaked plaintext email"
        assert "email_sha256" in u
