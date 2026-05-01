"""MITRE ATT&CK — full integration tests against a real STIX fixture.

Covers: matrix sync from a local STIX 2.1 bundle, idempotency on re-sync,
deprecated/revoked filtering, search by tactic/platform/substring,
sub-technique handling, mitigation list, attachment lifecycle (create,
list, detach, dedup, tenant scope, validation).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio


_FIXTURE = str(
    Path(__file__).resolve().parent / "fixtures" / "mitre_enterprise_mini.json"
)


def _hdr(user) -> dict:
    return user["headers"]


# --- Sync ---------------------------------------------------------------


async def test_sync_from_local_fixture(client: AsyncClient, admin_user):
    r = await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["succeeded"] is True
    assert rep["sync_version"] == "v15.1-test"
    assert rep["tactics"] == 2
    assert rep["techniques"] >= 3  # 4 minus deprecated
    assert rep["subtechniques"] == 1
    assert rep["mitigations"] == 2
    assert rep["deprecated"] >= 1


async def test_sync_idempotent(client: AsyncClient, admin_user):
    # Run twice — counts must not duplicate (uniqueness is on matrix+ext_id)
    for _ in range(2):
        r = await client.post(
            "/api/v1/mitre/sync",
            json={"matrix": "enterprise", "source": _FIXTURE},
            headers=_hdr(admin_user),
        )
        assert r.json()["succeeded"]

    techs = await client.get(
        "/api/v1/mitre/techniques",
        params={"matrix": "enterprise", "include_deprecated": "true"},
        headers=_hdr(admin_user),
    )
    ext_ids = sorted({t["external_id"] for t in techs.json()})
    # No duplicates — set count == row count
    assert len(ext_ids) == len(techs.json())


async def test_sync_only_admins(client: AsyncClient, analyst_user):
    r = await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 403


async def test_sync_audit_log_recorded(
    client: AsyncClient, admin_user, test_engine
):
    r = await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    assert r.status_code == 200

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        rows = await s.execute(
            select(AuditLog.action, AuditLog.resource_id).where(
                AuditLog.action == AuditAction.MITRE_SYNC.value
            )
        )
        actions = [(row[0], row[1]) for row in rows.all()]
    assert any(action == AuditAction.MITRE_SYNC.value for action, _ in actions)


# --- Catalog reads ------------------------------------------------------


async def test_list_tactics(client: AsyncClient, admin_user, analyst_user):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    r = await client.get(
        "/api/v1/mitre/tactics",
        params={"matrix": "enterprise"},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    short_names = {t["short_name"] for t in r.json()}
    assert {"initial-access", "execution"} <= short_names


async def test_filter_techniques_by_tactic_and_platform(
    client: AsyncClient, admin_user, analyst_user
):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )

    by_tactic = await client.get(
        "/api/v1/mitre/techniques",
        params={"tactic": "initial-access"},
        headers=_hdr(analyst_user),
    )
    ext_ids = {t["external_id"] for t in by_tactic.json()}
    assert "T1566" in ext_ids and "T1190" in ext_ids
    assert "T1059" not in ext_ids  # execution-only

    # Sub-technique filter off
    no_sub = await client.get(
        "/api/v1/mitre/techniques",
        params={"include_subtechniques": "false"},
        headers=_hdr(analyst_user),
    )
    assert all(t["is_subtechnique"] is False for t in no_sub.json())

    # Deprecated excluded by default
    default = await client.get(
        "/api/v1/mitre/techniques", headers=_hdr(analyst_user)
    )
    assert all(
        not (t["deprecated"] or t["revoked"]) for t in default.json()
    )

    # Deprecated included when asked
    incl = await client.get(
        "/api/v1/mitre/techniques",
        params={"include_deprecated": "true"},
        headers=_hdr(analyst_user),
    )
    assert any(t["deprecated"] or t["revoked"] for t in incl.json())

    # Platform filter
    plat = await client.get(
        "/api/v1/mitre/techniques",
        params={"platform": "Containers"},
        headers=_hdr(analyst_user),
    )
    assert all("Containers" in t["platforms"] for t in plat.json())
    assert {t["external_id"] for t in plat.json()} == {"T1190"}


async def test_subtechnique_parent_link(client: AsyncClient, admin_user, analyst_user):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    r = await client.get(
        "/api/v1/mitre/techniques/T1566.002", headers=_hdr(analyst_user)
    )
    assert r.status_code == 200
    body = r.json()
    assert body["is_subtechnique"] is True
    assert body["parent_external_id"] == "T1566"


async def test_search_substring(client: AsyncClient, admin_user, analyst_user):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    r = await client.get(
        "/api/v1/mitre/techniques",
        params={"q": "phish"},
        headers=_hdr(analyst_user),
    )
    ext_ids = {t["external_id"] for t in r.json()}
    assert "T1566" in ext_ids and "T1566.002" in ext_ids


async def test_mitigations_listed(client: AsyncClient, admin_user, analyst_user):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    r = await client.get(
        "/api/v1/mitre/mitigations",
        params={"matrix": "enterprise"},
        headers=_hdr(analyst_user),
    )
    ids = {m["external_id"] for m in r.json()}
    assert {"M1016", "M1017"} <= ids


# --- Attachments --------------------------------------------------------


async def test_attach_and_detach_technique(
    client: AsyncClient, admin_user, analyst_user, organization, make_alert
):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    alert_id = str(await make_alert(organization["id"]))

    attach = await client.post(
        "/api/v1/mitre/attachments",
        json={
            "organization_id": str(organization["id"]),
            "entity_type": "alert",
            "entity_id": alert_id,
            "matrix": "enterprise",
            "technique_external_id": "T1566",
            "confidence": 0.9,
            "source": "manual",
            "note": "phishing kit recovered",
        },
        headers=_hdr(analyst_user),
    )
    assert attach.status_code == 201, attach.text
    attach_id = attach.json()["id"]

    # Duplicate attach 409
    dup = await client.post(
        "/api/v1/mitre/attachments",
        json={
            "organization_id": str(organization["id"]),
            "entity_type": "alert",
            "entity_id": alert_id,
            "matrix": "enterprise",
            "technique_external_id": "T1566",
        },
        headers=_hdr(analyst_user),
    )
    assert dup.status_code == 409

    # Lookup techniques for the entity returns the right one(s)
    by_entity = await client.get(
        f"/api/v1/mitre/entities/alert/{alert_id}/techniques",
        headers=_hdr(analyst_user),
    )
    assert by_entity.status_code == 200
    ext_ids = {t["external_id"] for t in by_entity.json()}
    assert "T1566" in ext_ids

    # Detach
    detach = await client.delete(
        f"/api/v1/mitre/attachments/{attach_id}",
        headers=_hdr(analyst_user),
    )
    assert detach.status_code == 204


async def test_attach_unknown_technique_404(
    client: AsyncClient, admin_user, analyst_user, organization, make_alert
):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    alert_id = str(await make_alert(organization["id"]))
    r = await client.post(
        "/api/v1/mitre/attachments",
        json={
            "organization_id": str(organization["id"]),
            "entity_type": "alert",
            "entity_id": alert_id,
            "matrix": "enterprise",
            "technique_external_id": "T9999999",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 404


async def test_attach_invalid_entity_type(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/mitre/attachments",
        json={
            "organization_id": str(organization["id"]),
            "entity_type": "not_a_real_entity",
            "entity_id": str(uuid.uuid4()),
            "matrix": "enterprise",
            "technique_external_id": "T1566",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 422


async def test_list_attachments_filters(
    client: AsyncClient,
    admin_user,
    analyst_user,
    organization,
    second_organization,
    make_alert,
):
    await client.post(
        "/api/v1/mitre/sync",
        json={"matrix": "enterprise", "source": _FIXTURE},
        headers=_hdr(admin_user),
    )
    a1 = str(await make_alert(organization["id"]))
    a2 = str(await make_alert(second_organization["id"]))

    await client.post(
        "/api/v1/mitre/attachments",
        json={
            "organization_id": str(organization["id"]),
            "entity_type": "alert",
            "entity_id": a1,
            "matrix": "enterprise",
            "technique_external_id": "T1190",
        },
        headers=_hdr(analyst_user),
    )
    await client.post(
        "/api/v1/mitre/attachments",
        json={
            "organization_id": str(second_organization["id"]),
            "entity_type": "alert",
            "entity_id": a2,
            "matrix": "enterprise",
            "technique_external_id": "T1190",
        },
        headers=_hdr(analyst_user),
    )

    only_one = await client.get(
        "/api/v1/mitre/attachments",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert only_one.status_code == 200
    ent_ids = {a["entity_id"] for a in only_one.json()}
    assert a1 in ent_ids
    assert a2 not in ent_ids


async def test_unauthenticated_rejected(client: AsyncClient):
    r = await client.get("/api/v1/mitre/tactics")
    assert r.status_code in (401, 403)
