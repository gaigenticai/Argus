"""Phase 6 — TI Polish: actor playbooks + hardening + NVD/EPSS/KEV sync."""

from __future__ import annotations

import gzip
import io
import os
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_NVD = str(_FIXTURES / "nvd_mini.json")
_EPSS = str(_FIXTURES / "epss_mini.csv")
_KEV = str(_FIXTURES / "kev_mini.json")


def _hdr(user) -> dict:
    return user["headers"]


# --- Actor playbooks --------------------------------------------------


async def test_actor_playbook_lifecycle(
    client: AsyncClient, analyst_user, organization
):
    create = await client.post(
        "/api/v1/intel/actor-playbooks",
        json={
            "organization_id": str(organization["id"]),
            "actor_alias": "FIN7",
            "description": "Financial-sector eCrime",
            "aliases": ["Carbanak", "Anunak"],
            "targeted_sectors": ["banking", "retail"],
            "attack_techniques": ["T1566.001", "T1059.001"],
            "associated_malware": ["Carbanak", "Bateleur"],
            "infra_iocs": ["91.0.0.1", "evil.example"],
            "risk_score": 85.0,
        },
        headers=_hdr(analyst_user),
    )
    assert create.status_code == 201, create.text
    pid = create.json()["id"]

    # Duplicate within same scope = 409
    dup = await client.post(
        "/api/v1/intel/actor-playbooks",
        json={
            "organization_id": str(organization["id"]),
            "actor_alias": "FIN7",
        },
        headers=_hdr(analyst_user),
    )
    assert dup.status_code == 409

    listed = await client.get(
        "/api/v1/intel/actor-playbooks",
        params={"organization_id": str(organization["id"]), "q": "fin"},
        headers=_hdr(analyst_user),
    )
    assert any(p["actor_alias"] == "FIN7" for p in listed.json())

    patched = await client.patch(
        f"/api/v1/intel/actor-playbooks/{pid}",
        json={"risk_score": 92.0, "targeted_geos": ["US", "EU"]},
        headers=_hdr(analyst_user),
    )
    assert patched.status_code == 200
    assert patched.json()["risk_score"] == 92.0
    assert patched.json()["targeted_geos"] == ["US", "EU"]


# --- Hardening recommendations ---------------------------------------


async def _seed_exposure(client, analyst_user, admin_user, organization, category="vulnerability", severity="critical"):
    """Create an ExposureFinding directly via the EASM nuclei runner stub."""
    from src.easm.runners import (
        Runner,
        RunnerOutput,
        get_runner_registry,
        set_runner_registry,
    )

    class _Fake(Runner):
        kind = "vuln_scan"

        def __init__(self, output):
            self._output = output

        async def run(self, target, parameters=None):
            return self._output

    items = [
        {
            "rule_id": "argus-test-rule",
            "name": f"Test {category}",
            "description": "synthetic",
            "severity": severity,
            "tags": ["misconfig"] if category == "misconfiguration" else ["cve"],
            "matched_at": "https://argus.test/x",
            "host": "argus.test",
            "url": "https://argus.test/x",
            "cve_ids": ["CVE-2026-1001"] if category == "vulnerability" else [],
            "cwe_ids": [],
            "cvss_score": 9.5 if severity == "critical" else 5.0,
            "raw": {},
        }
    ]
    registry = dict(get_runner_registry())
    registry["vuln_scan"] = _Fake(RunnerOutput(succeeded=True, items=items))
    set_runner_registry(registry)

    enq = await client.post(
        "/api/v1/easm/scan",
        json={
            "organization_id": str(organization["id"]),
            "kind": "vuln_scan",
            "target": "argus.test",
        },
        headers=_hdr(analyst_user),
    )
    assert enq.status_code == 201, enq.text
    await client.post(
        "/api/v1/easm/worker/tick",
        json={"max_jobs": 200},
        headers=_hdr(admin_user),
    )
    listed = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    return listed.json()[0]["id"]


async def test_hardening_generated_for_exposure(
    client: AsyncClient, analyst_user, admin_user, organization
):
    eid = await _seed_exposure(client, analyst_user, admin_user, organization)
    r = await client.post(
        "/api/v1/intel/hardening/generate",
        json={
            "organization_id": str(organization["id"]),
            "exposure_finding_id": eid,
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["generated_count"] == 1

    listed = await client.get(
        "/api/v1/intel/hardening",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    rec = listed.json()[0]
    # Vulnerability template mappings
    assert "7" in rec["cis_control_ids"]
    assert rec["priority"] == "critical"
    assert rec["status"] == "open"
    assert rec["estimated_effort_hours"] == 4.0


async def test_hardening_generate_for_all_exposures(
    client: AsyncClient, analyst_user, admin_user, organization
):
    await _seed_exposure(client, analyst_user, admin_user, organization, category="misconfiguration")
    r = await client.post(
        "/api/v1/intel/hardening/generate",
        json={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert r.json()["generated_count"] >= 1


async def test_hardening_state_machine(
    client: AsyncClient, analyst_user, admin_user, organization
):
    eid = await _seed_exposure(client, analyst_user, admin_user, organization)
    g = await client.post(
        "/api/v1/intel/hardening/generate",
        json={
            "organization_id": str(organization["id"]),
            "exposure_finding_id": eid,
        },
        headers=_hdr(analyst_user),
    )
    rid = g.json()["recommendation_ids"][0]

    in_prog = await client.post(
        f"/api/v1/intel/hardening/{rid}/state",
        json={"to_state": "in_progress"},
        headers=_hdr(analyst_user),
    )
    assert in_prog.status_code == 200

    no_reason = await client.post(
        f"/api/v1/intel/hardening/{rid}/state",
        json={"to_state": "done"},
        headers=_hdr(analyst_user),
    )
    assert no_reason.status_code == 422

    done = await client.post(
        f"/api/v1/intel/hardening/{rid}/state",
        json={"to_state": "done", "reason": "patched in build 9000"},
        headers=_hdr(analyst_user),
    )
    assert done.status_code == 200
    assert done.json()["status"] == "done"


# --- NVD/EPSS/KEV sync ------------------------------------------------


async def test_nvd_sync_loads_fixture(
    client: AsyncClient, admin_user, analyst_user
):
    r = await client.post(
        "/api/v1/intel/sync/nvd",
        json={"source": _NVD},
        headers=_hdr(admin_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["succeeded"] is True
    # Audit B11 — strict now that the autouse `_scrub_global_tables`
    # fixture wipes cve_records per-test.
    assert body["rows_ingested"] == 2
    assert body["rows_updated"] == 0

    detail = await client.get(
        "/api/v1/intel/cves/CVE-2026-1001",
        headers=_hdr(analyst_user),
    )
    assert detail.status_code == 200
    assert detail.json()["cvss3_score"] == 9.8
    assert "CWE-94" in detail.json()["cwe_ids"]


async def test_epss_sync_lifts_score(
    client: AsyncClient, admin_user, analyst_user
):
    await client.post(
        "/api/v1/intel/sync/nvd",
        json={"source": _NVD},
        headers=_hdr(admin_user),
    )
    epss = await client.post(
        "/api/v1/intel/sync/epss",
        json={"source": _EPSS},
        headers=_hdr(admin_user),
    )
    assert epss.status_code == 200, epss.text
    body = epss.json()
    assert body["succeeded"] is True
    assert body["rows_ingested"] + body["rows_updated"] >= 2

    detail = await client.get(
        "/api/v1/intel/cves/CVE-2026-1001",
        headers=_hdr(analyst_user),
    )
    assert detail.json()["epss_score"] is not None
    assert detail.json()["epss_score"] > 0.9


async def test_kev_sync_marks_kev_flag(
    client: AsyncClient, admin_user, analyst_user
):
    await client.post(
        "/api/v1/intel/sync/kev",
        json={"source": _KEV},
        headers=_hdr(admin_user),
    )
    listed = await client.get(
        "/api/v1/intel/cves",
        params={"is_kev": "true"},
        headers=_hdr(analyst_user),
    )
    cve_ids = {c["cve_id"] for c in listed.json()}
    assert "CVE-2026-1001" in cve_ids
    assert "CVE-2025-0987" in cve_ids


async def test_intel_sync_admin_only(
    client: AsyncClient, analyst_user
):
    r = await client.post(
        "/api/v1/intel/sync/nvd",
        json={"source": _NVD},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 403


async def test_intel_sync_history_records(
    client: AsyncClient, admin_user, analyst_user
):
    await client.post(
        "/api/v1/intel/sync/nvd",
        json={"source": _NVD},
        headers=_hdr(admin_user),
    )
    history = await client.get(
        "/api/v1/intel/syncs",
        params={"source": "nvd"},
        headers=_hdr(analyst_user),
    )
    assert history.status_code == 200
    assert any(s["source"] == "nvd" and s["succeeded"] for s in history.json())


async def test_cve_filter_by_kev_and_epss(
    client: AsyncClient, admin_user, analyst_user
):
    await client.post(
        "/api/v1/intel/sync/nvd", json={"source": _NVD}, headers=_hdr(admin_user)
    )
    await client.post(
        "/api/v1/intel/sync/epss", json={"source": _EPSS}, headers=_hdr(admin_user)
    )
    await client.post(
        "/api/v1/intel/sync/kev", json={"source": _KEV}, headers=_hdr(admin_user)
    )

    high_epss = await client.get(
        "/api/v1/intel/cves",
        params={"min_epss": 0.5},
        headers=_hdr(analyst_user),
    )
    assert all(c["epss_score"] >= 0.5 for c in high_epss.json())
    assert any(c["cve_id"] == "CVE-2026-1001" for c in high_epss.json())
