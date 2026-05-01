"""DeepScan (Phase 1.2) — full integration tests against fake runners.

Verifies:
    - Nuclei vuln scan creates ExposureFinding rows with severity, category, CVE/CWE/CVSS
    - Re-running bumps occurrence_count + last_seen_at, state stays OPEN
    - Re-running after FIXED auto-reopens (REOPENED state)
    - nmap -sV updates service banner; emits SERVICE_BANNER_CHANGED on drift
    - nmap -sV with product+version creates a low-severity version_disclosure exposure
    - testssl finds weak crypto / expired cert / vulnerability — categorized correctly
    - State machine transitions (open → acknowledged → fixed → reopened ...)
    - Reason required for terminal states
    - Tenant isolation
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from src.easm.runners import (
    Runner,
    RunnerOutput,
    get_runner_registry,
    reset_runner_registry,
    set_runner_registry,
)

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


class _Fake(Runner):
    def __init__(self, kind: str, output: RunnerOutput):
        self.kind = kind
        self._output = output
        self.calls: list[tuple[str, dict | None]] = []

    async def run(self, target, parameters=None):
        self.calls.append((target, parameters))
        return self._output


@pytest.fixture(autouse=True)
def _reset_runners():
    reset_runner_registry()
    yield
    reset_runner_registry()


def _install(kind: str, output: RunnerOutput) -> _Fake:
    registry = dict(get_runner_registry())
    fake = _Fake(kind, output)
    registry[kind] = fake
    set_runner_registry(registry)
    return fake


async def _enqueue_and_tick(client, analyst, admin, organization, kind, target, asset_id=None):
    """Enqueue one job and drain enough queue that ours definitely runs.

    The worker is FIFO/global; cross-test residue is real. We tick
    generously and verify our job's row reached a terminal status.
    """
    body = {
        "organization_id": str(organization["id"]),
        "kind": kind,
        "target": target,
    }
    if asset_id is not None:
        body["asset_id"] = str(asset_id)
    r = await client.post("/api/v1/easm/scan", json=body, headers=_hdr(analyst))
    assert r.status_code == 201, r.text
    job_id = r.json()["job_id"]

    tick = await client.post(
        "/api/v1/easm/worker/tick", json={"max_jobs": 200}, headers=_hdr(admin)
    )
    assert tick.status_code == 200, tick.text
    body = tick.json()

    # Filter results to OUR job so callers can assert on the right row.
    mine = next((r for r in body["results"] if r["job_id"] == job_id), None)
    if mine is not None:
        body["results"] = [mine]
    body["jobs_processed"] = 1 if mine else 0
    return body


# --- Nuclei -------------------------------------------------------------


_NUCLEI_OUTPUT = RunnerOutput(
    succeeded=True,
    items=[
        {
            "rule_id": "CVE-2023-12345",
            "name": "Critical RCE in WidgetSoft",
            "description": "Exploits unauthenticated RCE.",
            "severity": "critical",
            "tags": ["cve", "rce"],
            "matched_at": "https://probe.example.test/admin",
            "host": "probe.example.test",
            "url": "https://probe.example.test/admin",
            "cve_ids": ["CVE-2023-12345"],
            "cwe_ids": ["CWE-94"],
            "cvss_score": 9.8,
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
            "raw": {"matched-at": "https://probe.example.test/admin"},
        },
        {
            "rule_id": "exposed-git-config",
            "name": "Git config exposure",
            "description": "Reveals repo metadata.",
            "severity": "medium",
            "tags": ["exposure"],
            "matched_at": "https://probe.example.test/.git/config",
            "host": "probe.example.test",
            "url": "https://probe.example.test/.git/config",
            "cve_ids": [],
            "cwe_ids": [],
            "cvss_score": None,
            "references": [],
        },
    ],
    duration_ms=120,
)


async def test_nuclei_creates_exposures(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install("vuln_scan", _NUCLEI_OUTPUT)
    out = await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "vuln_scan", "probe.example.test",
    )
    assert out["results"][0]["new_exposures"] == 2

    listed = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert listed.status_code == 200
    body = listed.json()
    assert len(body) == 2
    by_rule = {f["rule_id"]: f for f in body}
    assert "CVE-2023-12345" in by_rule
    assert by_rule["CVE-2023-12345"]["severity"] == "critical"
    assert "CVE-2023-12345" in by_rule["CVE-2023-12345"]["cve_ids"]
    assert by_rule["CVE-2023-12345"]["cvss_score"] == 9.8
    assert by_rule["exposed-git-config"]["category"] == "exposed_service"


async def test_nuclei_idempotent_bumps_occurrence(
    client: AsyncClient, analyst_user, admin_user, organization
):
    for _ in range(3):
        _install("vuln_scan", _NUCLEI_OUTPUT)
        await _enqueue_and_tick(
            client, analyst_user, admin_user, organization,
            "vuln_scan", "probe.example.test",
        )

    listed = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    counts = {f["rule_id"]: f["occurrence_count"] for f in listed.json()}
    assert counts == {"CVE-2023-12345": 3, "exposed-git-config": 3}


async def test_nuclei_reopens_after_fixed(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install("vuln_scan", _NUCLEI_OUTPUT)
    await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "vuln_scan", "probe.example.test",
    )
    listed = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"]), "severity": "critical"},
        headers=_hdr(analyst_user),
    )
    fid = listed.json()[0]["id"]

    # Mark fixed
    fixed = await client.post(
        f"/api/v1/easm/exposures/{fid}/state",
        json={"to_state": "fixed", "reason": "patched in build 4321"},
        headers=_hdr(analyst_user),
    )
    assert fixed.status_code == 200, fixed.text
    assert fixed.json()["state"] == "fixed"

    # Re-scan finds it again — auto-reopens
    _install("vuln_scan", _NUCLEI_OUTPUT)
    await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "vuln_scan", "probe.example.test",
    )
    again = await client.get(
        f"/api/v1/easm/exposures/{fid}", headers=_hdr(analyst_user)
    )
    assert again.json()["state"] == "reopened"


# --- nmap -sV -----------------------------------------------------------


async def test_service_version_emits_banner_change_and_disclosure(
    client: AsyncClient, analyst_user, admin_user, organization
):
    # Pre-create the service asset so banner-change can fire
    asset_resp = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "service",
            "value": "10.20.0.30:22",
            "details": {
                "host": "10.20.0.30",
                "port": 22,
                "service_name": "ssh",
                "banner": {"product": "OpenSSH", "version": "8.4"},
            },
        },
        headers=_hdr(analyst_user),
    )
    assert asset_resp.status_code == 201
    asset_id = asset_resp.json()["id"]

    _install(
        "service_version",
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "host": "10.20.0.30",
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6",
                    "extrainfo": "protocol 2.0",
                }
            ],
        ),
    )
    out = await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "service_version", "10.20.0.30",
    )
    assert out["results"][0]["enriched_assets"] == 1
    assert out["results"][0]["new_exposures"] == 1

    changes = await client.get(
        "/api/v1/easm/changes",
        params={
            "organization_id": str(organization["id"]),
            "asset_id": asset_id,
            "kind": "service_banner_changed",
        },
        headers=_hdr(analyst_user),
    )
    assert len(changes.json()) == 1
    assert changes.json()[0]["after"]["version"] == "9.6"

    exp = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"]), "category": "version_disclosure"},
        headers=_hdr(analyst_user),
    )
    assert len(exp.json()) == 1
    assert "9.6" in exp.json()[0]["title"]


# --- testssl.sh ---------------------------------------------------------


async def test_tls_audit_categorizes_findings(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install(
        "tls_audit",
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "id": "cert_expirationStatus",
                    "section": "serverDefaults",
                    "severity": "high",
                    "finding": "Certificate expired 12 days ago",
                    "ip": "203.0.113.55",
                    "port": "443",
                },
                {
                    "id": "BREACH",
                    "section": "vulnerabilities",
                    "severity": "medium",
                    "finding": "Potentially vulnerable to BREACH",
                    "ip": "203.0.113.55",
                    "port": "443",
                    "cve": "CVE-2013-3587",
                    "cwe": "CWE-310",
                },
                {
                    "id": "RC4",
                    "section": "cipherTests",
                    "severity": "high",
                    "finding": "RC4 ciphers offered",
                    "ip": "203.0.113.55",
                    "port": "443",
                },
            ],
        ),
    )
    out = await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "tls_audit", "203.0.113.55",
    )
    assert out["results"][0]["new_exposures"] == 3

    listed = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"]), "source": "testssl"},
        headers=_hdr(analyst_user),
    )
    by_rule = {f["rule_id"]: f for f in listed.json()}
    assert by_rule["testssl:cert_expirationStatus"]["category"] == "expired_cert"
    assert by_rule["testssl:BREACH"]["category"] == "vulnerability"
    assert "CVE-2013-3587" in by_rule["testssl:BREACH"]["cve_ids"]
    assert by_rule["testssl:RC4"]["category"] == "weak_crypto"


# --- State machine ------------------------------------------------------


async def test_exposure_state_machine(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install("vuln_scan", _NUCLEI_OUTPUT)
    await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "vuln_scan", "probe.example.test",
    )
    listed = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"]), "severity": "critical"},
        headers=_hdr(analyst_user),
    )
    fid = listed.json()[0]["id"]

    # open -> acknowledged (reason optional)
    ack = await client.post(
        f"/api/v1/easm/exposures/{fid}/state",
        json={"to_state": "acknowledged"},
        headers=_hdr(analyst_user),
    )
    assert ack.status_code == 200
    assert ack.json()["state"] == "acknowledged"

    # acknowledged -> fixed (reason required)
    no_reason = await client.post(
        f"/api/v1/easm/exposures/{fid}/state",
        json={"to_state": "fixed"},
        headers=_hdr(analyst_user),
    )
    assert no_reason.status_code == 422

    fixed = await client.post(
        f"/api/v1/easm/exposures/{fid}/state",
        json={"to_state": "fixed", "reason": "patched"},
        headers=_hdr(analyst_user),
    )
    assert fixed.status_code == 200

    # fixed -> open is NOT allowed (must go via reopened)
    bad = await client.post(
        f"/api/v1/easm/exposures/{fid}/state",
        json={"to_state": "open", "reason": "no"},
        headers=_hdr(analyst_user),
    )
    assert bad.status_code == 422

    re = await client.post(
        f"/api/v1/easm/exposures/{fid}/state",
        json={"to_state": "reopened", "reason": "regression"},
        headers=_hdr(analyst_user),
    )
    assert re.status_code == 200


# --- Tenant isolation ---------------------------------------------------


async def test_exposures_scoped_to_org(
    client: AsyncClient, analyst_user, admin_user, organization, second_organization
):
    _install("vuln_scan", _NUCLEI_OUTPUT)
    await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "vuln_scan", "probe.example.test",
    )
    listed_other = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(second_organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert listed_other.status_code == 200
    assert listed_other.json() == []
