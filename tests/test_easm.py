"""EASM Phase 1.1 — full integration tests.

Verifies:
    - DiscoveryJob worker tick: atomic claim → execute → persist → mark done
    - Subdomain enum produces DiscoveryFinding rows + AssetChange entries
    - Port scan creates SERVICE findings + PORT_OPENED change events
    - HTTPX probe enriches existing assets and emits drift events
      (HTTP_STATUS_CHANGED, HTTP_TITLE_CHANGED, HTTP_TECH_CHANGED, TLS_CERT_CHANGED)
    - DNS refresh updates email_domain assets, emits SPF/DMARC drift
    - Idempotency: re-running a job creates no duplicate findings
    - Failure: runner returns succeeded=False → job marked FAILED with error
    - Finding lifecycle: promote → Asset row created, dismiss → state change
    - Tenant isolation
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

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


# --- Fake runner factory ----------------------------------------------


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
    """Every test starts with the production registry, then sets fakes
    explicitly. Avoids cross-test pollution."""
    reset_runner_registry()
    yield
    reset_runner_registry()


def _install(kind: str, output: RunnerOutput) -> _Fake:
    registry = dict(get_runner_registry())
    fake = _Fake(kind, output)
    registry[kind] = fake
    set_runner_registry(registry)
    return fake


async def _enqueue_scan(client, analyst, organization, kind, target, asset_id=None):
    body = {
        "organization_id": str(organization["id"]),
        "kind": kind,
        "target": target,
    }
    if asset_id is not None:
        body["asset_id"] = str(asset_id)
    r = await client.post(
        "/api/v1/easm/scan", json=body, headers=_hdr(analyst)
    )
    assert r.status_code == 201, r.text
    return r.json()["job_id"]


async def _tick(client, admin) -> dict:
    """Drain enough of the queue to be safe across cross-test FIFO."""
    r = await client.post(
        "/api/v1/easm/worker/tick",
        json={"max_jobs": 200},
        headers=_hdr(admin),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _count_org_jobs(client, analyst, organization) -> int:
    """Helper: how many jobs has THIS org enqueued so far (any status)?"""
    r = await client.get(
        "/api/v1/onboarding/discovery-jobs",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst),
    )
    return len(r.json())


# --- Subdomain enum ---------------------------------------------------


async def test_subdomain_enum_creates_findings_and_changes(
    client: AsyncClient, analyst_user, admin_user, organization
):
    fake = _install(
        "subdomain_enum",
        RunnerOutput(
            succeeded=True,
            items=[
                {"host": "api.example.test", "source": "subfinder"},
                {"host": "admin.example.test", "source": "crtsh"},
                {"host": "example.test", "source": "subfinder"},  # apex — should be ignored
            ],
            duration_ms=42,
        ),
    )
    job_id = await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "example.test"
    )
    out = await _tick(client, admin_user)
    # Locate THIS test's job in the results regardless of queue depth.
    mine = next((r for r in out["results"] if r["job_id"] == job_id), None)
    assert mine is not None, f"job {job_id} not found in tick results"
    assert mine["new_findings"] == 2
    assert fake.calls == [("example.test", {})]

    findings = await client.get(
        "/api/v1/easm/findings",
        params={"organization_id": str(organization["id"]), "state": "new"},
        headers=_hdr(analyst_user),
    )
    values = {f["value"] for f in findings.json()}
    assert {"api.example.test", "admin.example.test"} <= values
    assert "example.test" not in values

    changes = await client.get(
        "/api/v1/easm/changes",
        params={"organization_id": str(organization["id"]), "kind": "asset_created"},
        headers=_hdr(analyst_user),
    )
    assert len(changes.json()) >= 2
    assert all(c["kind"] == "asset_created" for c in changes.json())


async def test_subdomain_enum_idempotent(
    client: AsyncClient, analyst_user, admin_user, organization
):
    output = RunnerOutput(
        succeeded=True,
        items=[{"host": "api.example.test"}, {"host": "blog.example.test"}],
    )
    _install("subdomain_enum", output)
    await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "example.test"
    )
    await _tick(client, admin_user)
    # Second run with overlapping output — no duplicate findings, no extra changes
    _install("subdomain_enum", output)
    await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "example.test"
    )
    await _tick(client, admin_user)

    findings = await client.get(
        "/api/v1/easm/findings",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    values = [f["value"] for f in findings.json()]
    assert len(values) == len(set(values)) == 2


# --- Port scan --------------------------------------------------------


async def test_port_scan_emits_port_opened(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install(
        "port_scan",
        RunnerOutput(
            succeeded=True,
            items=[
                {"host": "10.0.0.10", "port": 22, "protocol": "tcp"},
                {"host": "10.0.0.10", "port": 443, "protocol": "tcp"},
            ],
        ),
    )
    await _enqueue_scan(
        client, analyst_user, organization, "port_scan", "10.0.0.10"
    )
    await _tick(client, admin_user)

    changes = await client.get(
        "/api/v1/easm/changes",
        params={
            "organization_id": str(organization["id"]),
            "kind": "port_opened",
        },
        headers=_hdr(analyst_user),
    )
    assert len(changes.json()) == 2
    assert all(c["severity"] == "high" for c in changes.json())


# --- HTTPX probe --------------------------------------------------------


async def test_httpx_probe_enriches_asset_and_emits_drift(
    client: AsyncClient, analyst_user, admin_user, organization
):
    # Pre-create the domain asset
    asset = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "domain",
            "value": "probe-test.example",
        },
        headers=_hdr(analyst_user),
    )
    asset_id = asset.json()["id"]

    # First probe — sets baseline state
    _install(
        "httpx_probe",
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "host": "probe-test.example",
                    "url": "https://probe-test.example/",
                    "status_code": 200,
                    "title": "Welcome",
                    "tech": ["nginx", "react"],
                    "ips": ["203.0.113.10"],
                    "tls": {"fingerprint_sha256": "AAA"},
                }
            ],
        ),
    )
    await _enqueue_scan(
        client,
        analyst_user,
        organization,
        "httpx_probe",
        "probe-test.example",
        asset_id=asset_id,
    )
    await _tick(client, admin_user)

    # Second probe — drift in status, title, tech, and TLS
    _install(
        "httpx_probe",
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "host": "probe-test.example",
                    "url": "https://probe-test.example/",
                    "status_code": 503,
                    "title": "Maintenance",
                    "tech": ["cloudflare", "react"],
                    "ips": ["203.0.113.10"],
                    "tls": {"fingerprint_sha256": "BBB"},
                }
            ],
        ),
    )
    await _enqueue_scan(
        client,
        analyst_user,
        organization,
        "httpx_probe",
        "probe-test.example",
        asset_id=asset_id,
    )
    await _tick(client, admin_user)

    changes = await client.get(
        "/api/v1/easm/changes",
        params={
            "organization_id": str(organization["id"]),
            "asset_id": asset_id,
        },
        headers=_hdr(analyst_user),
    )
    kinds = {c["kind"] for c in changes.json()}
    assert {
        "http_status_changed",
        "http_title_changed",
        "http_tech_changed",
        "tls_cert_changed",
    } <= kinds


async def test_httpx_unknown_host_creates_finding(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install(
        "httpx_probe",
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "host": "ghost.example.test",
                    "url": "https://ghost.example.test/",
                    "status_code": 200,
                    "tech": [],
                    "ips": [],
                    "tls": {},
                }
            ],
        ),
    )
    await _enqueue_scan(
        client, analyst_user, organization, "httpx_probe", "example.test"
    )
    await _tick(client, admin_user)

    findings = await client.get(
        "/api/v1/easm/findings",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    values = {f["value"] for f in findings.json()}
    assert "ghost.example.test" in values


# --- DNS refresh --------------------------------------------------------


async def test_dns_refresh_emits_spf_and_dmarc_changes(
    client: AsyncClient, analyst_user, admin_user, organization
):
    # Pre-create email_domain with old SPF/DMARC
    a = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "email_domain",
            "value": "mail.dnstest.example",
            "details": {
                "domain": "mail.dnstest.example",
                "dmarc_policy": "none",
            },
        },
        headers=_hdr(analyst_user),
    )
    assert a.status_code == 201, a.text

    # First refresh → seeds the dns block
    _install(
        "dns_refresh",
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "domain": "mail.dnstest.example",
                    "a": ["10.0.0.1"],
                    "mx": ["10 mx1.dnstest.example."],
                    "ns": ["ns1.dnstest.example.", "ns2.dnstest.example."],
                    "txt": ["v=spf1 ip4:10.0.0.1 -all"],
                    "spf": "v=spf1 ip4:10.0.0.1 -all",
                    "dmarc": "v=DMARC1; p=none",
                }
            ],
        ),
    )
    await _enqueue_scan(
        client,
        analyst_user,
        organization,
        "dns_refresh",
        "mail.dnstest.example",
    )
    await _tick(client, admin_user)

    # Second refresh — SPF + DMARC drift
    _install(
        "dns_refresh",
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "domain": "mail.dnstest.example",
                    "a": ["10.0.0.1"],
                    "mx": ["10 mx1.dnstest.example."],
                    "ns": ["ns1.dnstest.example.", "ns2.dnstest.example."],
                    "txt": ["v=spf1 ip4:10.0.0.99 -all"],
                    "spf": "v=spf1 ip4:10.0.0.99 -all",
                    "dmarc": "v=DMARC1; p=reject",
                }
            ],
        ),
    )
    await _enqueue_scan(
        client,
        analyst_user,
        organization,
        "dns_refresh",
        "mail.dnstest.example",
    )
    await _tick(client, admin_user)

    changes = await client.get(
        "/api/v1/easm/changes",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    kinds = {c["kind"] for c in changes.json()}
    assert "spf_changed" in kinds
    assert "dmarc_changed" in kinds


# --- Failure path -------------------------------------------------------


async def test_runner_failure_marks_job_failed(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install(
        "subdomain_enum",
        RunnerOutput(
            succeeded=False, error_message="binary not found", duration_ms=5
        ),
    )
    job_id = await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "boom.example"
    )
    await _tick(client, admin_user)

    jobs = await client.get(
        "/api/v1/onboarding/discovery-jobs",
        params={
            "organization_id": str(organization["id"]),
            "status": "failed",
        },
        headers=_hdr(analyst_user),
    )
    matching = [j for j in jobs.json() if j["id"] == job_id]
    assert matching, "expected a failed job for the boom target"
    assert matching[0]["status"] == "failed"
    assert "binary not found" in (matching[0]["error_message"] or "")


# --- Worker semantics --------------------------------------------------


async def test_worker_tick_only_processes_queued_jobs(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install("subdomain_enum", RunnerOutput(succeeded=True, items=[{"host": "x.example.test"}]))
    await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "example.test"
    )

    first = await _tick(client, admin_user)
    assert first["jobs_processed"] >= 1
    # Subsequent tick has nothing to do for OUR org's jobs (queue may be empty
    # globally too, but we don't assume).
    second = await _tick(client, admin_user)
    assert second["jobs_processed"] == 0


async def test_tick_admin_only(client: AsyncClient, analyst_user):
    r = await client.post(
        "/api/v1/easm/worker/tick", json={"max_jobs": 1}, headers=_hdr(analyst_user)
    )
    assert r.status_code == 403


# --- Finding lifecycle -------------------------------------------------


async def test_promote_finding_creates_asset(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install(
        "subdomain_enum",
        RunnerOutput(
            succeeded=True,
            items=[{"host": "promoteme.example.test"}],
        ),
    )
    await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "example.test"
    )
    await _tick(client, admin_user)

    findings = await client.get(
        "/api/v1/easm/findings",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    fid = findings.json()[0]["id"]

    promote = await client.post(
        f"/api/v1/easm/findings/{fid}/promote",
        json={"criticality": "high", "tags": ["promoted"]},
        headers=_hdr(analyst_user),
    )
    assert promote.status_code == 200
    assert promote.json()["state"] == "promoted"

    asset_lookup = await client.get(
        "/api/v1/assets",
        params={
            "organization_id": str(organization["id"]),
            "asset_type": "subdomain",
        },
        headers=_hdr(analyst_user),
    )
    values = {a["value"] for a in asset_lookup.json()}
    assert "promoteme.example.test" in values

    # Promoting again is a 409
    again = await client.post(
        f"/api/v1/easm/findings/{fid}/promote",
        json={},
        headers=_hdr(analyst_user),
    )
    assert again.status_code == 409


async def test_dismiss_finding(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install(
        "subdomain_enum",
        RunnerOutput(succeeded=True, items=[{"host": "junk.example.test"}]),
    )
    await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "example.test"
    )
    await _tick(client, admin_user)

    findings = await client.get(
        "/api/v1/easm/findings",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    fid = findings.json()[0]["id"]

    r = await client.post(
        f"/api/v1/easm/findings/{fid}/dismiss",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()["state"] == "dismissed"


# --- Tenant isolation ---------------------------------------------------


async def test_changes_scoped_to_organization(
    client: AsyncClient,
    analyst_user,
    admin_user,
    organization,
    second_organization,
):
    _install(
        "subdomain_enum",
        RunnerOutput(succeeded=True, items=[{"host": "iso-a.example.test"}]),
    )
    await _enqueue_scan(
        client, analyst_user, organization, "subdomain_enum", "example.test"
    )
    await _tick(client, admin_user)

    listed_b = await client.get(
        "/api/v1/easm/changes",
        params={"organization_id": str(second_organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert listed_b.status_code == 200
    assert all(c["asset_id"] is None or c.get("organization_id") == str(second_organization["id"])
               for c in listed_b.json())
    # Org B should see no changes for org A's discovery
    summaries = " ".join(c["summary"] for c in listed_b.json())
    assert "iso-a.example.test" not in summaries
