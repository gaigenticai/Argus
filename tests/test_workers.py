"""Audit B2 + F1 — background worker smoke tests.

Verifies that ``src.workers.runner`` actually drains the EASM
``DiscoveryJob`` queue and runs SLA evaluation per organisation. The
ticks are invoked directly (not via subprocess) so we exercise the same
code paths the deployed `argus-worker` container would run.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from src.easm.runners import (
    Runner,
    RunnerOutput,
    get_runner_registry,
    reset_runner_registry,
    set_runner_registry,
)
from src.workers import runner as worker_runner

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


class _FakeRunner(Runner):
    def __init__(self, output: RunnerOutput):
        self._output = output

    async def run(self, target, parameters=None):
        return self._output


@pytest.fixture
def _stub_dns_runner():
    reset_runner_registry()
    registry = dict(get_runner_registry())
    registry["dns_refresh"] = _FakeRunner(
        RunnerOutput(
            succeeded=True,
            items=[
                {
                    "domain": "example.test",
                    "a": ["1.2.3.4"],
                    "mx": [],
                    "ns": [],
                    "txt": [],
                    "spf": None,
                    "dmarc": None,
                }
            ],
            duration_ms=1,
        )
    )
    set_runner_registry(registry)
    yield
    reset_runner_registry()


async def test_worker_easm_tick_drains_queue(
    client: AsyncClient, analyst_user, organization, _stub_dns_runner
):
    """Enqueue an EASM job via the API, then run the worker tick directly.

    The job must transition out of QUEUED — proves the worker module is
    wired to a working session factory, the runner registry, and the
    persistence layer.
    """
    enq = await client.post(
        "/api/v1/easm/scan",
        json={
            "organization_id": str(organization["id"]),
            "kind": "dns_refresh",
            "target": "example.test",
        },
        headers=_hdr(analyst_user),
    )
    assert enq.status_code == 201, enq.text
    job_id = enq.json()["job_id"]

    await worker_runner._easm_tick_once()

    after = await client.get(
        "/api/v1/onboarding/discovery-jobs",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert after.status_code == 200
    job = next((j for j in after.json() if j["id"] == job_id), None)
    assert job is not None, "enqueued job missing from listing"
    assert job["status"] in ("succeeded", "failed")


async def test_worker_sla_tick_runs_without_error(
    client: AsyncClient, organization
):
    """SLA tick should iterate every org and evaluate cases without
    raising — even when the org has zero cases or zero policies.
    """
    await worker_runner._sla_tick_once()


async def test_worker_requeues_stale_running_jobs(
    client: AsyncClient, analyst_user, organization, _stub_dns_runner
):
    """Audit C12 — a job stuck in ``running`` (because a previous worker
    was killed mid-execution) must be requeued on the next worker boot.
    """
    enq = await client.post(
        "/api/v1/easm/scan",
        json={
            "organization_id": str(organization["id"]),
            "kind": "dns_refresh",
            "target": "stale.example.test",
        },
        headers=_hdr(analyst_user),
    )
    job_id = enq.json()["job_id"]

    # Simulate a worker that crashed mid-execution.
    from sqlalchemy import text as _text
    from src.storage import database as _db

    async with _db.async_session_factory() as s:
        await s.execute(
            _text(
                "UPDATE discovery_jobs SET status='running', started_at=NOW() "
                "WHERE id = :id"
            ),
            {"id": job_id},
        )
        await s.commit()

    requeued = await worker_runner._requeue_stale_running_jobs()
    assert requeued >= 1

    # Now a tick should be able to claim and finish it.
    await worker_runner._easm_tick_once()
    after = await client.get(
        "/api/v1/onboarding/discovery-jobs",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    job = next(j for j in after.json() if j["id"] == job_id)
    assert job["status"] in ("succeeded", "failed")
