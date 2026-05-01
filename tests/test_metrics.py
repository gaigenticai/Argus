"""Audit C6 — Prometheus metrics smoke tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_metrics_endpoint_exposes_prometheus_format(client: AsyncClient):
    # Hit a real endpoint first so http_requests_total has a sample.
    await client.get("/health")

    r = await client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    # Standard Prometheus exposition: HELP and TYPE comments, then samples.
    assert "argus_http_requests_total" in body
    assert "argus_http_request_duration_seconds" in body
    assert "# TYPE argus_http_requests_total counter" in body


async def test_metrics_records_request_path_template(client: AsyncClient):
    # Force a known route so we can verify the path label.
    await client.get("/health")
    r = await client.get("/metrics")
    assert 'path="/health"' in r.text or "/health" in r.text
