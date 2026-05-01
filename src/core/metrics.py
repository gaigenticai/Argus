"""Prometheus metrics (Audit C6).

Exposes ``/metrics`` in the standard Prometheus exposition format, plus
a small set of named counters / histograms the rest of the codebase
can import. Banks running observability stacks (Datadog Agent +
Prometheus, Grafana Agent, etc.) scrape this directly.

What we instrument by default:

- ``argus_http_requests_total{method,path,status}`` — request count.
- ``argus_http_request_duration_seconds_bucket{...}`` — latency histogram.
- ``argus_easm_jobs_processed_total{kind,outcome}`` — worker throughput.
- ``argus_sla_evaluations_total{outcome}`` — SLA tick health.

The HTTP middleware uses the route *template* (``/api/v1/assets/{id}``)
not the raw path, so high-cardinality user IDs / asset IDs don't blow
up label cardinality in Prometheus.
"""

from __future__ import annotations

import time
from typing import Callable

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)


registry = CollectorRegistry()


http_requests_total = Counter(
    "argus_http_requests_total",
    "Total HTTP requests served by Argus, partitioned by method, path "
    "template, and response status.",
    labelnames=("method", "path", "status"),
    registry=registry,
)

http_request_duration_seconds = Histogram(
    "argus_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    labelnames=("method", "path"),
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
    ),
    registry=registry,
)


easm_jobs_processed_total = Counter(
    "argus_easm_jobs_processed_total",
    "DiscoveryJob outcomes per worker tick.",
    labelnames=("kind", "outcome"),
    registry=registry,
)


sla_evaluations_total = Counter(
    "argus_sla_evaluations_total",
    "SLA evaluation outcomes per worker tick.",
    labelnames=("outcome",),
    registry=registry,
)


def render_metrics() -> tuple[bytes, str]:
    """Return ``(body, content_type)`` for the /metrics endpoint."""
    return generate_latest(registry), CONTENT_TYPE_LATEST


def install_http_metrics_middleware(app) -> None:
    """Attach the request-timing middleware to a FastAPI app.

    Uses the matched route's path template — falls back to the raw URL
    path for unmatched routes so we still see 404 traffic.
    """

    @app.middleware("http")
    async def _record(request, call_next: Callable):
        start = time.perf_counter()
        response = None
        try:
            response = await call_next(request)
            return response
        finally:
            elapsed = time.perf_counter() - start
            route = request.scope.get("route")
            path_template = (
                getattr(route, "path", None) or request.url.path or "unknown"
            )
            method = request.method
            status = str(response.status_code) if response is not None else "500"
            http_requests_total.labels(
                method=method, path=path_template, status=status
            ).inc()
            http_request_duration_seconds.labels(
                method=method, path=path_template
            ).observe(elapsed)


__all__ = [
    "registry",
    "render_metrics",
    "install_http_metrics_middleware",
    "http_requests_total",
    "http_request_duration_seconds",
    "easm_jobs_processed_total",
    "sla_evaluations_total",
]
