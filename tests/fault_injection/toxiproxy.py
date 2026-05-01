"""Toxiproxy pytest fixture.

Provides a thin Python client (no extra dependencies — Toxiproxy's
admin API is plain HTTP+JSON) plus pytest fixtures that build proxies
in front of Postgres, MinIO, and Redis. Each test that uses the
fixtures is automatically skipped when the toxiproxy container isn't
reachable, so this file is safe to import in any environment.

Toxics applied per-test get torn down on fixture exit. The base
proxies themselves persist for the duration of the test session to
amortise setup cost.

URL conventions
---------------
    upstream services run on the standard test ports (55432 postgres,
    9100 minio, 56379 redis); toxiproxy listens on its own offset
    ports (55433 postgres, 9200 minio, 6380 redis). Tests that want
    fault-tolerance probing point their connection strings at the
    Toxiproxy port; tests that don't, hit upstream directly.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator


_TOXIPROXY_ADMIN = os.environ.get(
    "ARGUS_TOXIPROXY_ADMIN", "http://127.0.0.1:58474"
).rstrip("/")


@dataclass
class ProxyConfig:
    name: str
    listen: str
    upstream: str


_DEFAULT_PROXIES: tuple[ProxyConfig, ...] = (
    ProxyConfig("argus_postgres", "0.0.0.0:5433", "argus-test-postgres:5432"),
    ProxyConfig("argus_minio",    "0.0.0.0:9200", "argus-test-minio:9000"),
    ProxyConfig("argus_redis",    "0.0.0.0:6380", "argus-test-redis:6379"),
)


def _request(method: str, path: str, body: dict | None = None) -> dict | list | None:
    url = f"{_TOXIPROXY_ADMIN}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 — local trusted endpoint
        body_bytes = resp.read()
        if not body_bytes:
            return None
        return json.loads(body_bytes)


def is_available() -> bool:
    """True iff the toxiproxy admin API is reachable."""
    try:
        urllib.request.urlopen(f"{_TOXIPROXY_ADMIN}/version", timeout=2).read()  # noqa: S310
        return True
    except (urllib.error.URLError, OSError):
        return False


def reset() -> None:
    """Wipe every proxy + toxic. Idempotent."""
    _request("POST", "/reset")


def ensure_proxies(proxies: tuple[ProxyConfig, ...] = _DEFAULT_PROXIES) -> None:
    """Create the standard proxies if they don't already exist."""
    existing_raw = _request("GET", "/proxies")
    if not isinstance(existing_raw, dict):
        existing_names = set()
    else:
        existing_names = set(existing_raw.keys())
    for p in proxies:
        if p.name in existing_names:
            continue
        _request("POST", "/proxies", body={
            "name": p.name,
            "listen": p.listen,
            "upstream": p.upstream,
            "enabled": True,
        })


def add_toxic(
    proxy: str,
    *,
    name: str,
    type: str,
    attributes: dict,
    stream: str = "downstream",
    toxicity: float = 1.0,
) -> None:
    """Add a toxic to a proxy. Common types:

        latency        attrs={"latency": 5000} (ms)
        timeout        attrs={"timeout": 1000} (ms before drop)
        bandwidth      attrs={"rate": 32}      (KB/s)
        slow_close     attrs={"delay": 1000}   (ms)
        slicer         attrs={"average_size":1024,"size_variation":0,"delay":0}
        limit_data     attrs={"bytes": 1024}   (drop after N bytes)
        reset_peer     attrs={"timeout": 0}    (RST after timeout ms)
    """
    _request(f"POST", f"/proxies/{proxy}/toxics", body={
        "name": name,
        "type": type,
        "stream": stream,
        "toxicity": toxicity,
        "attributes": attributes,
    })


def remove_toxic(proxy: str, toxic_name: str) -> None:
    _request("DELETE", f"/proxies/{proxy}/toxics/{toxic_name}")


@contextmanager
def toxic(proxy: str, **kwargs) -> Iterator[None]:
    """Context manager: install a toxic for the duration of the block."""
    name = kwargs.get("name", f"argus_test_{proxy}_{kwargs['type']}")
    kwargs["name"] = name
    add_toxic(proxy, **kwargs)
    try:
        yield
    finally:
        try:
            remove_toxic(proxy, name)
        except urllib.error.HTTPError:
            # Already removed (test crashed) — ignore.
            pass


# --- pytest plumbing -------------------------------------------------


def requires_toxiproxy(item):
    """pytest skip marker. Use as ``pytestmark = requires_toxiproxy``
    at module level or per-test via ``@pytest.mark.skipif(...)``.
    """
    import pytest

    return pytest.mark.skipif(
        not is_available(),
        reason=(
            "Toxiproxy not reachable at "
            f"{_TOXIPROXY_ADMIN}. Bring it up with "
            "`docker compose -p argus -f docker-compose.test.yml up -d "
            "argus-test-toxiproxy` to enable the full-stack resilience suite."
        ),
    )(item)


__all__ = [
    "ProxyConfig",
    "is_available",
    "reset",
    "ensure_proxies",
    "add_toxic",
    "remove_toxic",
    "toxic",
    "requires_toxiproxy",
]
