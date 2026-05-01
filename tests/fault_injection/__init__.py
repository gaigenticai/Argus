"""Fault-injection test harness (audit E12).

Two layers:

* :mod:`tests.fault_injection.injector` — in-process FaultInjector.
  Monkey-patches aiohttp / asyncpg / Redis connection helpers with
  configurable failures (timeouts, 5xx, connection-refused, partial
  reads). Runs in any CI runner without extra infrastructure.

* :mod:`tests.fault_injection.toxiproxy` — Toxiproxy fixture.
  Talks to the ``argus-test-toxiproxy`` container (see
  ``docker-compose.test.yml``) to build proxies that sit in front of
  Postgres / MinIO / Redis. Tests that import from this module are
  automatically skipped when the container isn't running, so the
  in-process layer remains the default and Toxiproxy is opt-in for
  engineers who want a full-stack resilience drill.

The two layers are intentionally redundant: the in-process layer
catches the cases where Argus wraps the failure correctly *in code*;
the Toxiproxy layer catches the cases where the wrapping breaks down
because the actual TCP socket dies in a way our mocks didn't model.
"""

from __future__ import annotations
