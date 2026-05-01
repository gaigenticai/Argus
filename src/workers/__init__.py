"""Argus background worker entry point (Audit B2 + F1).

Runs out-of-process from the API. Owns:

- EASM ``DiscoveryJob`` queue tick loop (claims + executes jobs).
- Per-organisation SLA evaluation tick (re-evaluates every open Case).
- News-feed and threat-intel polling are intentionally *not* in here yet
  — they are still triggered manually until we wire HTTP fetchers behind
  SSRF-safe URL guards. Adding them is a one-liner once the fetcher
  helpers exist.

Run with::

    python -m src.workers

Configurable via env:

- ``ARGUS_WORKER_EASM_INTERVAL`` — seconds between EASM ticks (default 5)
- ``ARGUS_WORKER_SLA_INTERVAL``  — seconds between SLA ticks (default 300)
- ``ARGUS_WORKER_EASM_BATCH``    — max jobs per EASM tick (default 10)

The worker shares the same Postgres + MinIO + secrets the API uses, so
deploy it as a second Railway service pointing at the same env file.
"""

from __future__ import annotations

