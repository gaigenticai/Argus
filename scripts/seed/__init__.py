"""Layered seed package for Argus.

Three modes, selected by ``ARGUS_SEED_MODE`` env var:

* ``minimal`` (default in compose) — system organisation + admin user only.
  Safe for production-style deployments. The schema is initialised but the
  dashboard renders documented empty states ("no feeds configured", "BIN
  registry empty", etc.) instead of pretending data exists.
* ``realistic`` — full sales-walkthrough fixture: orgs across industries,
  IOCs, threat actors, brand suspects, EASM exposures, DLP/leakage, cases,
  SLA, news, advisories, MITRE catalogue subset, vendor scorecards,
  notification channels, BIN ranges, brand logos, audit history, sample
  reports, DMARC reports, onboarding sessions. Every dashboard screen has
  representative data.
* ``stress`` — high-cardinality variant for performance/UX validation
  (currently calls realistic; reserved for future cardinality dialing).

Idempotency: every section short-circuits on existing data. Re-running is
safe and a no-op when the dataset is already present. To wipe and re-seed,
use ``python -m scripts.seed --reset``.

Entry points:

* ``python -m scripts.seed`` — runs whatever ``ARGUS_SEED_MODE`` says
  (defaults to ``minimal``)
* ``ARGUS_SEED_MODE=realistic python -m scripts.seed`` — explicit
* ``python -m scripts.seed --mode realistic`` — flag overrides env
"""
