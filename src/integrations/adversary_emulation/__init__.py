"""Adversary-emulation validation loop (P3 #3.5).

Three pieces wire together:

  atomic_red_team   Curated subset of Red Canary's Atomic Red Team
                    YAMLs + a filesystem loader for the full corpus
                    (operator clones github.com/redcanaryco/atomic-
                    red-team and points ARGUS_ATOMIC_RED_TEAM_PATH at
                    the local checkout). Tests are indexed by MITRE
                    ATT&CK technique ID.

  caldera           MITRE Caldera REST client. Lists abilities +
                    adversaries + operations on a customer-deployed
                    Caldera server; v1 is read-only + start-operation.
                    Operator config: ARGUS_CALDERA_URL +
                    ARGUS_CALDERA_API_KEY.

  coverage          Coverage scorer: given a window of
                    (executed_techniques, detected_events), compute
                    per-technique coverage = detected / executed and
                    surface gaps. Pairs with the SIEM connectors
                    (P2 #2.7) so the customer's Wazuh / Suricata /
                    Splunk fired-events count as detections.

The full validation loop:
  1. Pick a technique
  2. ``atomic_red_team.tests_for(tid)`` lists the executable tests
  3. ``velociraptor_schedule_collection`` runs the test on an endpoint
  4. The customer's SIEM ingests the test's telemetry; Argus pulls
     fired events back via the SIEM connector
  5. ``coverage.score(executed, detected)`` produces the per-technique
     coverage map shown on the dashboard

This module is tooling — it doesn't drive the loop end-to-end on its
own. The threat_hunter_agent calls into these surfaces.
"""

from __future__ import annotations

from .atomic_red_team import (
    AtomicTest,
    available as atomic_red_team_available,
    list_techniques as atomic_list_techniques,
    tests_for as atomic_tests_for,
)
from .caldera import (
    CalderaResult,
    is_configured as caldera_configured,
    list_abilities as caldera_list_abilities,
    list_operations as caldera_list_operations,
    start_operation as caldera_start_operation,
)
from .coverage import (
    CoverageEntry,
    CoverageReport,
    score as coverage_score,
)


__all__ = [
    "AtomicTest",
    "atomic_red_team_available",
    "atomic_list_techniques",
    "atomic_tests_for",
    "CalderaResult",
    "caldera_configured",
    "caldera_list_abilities",
    "caldera_list_operations",
    "caldera_start_operation",
    "CoverageEntry",
    "CoverageReport",
    "coverage_score",
]
