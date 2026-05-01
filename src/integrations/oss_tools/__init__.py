"""OSS-tool installer (admin-onboarding flow).

When an Argus admin signs in for the first time, the dashboard offers
to install a curated set of open-source security tools alongside the
Argus stack:

  caldera        MITRE Caldera 5.x — adversary emulation
  shuffle        Shuffle SOAR — playbooks + workflow runner
  velociraptor   Velociraptor — live-endpoint forensics
  misp           MISP — threat-intel sharing platform
  opencti        OpenCTI — threat-intel platform with relationship graph
  wazuh          Wazuh — open-source SIEM + EDR

Each tool is **optional** — Argus runs end-to-end without any of them.
Selecting one wires up its docker-compose profile in
``compose.optional.yml`` and populates the matching ``ARGUS_*_URL``
env var so the in-tree connector finds the new service.

Public surface:
  list_catalog()                 catalog of selectable tools
  installer.install_selected     coroutine that drives the install
  installer.install_status       per-tool current state
"""

from __future__ import annotations

from .catalog import (
    OssTool,
    list_catalog,
    tool_by_name,
)


__all__ = [
    "OssTool",
    "list_catalog",
    "tool_by_name",
]
