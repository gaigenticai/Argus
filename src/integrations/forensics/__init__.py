"""Incident-response forensics tools (P3 #3.11).

Three tools wrapped behind a uniform interface so the
``case_copilot_agent`` (and the IOC pivot pages) can drive deep
forensic enrichment from inside Argus:

  volatility    Volatility 3 memory-image analysis (CLI subprocess —
                operator installs vol3 separately, we shell out)
  velociraptor  Velociraptor remote-forensics server API
                (artifact runs + collection downloads)
  circl_hashlookup  Already shipped at src/enrichment/circl.py; re-
                    exported here for uniformity so case_copilot has
                    one import surface

All three are **opt-in** — the wrappers detect availability and
return structured "unavailable" results when the operator hasn't
configured them. None are bundled into the runtime image.
"""

from __future__ import annotations

from .volatility import (
    VolatilityResult,
    is_available as volatility_available,
    run_plugin as volatility_run_plugin,
)
from .velociraptor import (
    VelociraptorResult,
    is_configured as velociraptor_configured,
    list_clients as velociraptor_list_clients,
    schedule_collection as velociraptor_schedule_collection,
)


__all__ = [
    "VolatilityResult",
    "volatility_available",
    "volatility_run_plugin",
    "VelociraptorResult",
    "velociraptor_configured",
    "velociraptor_list_clients",
    "velociraptor_schedule_collection",
]
