"""STIX-Shifter translation (P2 #2.5).

Wraps the IBM/OCA `stix-shifter` library so analysts can translate a
STIX 2.x pattern (e.g. ``[ipv4-addr:value = '203.0.113.7']``) into the
native query language for whichever SIEM / data store the customer
runs:

  splunk           Splunk SPL (search …)
  elastic_ecs      Elastic Lucene over ECS-shaped events
  qradar           IBM QRadar AQL
  azure_sentinel   Microsoft Sentinel (Graph Security Alert v2 query)

This pairs with :mod:`src.intel.sigma_rules` (P2 #2.3): Sigma is the
"detection rule" surface and STIX is the "indicator-pattern" surface.
Every IOC in Argus can therefore be projected into either format.

Each stix-shifter module is independently pinned in ``requirements.txt``;
the wrapper detects which modules import cleanly so a slimmed-down
deployment that skipped, say, ``stix-shifter-modules-qradar`` simply
omits QRadar from the response.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# Module name → friendly display name. Order is the friendly listing
# order in the API response.
SUPPORTED_MODULES: tuple[tuple[str, str], ...] = (
    ("splunk", "Splunk SPL"),
    ("elastic_ecs", "Elastic ECS (Lucene)"),
    ("qradar", "IBM QRadar AQL"),
    ("azure_sentinel", "Microsoft Sentinel"),
)


def available_modules() -> list[dict[str, str]]:
    """Return the list of stix-shifter modules importable in this venv.

    Each entry has ``id`` (module name passed to stix-shifter) and
    ``label`` (display name)."""
    out: list[dict[str, str]] = []
    for module_id, label in SUPPORTED_MODULES:
        try:
            __import__(f"stix_shifter_modules.{module_id}", fromlist=["entry_point"])
            out.append({"id": module_id, "label": label})
        except ImportError:
            continue
    return out


@dataclass
class StixTranslation:
    module: str
    queries: list[str]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "queries": self.queries,
            "error": self.error,
        }


def translate_pattern(
    stix_pattern: str,
    *,
    modules: list[str] | None = None,
    options: dict[str, Any] | None = None,
) -> list[StixTranslation]:
    """Translate ``stix_pattern`` (STIX 2.x) into each requested module.

    ``modules`` defaults to every module from :func:`available_modules`.
    Per-module errors are captured into the result rather than aborting
    the whole batch — one broken module on QRadar doesn't deny the
    Splunk operator their SPL output.
    """
    from stix_shifter.stix_translation import stix_translation as _st

    enabled = modules or [m["id"] for m in available_modules()]
    translator = _st.StixTranslation()
    out: list[StixTranslation] = []

    # stix-shifter's ``translate`` expects ``options`` as a dict
    # (default ``{}``); passing a JSON string yields an opaque
    # 'str object does not support item assignment' error from inside
    # the connector loader.
    options = dict(options or {})
    import json  # still needed for normalising dict-shaped queries below

    for module in enabled:
        try:
            result = translator.translate(
                module, "query", "{}", stix_pattern, options,
            )
            queries = result.get("queries") if isinstance(result, dict) else None
            if not queries:
                err = (result.get("error") or "no queries returned"
                       if isinstance(result, dict) else "translation failed")
                out.append(StixTranslation(module=module, queries=[],
                                            error=err[:300]))
                continue
            # ``queries`` is sometimes a list of strings, sometimes a
            # list of dicts (Sentinel) — normalise to strings.
            normalised: list[str] = []
            for q in queries:
                if isinstance(q, str):
                    normalised.append(q)
                else:
                    normalised.append(json.dumps(q, sort_keys=True))
            out.append(StixTranslation(
                module=module, queries=normalised, error=None,
            ))
        except Exception as exc:  # noqa: BLE001 — keep going to next module
            logger.warning("[stix-shifter] %s translation failed: %s", module, exc)
            out.append(StixTranslation(
                module=module, queries=[], error=str(exc)[:300],
            ))
    return out


# ── Convenience for IOC → STIX → translation ────────────────────────


_IOC_TO_STIX: dict[str, str] = {
    "ip":       "ipv4-addr:value",
    "ipv4":     "ipv4-addr:value",
    "ipv6":     "ipv6-addr:value",
    "domain":   "domain-name:value",
    "url":      "url:value",
    "hash":     "file:hashes.'SHA-256'",
    "md5":      "file:hashes.MD5",
    "sha1":     "file:hashes.'SHA-1'",
    "sha256":   "file:hashes.'SHA-256'",
    "email":    "email-addr:value",
}


def stix_pattern_for_ioc(ioc_type: str, ioc_value: str) -> str:
    """Build a STIX 2.x pattern from an Argus IOC.

    Hash inputs auto-route to the correct hash slot when the caller
    didn't supply the algorithm. SHA-256 is the safe default — the
    fallback ``hash`` mapping above.
    """
    safe = (ioc_value or "").replace("'", "''")
    if ioc_type.lower() == "hash":
        n = len(safe)
        if n == 32:
            field = _IOC_TO_STIX["md5"]
        elif n == 40:
            field = _IOC_TO_STIX["sha1"]
        else:
            field = _IOC_TO_STIX["sha256"]
    else:
        field = _IOC_TO_STIX.get(ioc_type.lower(), f"{ioc_type}:value")
    return f"[{field} = '{safe}']"


def translate_for_ioc(
    ioc_type: str, ioc_value: str,
    *,
    modules: list[str] | None = None,
) -> tuple[str, list[StixTranslation]]:
    """One-shot ``IOC → (stix_pattern, translations)``."""
    pattern = stix_pattern_for_ioc(ioc_type, ioc_value)
    return pattern, translate_pattern(pattern, modules=modules)
