"""Sigma rule generation + multi-SIEM translation (P2 #2.3).

Two surfaces:

  :func:`build_rule_yaml` — given a high-level descriptor (an IOC, a
  MITRE technique attachment, or an alert), produce a syntactically
  valid Sigma YAML document that downstream backends accept.

  :func:`translate_rule` — take a Sigma YAML and convert it to every
  registered SIEM backend in parallel: Splunk SPL · Elastic Lucene ·
  Elastic ES|QL · Microsoft Sentinel KQL · Microsoft 365 Defender KQL
  · IBM QRadar AQL.

Usage from the API:

  POST /intel/sigma/from-ioc        {ioc_value, ioc_type, ...}
  POST /intel/sigma/from-technique  {technique_id, ...}
  POST /intel/sigma/translate       {sigma_yaml}

Why this matters
----------------
Argus's "executable intel" promise: every alert / IOC ships with a
detection rule the customer's existing SIEM can run. RF charges
$150K+/yr for STIX-only export. We give the customer the actual
Splunk SPL / Sentinel KQL string, generated from the alert.

Backend availability is checked at import time — if a backend module
is missing (e.g. the operator skipped pysigma-backend-splunk during
``pip install``) it's omitted from the translation result rather than
raising; the dashboard shows the available subset.
"""

from __future__ import annotations

import logging
import uuid as _uuid
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ── Backend registration ────────────────────────────────────────────


@dataclass
class _BackendSpec:
    name: str          # surface name in the API response
    module: str        # importable module path under sigma.backends.*
    cls: str           # backend class name
    output_format: str | None = None  # if the backend supports multiple


_BACKEND_SPECS: tuple[_BackendSpec, ...] = (
    _BackendSpec("splunk_spl",       "sigma.backends.splunk",         "SplunkBackend"),
    _BackendSpec("elastic_lucene",   "sigma.backends.elasticsearch",  "LuceneBackend"),
    _BackendSpec("elastic_eql",      "sigma.backends.elasticsearch",  "EqlBackend"),
    _BackendSpec("sentinel_kql",     "sigma.backends.kusto",          "KustoBackend"),
    # The microsoft365defender backend repackaged as a kusto-table
    # specialisation in pysigma >= 0.3 — the public class is still
    # KustoBackend but lives under a separate module so customers can
    # discover it via PyPI search.
    _BackendSpec("m365defender_kql", "sigma.backends.microsoft365defender",
                                     "KustoBackend"),
    _BackendSpec("qradar_aql",       "sigma.backends.QRadarAQL",      "QRadarAQLBackend"),
)


def _resolve_backend(spec: _BackendSpec) -> Any | None:
    try:
        mod = __import__(spec.module, fromlist=[spec.cls])
        cls = getattr(mod, spec.cls)
        return cls()
    except (ImportError, AttributeError) as exc:
        logger.debug("[sigma] backend %s unavailable: %s", spec.name, exc)
        return None


def available_backends() -> list[str]:
    """Return the ``name`` of every backend that imports cleanly."""
    out = []
    for spec in _BACKEND_SPECS:
        if _resolve_backend(spec) is not None:
            out.append(spec.name)
    return out


# ── Rule generation ─────────────────────────────────────────────────


# IOC-type → ECS field hint. Sigma rules historically used Windows
# event-log fields, but the modern recommendation is "logsource:
# category: threat_intel" with ECS-aligned fields. We default to
# Windows process_creation when no hint fits because that's the
# fallback every backend supports.

_IOC_FIELD_MAP: dict[str, str] = {
    "ip":       "DestinationIp",
    "domain":   "DestinationHostname",
    "url":      "RequestUrl",
    "hash":     "Hash",
    "filename": "TargetFilename",
    "email":    "Sender",
    "username": "TargetUsername",
}


def build_rule_yaml(
    *,
    title: str,
    description: str,
    ioc_type: str | None = None,
    ioc_value: str | None = None,
    technique_id: str | None = None,
    extra_fields: dict[str, str] | None = None,
    level: str = "high",
    rule_id: str | None = None,
) -> str:
    """Compose a single Sigma rule YAML.

    The output is byte-stable for a fixed input (rule_id pinned), so
    callers can hash + dedup rule outputs. Pass an explicit ``rule_id``
    for stability; otherwise a UUIDv4 is generated.
    """
    # Pin rule_id to a well-formed UUIDv5 when the caller didn't supply
    # one — the Sigma spec requires a UUID, not arbitrary IDs, and
    # pysigma's parser rejects 16-char hex strings.
    if rule_id is None:
        rule_id = str(_uuid.uuid4())
    else:
        try:
            rule_id = str(_uuid.UUID(rule_id))
        except ValueError:
            # Treat the supplied string as a stable name and fold it
            # through UUIDv5 so the caller still gets reproducible IDs
            # without us silently substituting a v4.
            rule_id = str(_uuid.uuid5(_uuid.NAMESPACE_URL, rule_id))

    # YAML-safe quoting for fields the caller controls. Title +
    # description frequently contain ":" / "—" / IOC values that
    # break unquoted YAML parsing across pysigma versions.
    def _q(s: str) -> str:
        return "'" + (s or "").replace("'", "''") + "'"

    selection_pairs: list[tuple[str, str]] = []

    if ioc_value and ioc_type:
        field = _IOC_FIELD_MAP.get(ioc_type.lower(), ioc_type.title())
        v = ioc_value.replace("\\", "\\\\").replace("'", "''")
        selection_pairs.append((field, v))

    if extra_fields:
        for k, v in extra_fields.items():
            v_safe = (v or "").replace("\\", "\\\\").replace("'", "''")
            selection_pairs.append((k, v_safe))

    if not selection_pairs:
        selection_pairs.append(("EventID", "1"))

    # Sigma tags require ``namespace.identifier`` form. ``threat_intel``
    # alone fails the parser. ``tlp.green`` is the universally-accepted
    # fallback when there's no ATT&CK technique to anchor the tag to.
    tag = "tlp.green"
    if technique_id:
        tag_id = technique_id.lower().lstrip("t")
        tag = f"attack.t{tag_id}"

    # Build the YAML line-by-line so indentation is unambiguous —
    # textwrap.dedent + multi-line f-string interpolation has subtle
    # alignment bugs when the interpolated block contains its own
    # newlines.
    lines: list[str] = [
        f"title: {_q(title)}",
        f"id: {rule_id}",
        "status: experimental",
        f"description: {_q(description)}",
        "author: 'Marsad / Argus Threat Intelligence Platform'",
        "date: 2026-05-01",
        "tags:",
        f"  - {tag}",
        "logsource:",
        "  category: threat_intel",
        "detection:",
        "  selection:",
    ]
    for k, v in selection_pairs:
        lines.append(f"    {k}: '{v}'")
    lines.extend([
        "  condition: selection",
        "falsepositives:",
        "  - 'Legitimate traffic to the same destination — verify against asset inventory'",
        f"level: {level}",
        "",
    ])
    return "\n".join(lines)


# ── Translation ─────────────────────────────────────────────────────


@dataclass
class TranslationResult:
    backend: str
    query: str | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend, "query": self.query,
            "error": self.error,
        }


def translate_rule(sigma_yaml: str) -> list[TranslationResult]:
    """Translate a Sigma YAML rule into every available backend.

    Backend errors are captured per-backend rather than aborting the
    whole translation — so one broken rule on QRadar doesn't deny the
    Splunk operator their Sigma → SPL output.
    """
    from sigma.collection import SigmaCollection

    try:
        collection = SigmaCollection.from_yaml(sigma_yaml)
    except Exception as exc:  # noqa: BLE001 — surface parse errors uniformly
        return [TranslationResult(backend="parser", query=None,
                                  error=f"sigma yaml parse error: {exc}")]

    out: list[TranslationResult] = []
    for spec in _BACKEND_SPECS:
        backend = _resolve_backend(spec)
        if backend is None:
            continue
        try:
            queries = backend.convert(collection)
            if not queries:
                out.append(TranslationResult(
                    backend=spec.name, query=None,
                    error="empty result",
                ))
                continue
            # All current backends emit a list of one string per rule;
            # Argus rules are single-rule documents so [0] is correct.
            query = queries[0] if isinstance(queries, list) else str(queries)
            out.append(TranslationResult(
                backend=spec.name, query=str(query), error=None,
            ))
        except Exception as exc:  # noqa: BLE001 — keep going to next backend
            out.append(TranslationResult(
                backend=spec.name, query=None, error=str(exc)[:300],
            ))
    return out


# ── Convenience wrappers ────────────────────────────────────────────


def translate_for_ioc(
    *,
    ioc_value: str,
    ioc_type: str,
    title: str | None = None,
    description: str | None = None,
    technique_id: str | None = None,
    rule_id: str | None = None,
) -> tuple[str, list[TranslationResult]]:
    """One-shot ``IOC → (yaml, translations)``."""
    yaml = build_rule_yaml(
        title=title or f"Argus IOC match: {ioc_value}",
        description=(
            description or
            f"Detect activity matching {ioc_type} indicator {ioc_value} "
            f"sourced from the Argus threat-intelligence platform."
        ),
        ioc_type=ioc_type, ioc_value=ioc_value,
        technique_id=technique_id, rule_id=rule_id,
    )
    return yaml, translate_rule(yaml)


def translate_for_technique(
    *,
    technique_id: str,
    title: str | None = None,
    description: str | None = None,
    selection: dict[str, str] | None = None,
    rule_id: str | None = None,
) -> tuple[str, list[TranslationResult]]:
    """One-shot ``technique → (yaml, translations)``."""
    yaml = build_rule_yaml(
        title=title or f"Argus technique match: {technique_id}",
        description=(
            description or
            f"Detect activity associated with MITRE ATT&CK {technique_id}, "
            f"as tagged by the Argus triage agent."
        ),
        technique_id=technique_id,
        extra_fields=selection or {},
        rule_id=rule_id,
    )
    return yaml, translate_rule(yaml)
