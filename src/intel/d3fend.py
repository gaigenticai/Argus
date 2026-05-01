"""MITRE D3FEND defensive-technique catalog ingestion (P2 #2.12).

Two surfaces:

  :func:`seed_d3fend_minimal` — installs a 24-row hand-curated subset
  covering the most-relevant defenses against the techniques Argus
  alerts attach. Idempotent. Used by the realistic seed pipeline so a
  fresh install ships a populated catalog.

  :func:`refresh_from_upstream` — admin-triggered full refresh that
  pulls D3FEND's authoritative JSON-LD ontology export (~5 MB) from
  ``https://d3fend.mitre.org/ontologies/d3fend.json``. Replaces the
  curated subset with the full catalog.

Lookup helpers (:func:`lookup`, :func:`defenses_for_attack`) read from
the DB so the catalog is consistent across processes.

Source: https://d3fend.mitre.org/
License: D3FEND knowledge base is published under MIT (per MITRE's
         d3fend repo LICENSE).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.d3fend_oscal import D3FENDTechnique

logger = logging.getLogger(__name__)


_D3FEND_UPSTREAM_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
_CURATED_VERSION = "curated-2026-05-01"
_FULL_VERSION_PREFIX = "upstream"


# 24-entry curated subset covering the most-relevant defenses.
# (d3fend_id, label, tactic, definition, counters_attack_ids)
CURATED_D3FEND: list[tuple[str, str, str, str, list[str]]] = [
    # ── Harden ──────────────────────────────────────────────────────
    ("D3-MFA", "Multi-factor Authentication", "harden",
     "Authenticating using two or more identity factors before granting "
     "access to a system or service.",
     ["T1078", "T1110", "T1110.003", "T1078.004", "T1566.002"]),
    ("D3-SPP", "Strong Password Policy", "harden",
     "Enforcing entropy + rotation + uniqueness on user passwords to "
     "resist credential-guessing attacks.",
     ["T1110", "T1078"]),
    ("D3-AL", "Application Allowlisting", "harden",
     "Restricting executable launch to a vetted list of binaries to "
     "prevent unsigned-payload execution.",
     ["T1059.001", "T1059.005", "T1204.002", "T1218"]),
    ("D3-DLIC", "DNS Local Integrity Checking", "harden",
     "Validating outbound DNS queries against an allowlist to prevent "
     "DNS-tunnelling C2 channels.",
     ["T1071.004"]),
    # ── Detect ──────────────────────────────────────────────────────
    ("D3-NTA", "Network Traffic Analysis", "detect",
     "Inspecting network flows for indicators of compromise — beaconing, "
     "tunnelling, or known-bad TLS fingerprints.",
     ["T1071.001", "T1071.004", "T1572", "T1102"]),
    ("D3-PA", "Process Analysis", "detect",
     "Monitoring running processes for known-malicious patterns "
     "including injection, hollowing, and credential-dump tools.",
     ["T1003.001", "T1055", "T1057"]),
    ("D3-FA", "File Analysis", "detect",
     "Static + dynamic analysis of files at rest to identify malware "
     "before execution.",
     ["T1204.002", "T1027", "T1140"]),
    ("D3-UBA", "User Behavior Analysis", "detect",
     "Modelling user activity to detect anomalies — impossible-travel "
     "logins, after-hours admin actions, unusual data access volume.",
     ["T1078", "T1078.004", "T1556"]),
    ("D3-SBV", "Script Behaviour Analysis", "detect",
     "Inspecting scripting-engine activity (PowerShell, VBA, JScript) "
     "for malicious content via AMSI / similar.",
     ["T1059.001", "T1059.005"]),
    ("D3-DKBI", "Decoy Network Resource", "detect",
     "Operating canary resources whose access reliably indicates "
     "intrusion.",
     ["T1018", "T1083", "T1087"]),
    # ── Isolate ─────────────────────────────────────────────────────
    ("D3-NI", "Network Isolation", "isolate",
     "Segmenting the network so a compromised host cannot reach high-"
     "value targets without crossing a controlled boundary.",
     ["T1021.001", "T1021.002", "T1018"]),
    ("D3-EI", "Execution Isolation", "isolate",
     "Containing untrusted code in a sandbox / container so post-"
     "exploitation actions are limited.",
     ["T1055", "T1218", "T1059.001"]),
    ("D3-CSPP", "Credential Storage Process Protection", "isolate",
     "Hardening the OS-level credential store (LSASS, keychains) so "
     "process-injection cannot exfiltrate secrets.",
     ["T1003.001", "T1555", "T1555.003"]),
    # ── Deceive ─────────────────────────────────────────────────────
    ("D3-DA", "Decoy Account", "deceive",
     "Operating fake accounts whose credential use signals adversary "
     "post-exploitation activity.",
     ["T1078", "T1110.003", "T1003.001"]),
    ("D3-DST", "Decoy System", "deceive",
     "Honeypot infrastructure that attracts adversary engagement and "
     "yields TTPs without exposing production assets.",
     ["T1018", "T1190"]),
    # ── Evict ───────────────────────────────────────────────────────
    ("D3-CR", "Credential Rotation", "evict",
     "Rotating credentials following a confirmed exposure to deny "
     "the adversary persistent access.",
     ["T1078", "T1078.004", "T1003.001"]),
    ("D3-AD", "Account Disabling", "evict",
     "Disabling compromised or unused accounts to remove the attacker's "
     "foothold.",
     ["T1078", "T1136", "T1098"]),
    ("D3-FE", "File Eviction", "evict",
     "Removing malicious files identified during incident response.",
     ["T1505.003", "T1486"]),
    # ── Restore ─────────────────────────────────────────────────────
    ("D3-SDR", "System Configuration Restoration", "restore",
     "Restoring a known-good system configuration after compromise.",
     ["T1486", "T1490", "T1485"]),
    ("D3-DRT", "Data from Backup Restoration", "restore",
     "Recovering data from offline / immutable backups after impact.",
     ["T1486", "T1485", "T1490"]),
    # ── Model ───────────────────────────────────────────────────────
    ("D3-AAM", "Asset Inventory Mapping", "model",
     "Maintaining a current inventory of hosts, services, and software "
     "to enable risk-based defense prioritisation.",
     ["T1018", "T1083", "T1082"]),
    ("D3-AVE", "Asset Vulnerability Enumeration", "model",
     "Continuous discovery of vulnerable software / configurations on "
     "the inventory above.",
     ["T1190", "T1068"]),
    ("D3-NM", "Network Mapping", "model",
     "Continuous discovery of network reachability + segmentation gaps.",
     ["T1018", "T1021.001", "T1021.002"]),
    ("D3-CH", "Configuration Hardening", "model",
     "Documented baseline configurations that reduce the attack surface.",
     ["T1547.001", "T1218", "T1562.001"]),
]


# ── Seeder ────────────────────────────────────────────────────────────


async def seed_d3fend_minimal(session: AsyncSession) -> dict[str, int]:
    """Idempotent seeder for the curated subset.

    Returns counts: {"created", "updated", "unchanged"}.
    """
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    for d3id, label, tactic, definition, attacks in CURATED_D3FEND:
        existing = (await session.execute(
            select(D3FENDTechnique).where(D3FENDTechnique.d3fend_id == d3id)
        )).scalar_one_or_none()
        if existing is None:
            session.add(D3FENDTechnique(
                d3fend_id=d3id, label=label, tactic=tactic,
                definition=definition, counters_attack_ids=attacks,
                source_url="https://d3fend.mitre.org/",
                source_version=_CURATED_VERSION,
            ))
            counts["created"] += 1
        else:
            # Refresh curated fields so a corpus revision rolls forward
            # without manual SQL.
            changed = False
            for col, val in (
                ("label", label), ("tactic", tactic),
                ("definition", definition), ("counters_attack_ids", attacks),
                ("source_version", _CURATED_VERSION),
            ):
                if getattr(existing, col) != val:
                    setattr(existing, col, val)
                    changed = True
            counts["updated" if changed else "unchanged"] += 1
    await session.flush()
    logger.info("d3fend curated seed: %s", counts)
    return counts


# ── Live upstream refresh ─────────────────────────────────────────────


async def refresh_from_upstream(
    session: AsyncSession,
    *,
    json_payload: dict | None = None,
) -> dict[str, int]:
    """Fetch the live D3FEND ontology and replace the catalog.

    ``json_payload`` is an optional pre-fetched ontology dict — used by
    tests to avoid the HTTP round-trip; production callers leave it as
    None and the function fetches the upstream URL.

    The full upstream ontology contains ~700 techniques. Each entity
    that has an ``rdfs:label`` and an ``http://d3fend.mitre.org/...``
    URI becomes a row.
    """
    if json_payload is None:
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(timeout=timeout) as http:
            async with http.get(_D3FEND_UPSTREAM_URL) as resp:
                resp.raise_for_status()
                json_payload = await resp.json()

    counts = {"created": 0, "updated": 0, "unchanged": 0}
    version = f"{_FULL_VERSION_PREFIX}-" + datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d")

    # The ontology JSON-LD shape: {"@graph": [{"@id": "d3f:D3-MFA",
    # "rdfs:label": "Multi-factor Authentication", ...}, ...]}.
    # We only ingest nodes that are d3fend defensive techniques —
    # detected by the d3f: namespace prefix on the @id.
    graph = json_payload.get("@graph") or json_payload.get("graph") or []
    for node in graph:
        if not isinstance(node, dict):
            continue
        node_id = node.get("@id") or node.get("id") or ""
        if not isinstance(node_id, str) or "d3fend.mitre.org" not in (
            node_id + str(node.get("@type", ""))
        ):
            # Be permissive — accept either prefixed (d3f:D3-MFA) or
            # full URI form. Filter to our defensive-technique IDs.
            if not node_id.startswith("d3f:D3-") and "/D3-" not in node_id:
                continue
        label = node.get("rdfs:label") or node.get("label") or ""
        if isinstance(label, dict):
            label = label.get("@value") or ""
        definition = node.get("rdfs:comment") or node.get("definition") or ""
        if isinstance(definition, dict):
            definition = definition.get("@value") or ""
        # Extract a short ID (D3-MFA) from the full URI form.
        d3id = node_id.split(":")[-1].split("/")[-1]
        if not d3id.startswith("D3-"):
            continue
        existing = (await session.execute(
            select(D3FENDTechnique).where(D3FENDTechnique.d3fend_id == d3id)
        )).scalar_one_or_none()
        if existing is None:
            session.add(D3FENDTechnique(
                d3fend_id=d3id,
                label=str(label) or d3id,
                tactic=None,  # Tactic info needs a second pass over the graph
                definition=str(definition) or None,
                counters_attack_ids=None,
                source_url=_D3FEND_UPSTREAM_URL,
                source_version=version,
            ))
            counts["created"] += 1
        else:
            existing.label = str(label) or existing.label
            existing.definition = str(definition) or existing.definition
            existing.source_version = version
            existing.source_url = _D3FEND_UPSTREAM_URL
            counts["updated"] += 1
    await session.flush()
    logger.info("d3fend upstream refresh: %s", counts)
    return counts


# ── Lookups ───────────────────────────────────────────────────────────


async def lookup(session: AsyncSession, d3fend_id: str) -> D3FENDTechnique | None:
    return (await session.execute(
        select(D3FENDTechnique).where(D3FENDTechnique.d3fend_id == d3fend_id)
    )).scalar_one_or_none()


async def defenses_for_attack(
    session: AsyncSession, attack_technique_ids: Iterable[str],
) -> list[D3FENDTechnique]:
    """Return the D3FEND defenses that counter any of the given ATT&CK
    technique IDs. Match is by membership in
    ``D3FENDTechnique.counters_attack_ids``."""
    ids = [t for t in attack_technique_ids if t]
    if not ids:
        return []
    rows = (await session.execute(select(D3FENDTechnique))).scalars().all()
    out: list[D3FENDTechnique] = []
    for r in rows:
        counters = set(r.counters_attack_ids or [])
        # Match either the exact ID or its base (T1566.001 → T1566).
        for tid in ids:
            base = tid.split(".")[0]
            if tid in counters or base in counters:
                out.append(r)
                break
    return out
