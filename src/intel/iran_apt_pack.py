"""Iran-nexus APT pack — curated threat-actor profiles + Navigator layer
emitter (P1 #1.4).

Six Iran-aligned actor clusters relevant to GCC defenders, each with
hand-curated MITRE ATT&CK technique IDs sourced from the actor's
public MITRE Group profile. The seeder is idempotent and intended to
run once per install.

When an alert is linked to one of these actors via :class:`ActorSighting`,
the auto-apply hook in :func:`attach_actor_ttps_to_alert` materialises
``AttackTechniqueAttachment`` rows so the alert detail page already
shows the relevant techniques without analyst tagging.

The Navigator layer JSON is built to MITRE ATT&CK Navigator schema v4.5
(https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/Layer.schema.json).

Sources (verifiable per-actor):
    APT33 (G0064)             https://attack.mitre.org/groups/G0064/
    APT34 / OilRig (G0049)    https://attack.mitre.org/groups/G0049/
    APT35 (G0059)             https://attack.mitre.org/groups/G0059/
    MuddyWater (G0069)        https://attack.mitre.org/groups/G0069/
    DEV-0270                  Microsoft Threat Intelligence — DEV-0270 / Cobalt Mirage
    Cyber Av3ngers            CISA AA23-335A (joint advisory, Dec 2023)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.intel import ActorSighting, ThreatActor
from src.models.mitre import AttachmentSource, AttackTechniqueAttachment

logger = logging.getLogger(__name__)


# --- Curated actor pack -----------------------------------------------


# Per-actor: (primary_alias, aliases, description, mitre_group_id,
#            ttps_enterprise, ttps_ics)
#
# TTP lists are curated for completeness over the most-cited / highest-
# confidence techniques per the MITRE Group page; intentionally not
# exhaustive — picking the top ~12-15 keeps the Navigator overlay
# legible during a CISO walkthrough rather than producing a wall of
# yellow squares.

IRAN_APT_PACK: list[dict[str, Any]] = [
    {
        "primary_alias": "APT33",
        "aliases": ["Elfin", "HOLMIUM", "MAGNALLIUM", "Refined Kitten"],
        "description": (
            "Iranian state-aligned actor (G0064). Targets aerospace, "
            "energy, and petrochemical sectors across the Gulf, US, and "
            "Saudi Arabia. Operator of Shamoon-family wipers."
        ),
        "mitre_group_id": "G0064",
        "ttps_enterprise": [
            "T1566", "T1566.001", "T1566.002", "T1190",
            "T1059.001", "T1059.005",
            "T1547.001",
            "T1027", "T1140",
            "T1057", "T1083",
            "T1005",
            "T1071.001",
            "T1485",
        ],
        "ttps_ics": [],
    },
    {
        "primary_alias": "APT34",
        "aliases": ["OilRig", "HELIX KITTEN", "Cobalt Gypsy", "IRN2"],
        "description": (
            "Iranian state-aligned actor (G0049). Long-running campaigns "
            "against GCC government, financial, and telecom sectors. "
            "Heavy use of DNS-tunnelling C2 and supply-chain pivots."
        ),
        "mitre_group_id": "G0049",
        "ttps_enterprise": [
            "T1566", "T1566.001", "T1566.002", "T1190",
            "T1059.001", "T1059.003",
            "T1505.003", "T1547.001",
            "T1068",
            "T1140", "T1218.005", "T1027",
            "T1003.001", "T1110.003",
            "T1018", "T1083", "T1087",
            "T1021.001", "T1021.002",
            "T1005", "T1119",
            "T1071.001", "T1071.004", "T1090",
            "T1041", "T1567",
        ],
        "ttps_ics": [],
    },
    {
        "primary_alias": "APT35",
        "aliases": ["Charming Kitten", "Phosphorus", "Magic Hound", "Mint Sandstorm"],
        "description": (
            "Iranian IRGC-aligned actor (G0059). Targets journalists, "
            "policy researchers, dissidents, and selected GCC government "
            "and energy assets. Proficient at credential harvesting via "
            "spearphishing with disposable infrastructure."
        ),
        "mitre_group_id": "G0059",
        "ttps_enterprise": [
            "T1566.002", "T1566.003",
            "T1059.001",
            "T1547.001", "T1098",
            "T1027", "T1070.004",
            "T1056", "T1056.004", "T1110",
            "T1114",
            "T1071.001", "T1102",
        ],
        "ttps_ics": [],
    },
    {
        "primary_alias": "MuddyWater",
        "aliases": ["TEMP.Zagros", "Static Kitten", "Mango Sandstorm",
                    "Seedworm"],
        "description": (
            "Iranian MOIS-aligned actor (G0069). Heavy targeting of "
            "Middle East telecoms, government, and oil & gas. Signature "
            "use of legitimate remote-management tools (ScreenConnect, "
            "RemoteUtilities, Atera) plus PowerShell/VBA loaders."
        ),
        "mitre_group_id": "G0069",
        "ttps_enterprise": [
            "T1566.001",
            "T1059.001", "T1204.002",
            "T1547.001", "T1053.005",
            "T1055",
            "T1140", "T1027", "T1218",
            "T1003.001",
            "T1018", "T1057", "T1082",
            "T1021.001",
            "T1071.001", "T1132.001",
        ],
        "ttps_ics": [],
    },
    {
        "primary_alias": "DEV-0270",
        "aliases": ["Nemesis Kitten", "Cobalt Mirage"],
        "description": (
            "Iranian actor cluster overlapping with PHOSPHORUS subgroups, "
            "tracked by Microsoft Threat Intelligence. Mass exploitation "
            "of unpatched edge devices (ProxyShell, Log4Shell) followed "
            "by BitLocker-abuse ransomware against opportunistic victims."
        ),
        "mitre_group_id": None,
        "ttps_enterprise": [
            "T1190",
            "T1059.001",
            "T1136",
            "T1562.001",
            "T1003.001",
            "T1021.001", "T1021.002",
            "T1486",
            "T1071.001",
        ],
        "ttps_ics": [],
    },
    {
        "primary_alias": "Cyber Av3ngers",
        "aliases": ["CyberAv3ngers", "Cyber Avengers"],
        "description": (
            "Iranian-aligned hacktivist front per CISA AA23-335A. Active "
            "against ICS / OT — particularly Unitronics PLCs in water "
            "treatment and similar critical-infrastructure verticals "
            "across the US and GCC region."
        ),
        "mitre_group_id": None,
        "ttps_enterprise": [
            "T1078", "T1190",
            "T1021.001",
            "T1071.001",
        ],
        "ttps_ics": [
            "T0807",  # Command-Line Interface
            "T0846",  # Remote System Discovery
            "T0809",  # Data Destruction
            "T0813",  # Denial of Control
        ],
    },
]


_PACK_VERSION = "2026-05-01"


# --- Idempotent seeder ------------------------------------------------


async def seed_iran_apt_pack(session: AsyncSession) -> dict[str, int]:
    """Upsert the Iran-nexus APT pack into ``threat_actors``.

    Idempotent — re-running on an already-seeded DB updates the
    ``known_ttps`` and ``profile_data`` fields to the latest curated
    values but never duplicates rows.
    """
    counts = {"created": 0, "updated": 0}
    now = datetime.now(timezone.utc)

    for entry in IRAN_APT_PACK:
        ttps = list(entry["ttps_enterprise"]) + list(entry["ttps_ics"])
        existing = (await session.execute(
            select(ThreatActor).where(
                ThreatActor.primary_alias == entry["primary_alias"]
            )
        )).scalar_one_or_none()

        profile_data = {
            "pack": "iran_nexus",
            "pack_version": _PACK_VERSION,
            "mitre_group_id": entry.get("mitre_group_id"),
            "ttps_enterprise": entry["ttps_enterprise"],
            "ttps_ics": entry["ttps_ics"],
        }

        if existing is None:
            session.add(ThreatActor(
                primary_alias=entry["primary_alias"],
                aliases=list(set(entry["aliases"])),
                description=entry["description"],
                forums_active=[],
                languages=["en", "fa"],
                pgp_fingerprints=[],
                known_ttps=ttps,
                risk_score=0.85,
                first_seen=now,
                last_seen=now,
                total_sightings=0,
                profile_data=profile_data,
            ))
            counts["created"] += 1
        else:
            # Refresh the curated fields without overwriting tracker
            # state (sightings, last_seen, alias additions from real
            # observations).
            existing.description = entry["description"]
            merged_aliases = list(set(
                (existing.aliases or []) + entry["aliases"]
            ))
            existing.aliases = merged_aliases
            existing.known_ttps = ttps
            existing.profile_data = {
                **(existing.profile_data or {}),
                **profile_data,
            }
            counts["updated"] += 1

    await session.flush()
    logger.info("iran_apt_pack seed: %s", counts)
    return counts


# --- Auto-apply hook --------------------------------------------------


_DEFAULT_MATRIX = "enterprise"
_ICS_PREFIX = "T0"  # MITRE ICS techniques are T0xxxx


def _matrix_for(technique_external_id: str) -> str:
    return "ics" if technique_external_id.startswith(_ICS_PREFIX) else _DEFAULT_MATRIX


async def attach_actor_ttps_to_alert(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    alert_id: uuid.UUID,
    actor: ThreatActor,
) -> int:
    """Materialise ``AttackTechniqueAttachment`` rows on the alert for
    every TTP in the actor's ``known_ttps``.

    Idempotent on (entity_type, entity_id, matrix, technique_external_id)
    — re-running across the same alert/actor pair inserts no duplicates.
    Returns the number of newly-attached techniques.
    """
    if not actor.known_ttps:
        return 0

    existing_keys: set[tuple[str, str]] = set(
        (await session.execute(
            select(
                AttackTechniqueAttachment.matrix,
                AttackTechniqueAttachment.technique_external_id,
            ).where(
                AttackTechniqueAttachment.organization_id == organization_id,
                AttackTechniqueAttachment.entity_type == "alert",
                AttackTechniqueAttachment.entity_id == alert_id,
            )
        )).all()
    )

    attached = 0
    for ext_id in actor.known_ttps:
        matrix = _matrix_for(ext_id)
        if (matrix, ext_id) in existing_keys:
            continue
        session.add(AttackTechniqueAttachment(
            organization_id=organization_id,
            entity_type="alert",
            entity_id=alert_id,
            matrix=matrix,
            technique_external_id=ext_id,
            confidence=0.85,
            source=AttachmentSource.MITRE_GROUP_LINK.value,
            note=(
                f"Auto-attached from {actor.primary_alias} known_ttps "
                f"(pack=iran_nexus, version={_PACK_VERSION})."
            ),
        ))
        existing_keys.add((matrix, ext_id))
        attached += 1

    return attached


async def attach_actor_ttps_to_alerts_for_sighting(
    session: AsyncSession,
    sighting: ActorSighting,
) -> int:
    """Convenience wrapper: given a freshly-recorded sighting that links
    an alert to an actor, run the auto-apply.

    Returns the number of newly-attached techniques. Returns 0 if the
    sighting has no alert_id (some sightings link only to raw_intel).
    """
    if sighting.alert_id is None:
        return 0
    actor = await session.get(ThreatActor, sighting.threat_actor_id)
    if actor is None:
        return 0
    # Resolve the alert's organization_id without joining the model
    # imports here (avoids a cycle on src.models.threat at import time).
    from src.models.threat import Alert
    alert = await session.get(Alert, sighting.alert_id)
    if alert is None:
        return 0
    return await attach_actor_ttps_to_alert(
        session,
        organization_id=alert.organization_id,
        alert_id=alert.id,
        actor=actor,
    )


# --- Navigator layer emitter ------------------------------------------


_NAVIGATOR_VERSION = "4.5"
_ATTACK_VERSION = "14"  # ATT&CK content version we last cross-checked


def build_navigator_layer(
    actor: ThreatActor,
    *,
    matrix: str = "enterprise",
) -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator v4.5 layer JSON for this actor.

    The layer highlights every technique in ``actor.known_ttps`` for
    the requested matrix. Designed to be downloaded by the analyst and
    loaded into MITRE's hosted Navigator
    (https://mitre-attack.github.io/attack-navigator/) or a self-hosted
    instance to overlay against the customer's detection coverage map.
    """
    pack = (actor.profile_data or {}).get("pack")
    pack_version = (actor.profile_data or {}).get("pack_version")
    enterprise_ttps: list[str] = (
        (actor.profile_data or {}).get("ttps_enterprise") or []
    )
    ics_ttps: list[str] = (actor.profile_data or {}).get("ttps_ics") or []
    if matrix == "ics":
        techniques_src = ics_ttps
        domain = "ics-attack"
    else:
        techniques_src = enterprise_ttps or [
            t for t in (actor.known_ttps or []) if not t.startswith("T0")
        ]
        domain = "enterprise-attack"

    techniques = [
        {
            "techniqueID": t,
            "score": 1,
            "color": "",
            "comment": (
                f"Observed in {actor.primary_alias} ({pack or 'curated pack'}) "
                f"TTP set."
            ),
            "enabled": True,
            "metadata": [],
            "showSubtechniques": "." in t,
        }
        for t in techniques_src
    ]

    layer_name = f"Argus — {actor.primary_alias} TTP overlay"
    description_parts = [
        actor.description or actor.primary_alias,
        f"Aliases: {', '.join(actor.aliases or [])}." if actor.aliases else "",
        f"Pack: {pack} (version {pack_version}).",
        "Generated by Argus Threat Intelligence Platform.",
    ]
    description = " ".join(p for p in description_parts if p)

    return {
        "name": layer_name,
        "versions": {
            "attack": _ATTACK_VERSION,
            "navigator": _NAVIGATOR_VERSION,
            "layer": _NAVIGATOR_VERSION,
        },
        "domain": domain,
        "description": description,
        "filters": {"platforms": ["Linux", "macOS", "Windows", "Network",
                                  "Containers", "Office 365", "Azure AD",
                                  "SaaS", "IaaS"]} if matrix != "ics" else {},
        "sorting": 0,
        "viewMode": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#fff5e6", "#ff4f00"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [{"label": actor.primary_alias, "color": "#ff4f00"}],
        "metadata": [
            {"name": "argus_actor_id", "value": str(actor.id)},
            {"name": "argus_pack", "value": str(pack or "")},
            {"name": "argus_pack_version", "value": str(pack_version or "")},
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
