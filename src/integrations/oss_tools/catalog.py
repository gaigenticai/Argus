"""Curated OSS-tool catalog surfaced on the admin onboarding screen."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OssTool:
    """One installable OSS tool.

    ``compose_profile`` matches a profile in ``compose.optional.yml`` —
    the installer runs ``docker compose --profile <p> up -d`` to bring
    it up alongside Argus.

    ``env_vars`` is a mapping of env var → value the installer writes
    into the host ``.env`` once the tool is reachable. The matching
    Argus connector reads those variables to find the new service.
    """

    name: str
    label: str
    summary: str
    capability: str           # what feature this unlocks in Argus
    ram_estimate_mb: int
    disk_estimate_gb: int
    compose_profile: str
    env_vars: dict[str, str] = field(default_factory=dict)
    docs_url: str | None = None
    # Heavy tools (>4 GB RAM) get a confirmation step in the UI.
    is_heavyweight: bool = False
    # Tools whose first-launch UI requires the operator to set
    # something (e.g. MISP's per-install API key) get a "post-install
    # action required" notice.
    post_install_action: str | None = None


_CATALOG: list[OssTool] = [
    OssTool(
        name="caldera",
        label="MITRE Caldera",
        summary=(
            "MITRE's open-source adversary-emulation platform. Drives "
            "Atomic Red Team-style scripted attacks against your "
            "endpoints so you can verify your detections fire."
        ),
        capability=(
            "Unlocks the Caldera REST client behind /intel/adversary-"
            "emulation/caldera/* and lets the threat-hunter agent "
            "kick off operations end-to-end."
        ),
        ram_estimate_mb=512,
        disk_estimate_gb=2,
        compose_profile="caldera",
        env_vars={
            "ARGUS_CALDERA_URL": "http://caldera:8888",
            # Caldera's red user has password "admin" by default in
            # the public image; override via CALDERA_DEFAULT_PASSWORD
            # in .env if you want something else.
            "ARGUS_CALDERA_API_KEY": "ADMINREDADMINRED",
        },
        docs_url="https://github.com/mitre/caldera",
        post_install_action=(
            "Caldera ships with default red:admin credentials. Rotate "
            "via the Caldera Settings page on first login, then update "
            "ARGUS_CALDERA_API_KEY in your .env."
        ),
    ),
    OssTool(
        name="shuffle",
        label="Shuffle SOAR",
        summary=(
            "Open-source SOAR — drag-and-drop workflow runner with "
            "1500+ pre-built integrations. Receives alert pushes from "
            "Argus and fans out to ticketing / paging / chat."
        ),
        capability=(
            "Hooks Argus's existing Shuffle connector at /integrations/"
            "shuffle so saved playbooks fire on critical alerts."
        ),
        ram_estimate_mb=2048,    # backend + opensearch
        disk_estimate_gb=10,
        compose_profile="shuffle",
        env_vars={
            "ARGUS_SHUFFLE_URL": "http://shuffle-frontend:80",
        },
        docs_url="https://github.com/Shuffle/Shuffle",
        post_install_action=(
            "Visit http://localhost:3443 to create the first Shuffle "
            "user, then paste their API key into ARGUS_SHUFFLE_API_KEY."
        ),
    ),
    OssTool(
        name="velociraptor",
        label="Velociraptor",
        summary=(
            "Endpoint visibility + DFIR. VQL queries + live triage on "
            "Windows / Linux / macOS hosts. The case-copilot agent uses "
            "it to schedule on-demand collections."
        ),
        capability=(
            "Unlocks /intel/forensics/velociraptor/{clients,schedule}. "
            "Without it, IR is limited to memory-image analysis via "
            "Volatility."
        ),
        ram_estimate_mb=1024,
        disk_estimate_gb=4,
        compose_profile="velociraptor",
        env_vars={
            "ARGUS_VELOCIRAPTOR_URL": "https://velociraptor:8889",
            "ARGUS_VELOCIRAPTOR_VERIFY_SSL": "false",
        },
        docs_url="https://docs.velociraptor.app/",
        post_install_action=(
            "Open https://localhost:8000 (self-signed cert), log in as "
            "admin / velociraptor, mint an API token under Server → "
            "Users, then paste it into ARGUS_VELOCIRAPTOR_TOKEN."
        ),
    ),
    OssTool(
        name="misp",
        label="MISP",
        summary=(
            "The de-facto OSS threat-intel sharing platform. Argus can "
            "subscribe to events, push observed IOCs back, and pivot "
            "from any indicator to its full sharing-circle context."
        ),
        capability=(
            "Unlocks /intel/misp/{events,attributes,galaxies}. Adds a "
            "MISP-events column to the IOC detail page."
        ),
        ram_estimate_mb=4096,
        disk_estimate_gb=20,
        compose_profile="misp",
        env_vars={
            "ARGUS_MISP_URL": "https://misp",
            "ARGUS_MISP_VERIFY_SSL": "false",
        },
        docs_url="https://www.misp-project.org/",
        is_heavyweight=True,
        post_install_action=(
            "MISP first-launch: visit https://localhost:8443 (self-"
            "signed cert), log in as admin@admin.test / admin, change "
            "the password, then create an automation key under "
            "Administration → List Auth Keys. Paste it into "
            "ARGUS_MISP_API_KEY."
        ),
    ),
    OssTool(
        name="opencti",
        label="OpenCTI",
        summary=(
            "Filigran's OSS threat-intel platform — relationship graph "
            "between actors, campaigns, malware, IOCs. Argus pushes "
            "STIX 2.1 indicators in and pulls back the relationships."
        ),
        capability=(
            "Unlocks /intel/opencti/{availability,project,graph} for "
            "visual pivots. Without it, the same data is reachable via "
            "Argus's actor-playbook + sightings tables."
        ),
        ram_estimate_mb=8192,    # platform + ES + RabbitMQ + Redis + MinIO
        disk_estimate_gb=40,
        compose_profile="opencti",
        env_vars={
            "ARGUS_OPENCTI_URL": "http://opencti:8080",
        },
        docs_url="https://docs.opencti.io/",
        is_heavyweight=True,
        post_install_action=(
            "OpenCTI first-launch is interactive. Uncomment the opencti "
            "block in compose.optional.yml, set OPENCTI_ADMIN_TOKEN, "
            "then visit http://localhost:8080. Paste the token into "
            "ARGUS_OPENCTI_TOKEN."
        ),
    ),
    OssTool(
        name="wazuh",
        label="Wazuh SIEM",
        summary=(
            "Open-source SIEM + EDR. Useful when the customer doesn't "
            "already have Splunk / Sentinel / QRadar — Argus's Wazuh "
            "connector ingests alerts straight from the indexer."
        ),
        capability=(
            "Unlocks /intel/siem/wazuh/* and adds Wazuh as a destination "
            "for the alert-stream replicator."
        ),
        ram_estimate_mb=8192,
        disk_estimate_gb=30,
        compose_profile="wazuh",
        env_vars={
            "ARGUS_WAZUH_INDEXER_URL": "https://wazuh-indexer:9200",
            "ARGUS_WAZUH_VERIFY_SSL": "false",
        },
        docs_url="https://documentation.wazuh.com/",
        is_heavyweight=True,
        post_install_action=(
            "Wazuh ships its own Kibana — visit https://localhost:5601, "
            "log in as kibanaserver / kibanaserver, then mint an "
            "indexer API key. Paste it into "
            "ARGUS_WAZUH_INDEXER_USERNAME / _PASSWORD."
        ),
    ),
]


def list_catalog() -> list[OssTool]:
    return list(_CATALOG)


def tool_by_name(name: str) -> OssTool | None:
    for t in _CATALOG:
        if t.name == name:
            return t
    return None


def to_dict(t: OssTool) -> dict[str, Any]:
    return {
        "name": t.name,
        "label": t.label,
        "summary": t.summary,
        "capability": t.capability,
        "ram_estimate_mb": t.ram_estimate_mb,
        "disk_estimate_gb": t.disk_estimate_gb,
        "compose_profile": t.compose_profile,
        "env_vars": dict(t.env_vars),
        "docs_url": t.docs_url,
        "is_heavyweight": t.is_heavyweight,
        "post_install_action": t.post_install_action,
    }
