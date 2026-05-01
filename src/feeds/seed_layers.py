"""Seed default threat map layers and integration configs."""

from __future__ import annotations


import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.models.feeds import ThreatLayer
from src.models.intel import IntegrationConfig

logger = logging.getLogger(__name__)

DEFAULT_LAYERS = [
    {"name": "ransomware", "display_name": "Ransomware Victims", "icon": "skull", "color": "#FF5630", "feed_names": ["ransomware_live"], "refresh_interval_seconds": 21600, "description": "Active ransomware victims from leak sites"},
    {"name": "botnet_c2", "display_name": "Botnet C2 Servers", "icon": "radio", "color": "#FF8B00", "feed_names": ["feodo_tracker", "c2_tracker", "greynoise"], "refresh_interval_seconds": 3600, "description": "Active command-and-control server IPs"},
    {"name": "phishing", "display_name": "Phishing Campaigns", "icon": "fish", "color": "#FFAB00", "feed_names": ["openphish", "phishstats", "otx_pulse"], "refresh_interval_seconds": 21600, "description": "Active phishing URLs and hosting infrastructure"},
    {"name": "malware", "display_name": "Malware Distribution", "icon": "bug", "color": "#8E33FF", "feed_names": ["urlhaus", "threatfox", "otx_pulse"], "refresh_interval_seconds": 3600, "description": "Malware distribution URLs and hosting"},
    {"name": "honeypot", "display_name": "Honeypot Attackers", "icon": "target", "color": "#00BBD9", "feed_names": ["dshield"], "refresh_interval_seconds": 300, "description": "Top attacking IPs from DShield/SANS honeypots"},
    {"name": "tor_exit", "display_name": "Tor Exit Nodes", "icon": "eye-off", "color": "#637381", "feed_names": ["tor_bulk_exit"], "refresh_interval_seconds": 1800, "description": "Current Tor network exit node locations"},
    {"name": "ip_reputation", "display_name": "Malicious IPs", "icon": "ban", "color": "#B71D18", "feed_names": ["ipsum", "blocklist_de", "firehol_l1", "abuseipdb", "greynoise", "otx_pulse"], "refresh_interval_seconds": 3600, "description": "Aggregated malicious IP blocklists"},
    {"name": "exploited_cve", "display_name": "Exploited CVEs", "icon": "shield-alert", "color": "#FF5630", "feed_names": ["cisa_kev", "greynoise", "otx_pulse"], "refresh_interval_seconds": 86400, "description": "CISA known exploited vulnerabilities"},
    {"name": "ssl_abuse", "display_name": "SSL Blacklist", "icon": "lock", "color": "#00A76F", "feed_names": ["sslbl", "ja3_fingerprints"], "refresh_interval_seconds": 3600, "description": "Malicious SSL certificates and JA3 fingerprints"},
    {"name": "bgp_hijack", "display_name": "BGP Hijacks", "icon": "network", "color": "#FF5630", "feed_names": ["ripe_ris_live"], "refresh_interval_seconds": 3600, "description": "BGP prefix hijack events from Cloudflare Radar (requires ARGUS_FEED_CF_RADAR_API_KEY)"},
    {"name": "underground", "display_name": "Underground Intel", "icon": "message-circle", "color": "#8E33FF", "feed_names": [], "refresh_interval_seconds": 0, "description": "Argus underground crawler findings (Tor, I2P, Lokinet, Matrix)"},
]


async def seed_default_layers(db: AsyncSession) -> None:
    """Ensure all default layers exist. Does not overwrite existing config."""
    for layer_data in DEFAULT_LAYERS:
        existing = await db.execute(
            select(ThreatLayer).where(ThreatLayer.name == layer_data["name"])
        )
        if existing.scalar_one_or_none():
            continue

        layer = ThreatLayer(**layer_data)
        db.add(layer)
        logger.info("Seeded threat layer: %s", layer_data["name"])

    await db.commit()


# ---------------------------------------------------------------------------
# Integration configs — auto-enable local/open-source tools
# ---------------------------------------------------------------------------

# Tools installed in the Docker image — genuinely functional
LOCAL_TOOLS = [
    {"tool_name": "nuclei", "api_url": "", "enabled": True, "health_status": "connected"},
    {"tool_name": "yara", "api_url": "data/yara_rules", "enabled": True, "health_status": "connected"},
    {"tool_name": "sigma", "api_url": "data/sigma_rules", "enabled": True, "health_status": "connected"},
]

# Tools that need external infrastructure — available but not installed
AVAILABLE_TOOLS = [
    {"tool_name": "opencti", "api_url": "", "enabled": False, "health_status": "available"},
    {"tool_name": "wazuh", "api_url": "", "enabled": False, "health_status": "available"},
    {"tool_name": "spiderfoot", "api_url": "", "enabled": False, "health_status": "available"},
    {"tool_name": "shuffle", "api_url": "", "enabled": False, "health_status": "available"},
    {"tool_name": "gophish", "api_url": "", "enabled": False, "health_status": "available"},
    {"tool_name": "suricata", "api_url": "", "enabled": False, "health_status": "available"},
    {"tool_name": "prowler", "api_url": "", "enabled": False, "health_status": "available"},
]


async def seed_integrations(db: AsyncSession) -> None:
    """Seed integration configs — auto-enable local tools, mark others as available."""
    all_tools = LOCAL_TOOLS + AVAILABLE_TOOLS
    expected = {t["tool_name"]: t for t in all_tools}

    for tool_data in all_tools:
        result = await db.execute(
            select(IntegrationConfig).where(
                IntegrationConfig.tool_name == tool_data["tool_name"]
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Fix any wrongly-seeded statuses (e.g. suricata/prowler were "connected")
            target = expected[existing.tool_name]
            if existing.health_status != target["health_status"] and existing.health_status in ("unconfigured", "connected"):
                existing.health_status = target["health_status"]
                existing.enabled = target["enabled"]
                existing.api_url = target["api_url"]
                logger.info("Fixed integration status: %s → %s", existing.tool_name, target["health_status"])
            continue

        config = IntegrationConfig(
            tool_name=tool_data["tool_name"],
            api_url=tool_data["api_url"],
            enabled=tool_data["enabled"],
            health_status=tool_data["health_status"],
        )
        db.add(config)
        logger.info("Seeded integration: %s (enabled=%s)", tool_data["tool_name"], tool_data["enabled"])

    await db.commit()
