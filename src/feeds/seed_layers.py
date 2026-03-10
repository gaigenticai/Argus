"""Seed default threat map layers."""

import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.models.feeds import ThreatLayer

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
    {"name": "bgp_hijack", "display_name": "BGP Hijacks", "icon": "network", "color": "#FF5630", "feed_names": ["ripe_ris_live"], "refresh_interval_seconds": 0, "description": "Real-time BGP route hijack detection"},
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
