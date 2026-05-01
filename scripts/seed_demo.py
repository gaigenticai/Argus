"""Seed Argus with realistic-looking demo data for presentation purposes.

Usage:
    python -m scripts.seed_demo

Adversarial audit D-4 — this script bootstraps users; it must refuse
to run against a production database. The legacy literal passwords
that used to live near line 932 have been replaced with
``secrets.token_urlsafe`` and printed once at the top of the run.
"""

import asyncio
import os as _os
import secrets as _secrets
import sys as _sys
import uuid
import random
from datetime import datetime, timezone, timedelta

from sqlalchemy import select


def _refuse_in_production() -> None:
    """Same gate as scripts/seed_full_demo.py — see audit D-4."""
    seed_mode = (_os.environ.get("ARGUS_SEED_MODE") or "").strip().lower()
    env = (_os.environ.get("ARGUS_ENVIRONMENT") or "").strip().lower()
    debug = (_os.environ.get("ARGUS_DEBUG") or "").strip().lower() in ("1", "true", "yes")
    if seed_mode not in {"demo", "realistic", "stress"}:
        _sys.stderr.write(
            "scripts/seed_demo.py refuses to run unless ARGUS_SEED_MODE is one of "
            "{demo, realistic, stress}.\n"
        )
        _sys.exit(2)
    if env == "production" and not debug:
        _sys.stderr.write(
            "scripts/seed_demo.py refuses to run when ARGUS_ENVIRONMENT=production. "
            "Set ARGUS_DEBUG=true on a non-prod database to override.\n"
        )
        _sys.exit(2)

from src.config.settings import settings
from src.core.auth import hash_password, audit_log
from src.storage.database import init_db, get_session
from src.models.auth import AuditAction, User, UserRole
from src.models.threat import (
    Alert,
    AlertStatus,
    Asset,
    Organization,
    RawIntel,
    SourceType,
    ThreatCategory,
    ThreatSeverity,
    VIPTarget,
)
from scripts._seed_extra import seed_extra


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------

ORGS = [
    {
        "name": "Meridian Financial Group",
        "domains": ["meridianfg.com", "meridian-bank.com", "mfg-portal.com"],
        "keywords": [
            "Meridian Financial",
            "MeridianFG",
            "Meridian Bank",
            "MRDN stock",
            "Meridian Capital",
        ],
        "industry": "Financial Services",
        "tech_stack": {
            "frontend": ["React", "Next.js"],
            "backend": ["Java Spring Boot", "Node.js"],
            "databases": ["PostgreSQL", "Redis", "MongoDB"],
            "cloud": ["AWS", "Kubernetes"],
            "security": ["CrowdStrike Falcon", "Palo Alto Cortex XDR"],
            "ci_cd": ["Jenkins", "ArgoCD"],
        },
    },
    {
        "name": "NovaMed Health Systems",
        "domains": ["novamed.health", "novamedhealth.com", "patient.novamed.health"],
        "keywords": [
            "NovaMed",
            "NovaMed Health",
            "Nova Medical",
            "NovaMed patient portal",
        ],
        "industry": "Healthcare",
        "tech_stack": {
            "frontend": ["Angular", "Ionic"],
            "backend": ["Python Django", ".NET Core"],
            "databases": ["SQL Server", "Elasticsearch"],
            "cloud": ["Azure", "Azure Kubernetes Service"],
            "emr": ["Epic Systems"],
            "security": ["Microsoft Sentinel", "Fortinet FortiGate"],
        },
    },
    {
        "name": "Helios Semiconductor",
        "domains": ["heliossemi.com", "helios-chip.io", "design.heliossemi.com"],
        "keywords": [
            "Helios Semiconductor",
            "Helios chip",
            "HELI stock",
            "Helios RISC-V",
            "Helios ASIC",
        ],
        "industry": "Semiconductor Manufacturing",
        "tech_stack": {
            "frontend": ["Vue.js"],
            "backend": ["C++", "Rust", "Python"],
            "databases": ["PostgreSQL", "InfluxDB"],
            "cloud": ["On-Premise", "AWS GovCloud"],
            "eda": ["Synopsys", "Cadence", "Mentor Graphics"],
            "ci_cd": ["GitLab CI", "Bazel"],
        },
    },
]

# ---------------------------------------------------------------------------
# VIPs
# ---------------------------------------------------------------------------

VIPS = {
    "Meridian Financial Group": [
        {
            "name": "David Chen",
            "title": "Chief Executive Officer",
            "emails": ["david.chen@meridianfg.com", "dchen@meridian-bank.com"],
            "usernames": ["dchen", "davidchen_ceo"],
            "phone_numbers": ["+1-415-555-0142"],
        },
        {
            "name": "Priya Sharma",
            "title": "Chief Information Security Officer",
            "emails": ["priya.sharma@meridianfg.com", "p.sharma@meridianfg.com"],
            "usernames": ["psharma", "priya.sharma"],
            "phone_numbers": ["+1-415-555-0198"],
        },
        {
            "name": "Marcus Williams",
            "title": "Chief Financial Officer",
            "emails": ["m.williams@meridianfg.com"],
            "usernames": ["mwilliams"],
            "phone_numbers": ["+1-415-555-0267"],
        },
    ],
    "NovaMed Health Systems": [
        {
            "name": "Dr. Sarah Nakamura",
            "title": "Chief Medical Information Officer",
            "emails": ["s.nakamura@novamed.health", "sarah.nakamura@novamedhealth.com"],
            "usernames": ["snakamura", "dr_nakamura"],
            "phone_numbers": ["+1-617-555-0331"],
        },
        {
            "name": "James Okafor",
            "title": "VP of Information Technology",
            "emails": ["j.okafor@novamed.health"],
            "usernames": ["jokafor"],
            "phone_numbers": ["+1-617-555-0455"],
        },
    ],
    "Helios Semiconductor": [
        {
            "name": "Dr. Li Wei",
            "title": "Chief Technology Officer",
            "emails": ["li.wei@heliossemi.com", "lwei@helios-chip.io"],
            "usernames": ["liwei", "lwei_helios"],
            "phone_numbers": ["+1-408-555-0712"],
        },
        {
            "name": "Anna Petrova",
            "title": "VP of Engineering",
            "emails": ["a.petrova@heliossemi.com"],
            "usernames": ["apetrova"],
            "phone_numbers": ["+1-408-555-0834"],
        },
    ],
}

# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

ASSETS = {
    "Meridian Financial Group": [
        {"asset_type": "subdomain", "value": "api.meridianfg.com", "details": {"ip": "52.14.201.73", "cdn": "Cloudflare"}},
        {"asset_type": "subdomain", "value": "portal.meridianfg.com", "details": {"ip": "52.14.201.74"}},
        {"asset_type": "subdomain", "value": "staging.meridianfg.com", "details": {"ip": "10.0.4.22", "internal": True}},
        {"asset_type": "subdomain", "value": "vpn.meridianfg.com", "details": {"ip": "52.14.201.80", "service": "Cisco AnyConnect"}},
        {"asset_type": "subdomain", "value": "mail.meridianfg.com", "details": {"ip": "52.14.201.81", "service": "Exchange Online"}},
        {"asset_type": "subdomain", "value": "jenkins.meridianfg.com", "details": {"ip": "52.14.201.90", "service": "Jenkins 2.414"}},
        {"asset_type": "ip_address", "value": "52.14.201.73", "details": {"asn": "AS16509 Amazon", "region": "us-east-1"}},
        {"asset_type": "service", "value": "meridianfg.com:443", "details": {"tls": "1.3", "cert_expiry": "2026-09-15"}},
    ],
    "NovaMed Health Systems": [
        {"asset_type": "subdomain", "value": "ehr.novamed.health", "details": {"ip": "20.84.10.55", "service": "Epic Web"}},
        {"asset_type": "subdomain", "value": "api.novamed.health", "details": {"ip": "20.84.10.56"}},
        {"asset_type": "subdomain", "value": "telehealth.novamed.health", "details": {"ip": "20.84.10.60", "service": "Zoom Health"}},
        {"asset_type": "subdomain", "value": "imaging.novamed.health", "details": {"ip": "20.84.10.62", "service": "PACS"}},
        {"asset_type": "ip_address", "value": "20.84.10.55", "details": {"asn": "AS8075 Microsoft", "region": "East US 2"}},
    ],
    "Helios Semiconductor": [
        {"asset_type": "subdomain", "value": "git.heliossemi.com", "details": {"ip": "198.51.100.20", "service": "GitLab CE 16.8"}},
        {"asset_type": "subdomain", "value": "design.heliossemi.com", "details": {"ip": "198.51.100.22", "service": "Internal EDA portal"}},
        {"asset_type": "subdomain", "value": "vpn.heliossemi.com", "details": {"ip": "198.51.100.25", "service": "WireGuard"}},
        {"asset_type": "subdomain", "value": "wiki.heliossemi.com", "details": {"ip": "198.51.100.30", "service": "Confluence"}},
    ],
}

# ---------------------------------------------------------------------------
# Raw Intel
# ---------------------------------------------------------------------------


def _now_minus(days: int = 0, hours: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days, hours=hours)


RAW_INTEL = [
    # Meridian — credential leak
    {
        "source_type": SourceType.TOR_FORUM.value,
        "source_url": "http://breachforums.onion/thread/48291",
        "source_name": "BreachForums",
        "title": "Meridian Financial Group — Employee credential dump (12K records)",
        "content": (
            "Fresh dump from Meridian Financial Group internal systems. "
            "12,847 employee records including emails, hashed passwords (bcrypt), "
            "employee IDs, department info. Data appears from their Azure AD sync. "
            "Includes C-suite emails: david.chen@meridianfg.com, priya.sharma@meridianfg.com. "
            "Selling for 2 BTC. Contact: darkvendor77 on Telegram."
        ),
        "author": "darkvendor77",
        "published_at": _now_minus(days=1, hours=6),
        "raw_data": {"thread_id": 48291, "views": 2847, "replies": 34, "price_btc": 2.0},
    },
    # Meridian — phishing kit
    {
        "source_type": SourceType.TELEGRAM.value,
        "source_url": "https://t.me/phishkits/15782",
        "source_name": "PhishKits Channel",
        "title": "Meridian Bank login clone kit with SMS bypass",
        "content": (
            "New phishing kit replicating Meridian Bank portal. Includes 2FA bypass module "
            "that intercepts SMS OTP in real-time. Kit targets portal.meridianfg.com login page. "
            "Hosted on Cloudflare Workers for fast deployment. Domain merid1an-secure.com already "
            "registered and SSL provisioned. Kit includes anti-detection: blocks security scanners, "
            "geofences to US only. Price: $500 per kit."
        ),
        "author": "phish_master_x",
        "published_at": _now_minus(days=2, hours=3),
        "raw_data": {"channel": "phishkits", "message_id": 15782, "forwards": 89},
    },
    # Meridian — ransomware
    {
        "source_type": SourceType.TOR_FORUM.value,
        "source_url": "http://lockbit.onion/blog/meridian-financial",
        "source_name": "LockBit Blog",
        "title": "LockBit claims breach of financial services firm",
        "content": (
            "LockBit ransomware group posted a new victim on their data leak site. "
            "The listing references a 'major US financial services company' with "
            "screenshots showing internal file shares containing documents labeled "
            "'Meridian Capital Advisors' and 'MFG Compliance Reports Q4 2025'. "
            "Countdown timer set to 14 days. Ransom demand: $3.5M. "
            "Sample data includes board meeting minutes, M&A documents, "
            "and customer PII spreadsheets from wealth management division."
        ),
        "author": "LockBitSupp",
        "published_at": _now_minus(hours=18),
        "raw_data": {"group": "LockBit 3.0", "timer_days": 14, "ransom_usd": 3500000},
    },
    # NovaMed — data breach
    {
        "source_type": SourceType.FORUM_UNDERGROUND.value,
        "source_url": "http://breachforums.onion/thread/50112",
        "source_name": "BreachForums",
        "title": "NovaMed patient records sample — 500 PHI records",
        "content": (
            "Sample from NovaMed Health Systems patient database. Full dump contains "
            "2.3 million records. Fields: patient_id, full_name, ssn, dob, "
            "diagnosis_codes (ICD-10), prescriptions, insurance_id, address, phone. "
            "Sample: John Doe, SSN 412-XX-8891, DOB 1978-03-15, Dx: E11.9 Type 2 Diabetes, "
            "Rx: Metformin 1000mg, Insurance: BlueCross BCBS-4412789. "
            "Full dump available on BreachForums. Seller: ghost_data_vendor."
        ),
        "author": "ghost_data_vendor",
        "published_at": _now_minus(days=3, hours=12),
        "raw_data": {"records_sample": 500, "records_total": 2300000, "data_type": "PHI"},
    },
    # NovaMed — vulnerability
    {
        "source_type": SourceType.STEALER_LOG.value,
        "source_url": "http://russianmarket.onion/logs/novamed",
        "source_name": "Russian Market",
        "title": "NovaMed Health — 847 stealer log entries with EHR session cookies",
        "content": (
            "Batch of 847 stealer logs from RedLine infostealer containing saved credentials "
            "and session cookies for novamed.health and patient.novamed.health domains. "
            "Includes 23 entries with active session cookies for Epic MyChart EHR portal. "
            "Credentials include @novamed.health email/password pairs. "
            "Logs dated within last 72 hours — sessions likely still active. "
            "Bot IDs from US-based machines. Price: $10 per log."
        ),
        "author": "stealer_vendor_rx",
        "published_at": _now_minus(hours=14),
        "raw_data": {
            "log_count": 847,
            "stealer_type": "RedLine",
            "active_sessions": 23,
            "price_per_log": 10,
        },
    },
    # NovaMed — insider threat
    {
        "source_type": SourceType.TOR_MARKETPLACE.value,
        "source_url": "http://darkmarket.onion/listing/nova-access",
        "source_name": "DarkMarket",
        "title": "NovaMed VPN + AD credentials — verified insider access",
        "content": (
            "Selling verified VPN credentials for NovaMed Health Systems. "
            "Includes Active Directory domain admin account and Citrix workspace access. "
            "Currently active — tested today. Access to EHR system, patient records, "
            "billing system, and internal SharePoint. Credentials rotated weekly, "
            "subscription model: $2,000/week for continued access. "
            "Proof: screenshot of NovaMed internal dashboard showing 'Welcome, Admin' "
            "with timestamp from today."
        ),
        "author": "inside_man_med",
        "published_at": _now_minus(hours=8),
        "raw_data": {"listing_id": "nova-access", "price_weekly": 2000, "verified": True},
    },
    # Helios — code leak
    {
        "source_type": SourceType.I2P.value,
        "source_url": "http://helios-leaks.i2p/rtl-v3",
        "source_name": "I2P Eepsite",
        "title": "Helios RISC-V RTL design files dumped on I2P",
        "content": (
            "I2P eepsite hosting what appears to be proprietary RTL (Register Transfer Level) "
            "source code for the Helios H7 RISC-V processor core. Includes SystemVerilog files, "
            "constraint files, testbenches, and synthesis scripts. Files contain copyright headers "
            "referencing 'Helios Semiconductor Inc. Confidential'. Eepsite appeared 6 hours ago. "
            "Operator claims more IP will be published weekly. "
            "Files match structure of commercial RISC-V implementations with custom extensions."
        ),
        "author": "silicon_liberator",
        "published_at": _now_minus(hours=6),
        "raw_data": {"eepsite": "helios-leaks.i2p", "file_count": 342, "network": "i2p"},
    },
    # Helios — exploit
    {
        "source_type": SourceType.TOR_FORUM.value,
        "source_url": "http://exploit.onion/thread/helios-supply-chain",
        "source_name": "Exploit.in",
        "title": "0-day in Helios chip firmware update mechanism",
        "content": (
            "Discovered vulnerability in the secure boot chain of Helios H5 and H7 series chips. "
            "The firmware update verification uses a predictable nonce in the signature check, "
            "allowing an attacker with physical access to install unsigned firmware. "
            "Combined with the JTAG debug port issue (CVE-2025-41122), this creates a complete "
            "supply chain attack vector. PoC available. Selling exclusive for $150K. "
            "Affected: all Helios H5/H7 chips manufactured before Feb 2026."
        ),
        "author": "silicon_ghost",
        "published_at": _now_minus(days=4),
        "raw_data": {"price_usd": 150000, "affected_products": ["H5", "H7"]},
    },
    # Helios — dark web mention
    {
        "source_type": SourceType.TOR_FORUM.value,
        "source_url": "http://forum.onion/thread/92847",
        "source_name": "XSS.is",
        "title": "APT group targeting semiconductor companies — Helios mentioned",
        "content": (
            "Threat intelligence report shared on XSS.is forum discussing APT41 (Winnti) "
            "campaign targeting semiconductor companies. Specific mention of Helios Semiconductor "
            "as a confirmed target. Attack vector: spear-phishing of engineering staff via "
            "fake EDA tool updates. Malware: modified version of ShadowPad backdoor with "
            "custom C2 protocol. IOCs: C2 domains include eda-update.heliossemi-support[.]com, "
            "synopsys-patch[.]com. Campaign active since November 2025."
        ),
        "author": "intel_analyst_99",
        "published_at": _now_minus(days=5, hours=14),
        "raw_data": {"apt_group": "APT41", "campaign": "Operation Silicon Harvest"},
    },
    # Meridian — brand abuse
    {
        "source_type": SourceType.SURFACE_WEB.value,
        "source_url": "https://meridianfg-secure.com",
        "source_name": "Brand Monitor",
        "title": "Typosquat domain meridianfg-secure.com serving credential harvester",
        "content": (
            "Newly registered domain meridianfg-secure.com (registered 2026-03-07 via Namecheap) "
            "is hosting a pixel-perfect clone of the Meridian Financial Group customer login portal. "
            "The page collects username, password, and 2FA codes. Exfiltration via WebSocket to "
            "185.234.72.19 (AS 208091, Flyservers). SSL cert from Let's Encrypt. "
            "WHOIS privacy enabled. Page loads custom anti-bot JS that blocks headless browsers."
        ),
        "author": None,
        "published_at": _now_minus(days=1, hours=2),
        "raw_data": {"domain": "meridianfg-secure.com", "registrar": "Namecheap", "ip": "185.234.72.19"},
    },
    # Meridian — VIP doxxing
    {
        "source_type": SourceType.MATRIX.value,
        "source_url": "matrix:r/doxbin-ops:matrix.org/$event123",
        "source_name": "Matrix/Element",
        "title": "Doxxing of Meridian Financial CEO David Chen posted on Matrix",
        "content": (
            "Message in Matrix room #doxbin-ops:matrix.org containing personal information about "
            "David Chen, CEO of Meridian Financial Group. Includes home address in Pacific Heights SF, "
            "personal phone number, children's school, vehicle details (2025 Tesla Model S, CA plate). "
            "Message links to paste with additional family member details compiled from public records. "
            "Posted in retaliation for Meridian's foreclosure actions. Pinned in room with 3,200 members."
        ),
        "author": "@anon_doxer:matrix.org",
        "published_at": _now_minus(days=2, hours=18),
        "raw_data": {"room": "#doxbin-ops:matrix.org", "members": 3200, "target": "David Chen"},
    },
    # NovaMed — impersonation
    {
        "source_type": SourceType.SURFACE_WEB.value,
        "source_url": "https://novamed-careers.com",
        "source_name": "Brand Monitor",
        "title": "Fake NovaMed Health careers site collecting applicant PII",
        "content": (
            "Domain novamed-careers.com is impersonating NovaMed Health Systems' career portal. "
            "The site lists fake job openings (Senior Nurse, IT Security Analyst, Billing Specialist) "
            "and collects full applications including SSN, driver's license, and direct deposit info "
            "'for background check purposes'. Uses NovaMed logo and branding. Hosted on Digital Ocean "
            "droplet 164.90.131.44. Domain registered 2026-03-05 via GoDaddy. "
            "Google has not yet flagged it as phishing."
        ),
        "author": None,
        "published_at": _now_minus(days=1, hours=14),
        "raw_data": {"domain": "novamed-careers.com", "ip": "164.90.131.44", "registrar": "GoDaddy"},
    },
]

# ---------------------------------------------------------------------------
# Alerts (derived from raw intel, with triage output)
# ---------------------------------------------------------------------------

ALERTS_DATA = [
    # Meridian alerts
    {
        "org": "Meridian Financial Group",
        "raw_title": "Meridian Financial Group — Employee credential dump (12K records)",
        "category": ThreatCategory.CREDENTIAL_LEAK.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "status": AlertStatus.INVESTIGATING.value,
        "title": "12,847 Meridian employee credentials listed for sale on BreachForums",
        "summary": (
            "A threat actor 'darkvendor77' is selling a dump of 12,847 employee credentials from "
            "Meridian Financial Group on BreachForums. The data includes bcrypt-hashed passwords, "
            "emails, employee IDs, and department info. C-suite email addresses were identified, "
            "including the CEO and CISO."
        ),
        "confidence": 0.94,
        "matched_entities": {
            "domain": "meridianfg.com — exact match in email addresses",
            "VIP - David Chen": "david.chen@meridianfg.com found in dump",
            "VIP - Priya Sharma": "priya.sharma@meridianfg.com found in dump",
            "organization name": "Meridian Financial Group explicitly named",
        },
        "recommended_actions": [
            "Immediately force password reset for all employees, prioritizing C-suite accounts",
            "Enable MFA on all accounts that don't have it already",
            "Engage incident response team to investigate the source of the breach",
            "Monitor for account takeover attempts on compromised email addresses",
            "Contact BreachForums moderators to request takedown (likely unsuccessful but documented)",
            "Notify legal team and prepare breach disclosure per SEC requirements",
        ],
        "agent_reasoning": (
            "This is a confirmed, high-confidence threat. The credential dump explicitly names "
            "Meridian Financial Group and contains email addresses matching the organization's "
            "primary domain. Two VIP email addresses (CEO and CISO) were found in the sample data. "
            "The data format (Azure AD sync) matches the org's known tech stack. The seller has "
            "a history of legitimate sales on BreachForums with 47 positive reviews."
        ),
        "analyst_notes": (
            "IR team engaged at 14:30 UTC. Confirmed the Azure AD sync service was compromised "
            "via a deprecated API endpoint. Password resets initiated for all 12K+ accounts. "
            "CISO Priya Sharma notified directly."
        ),
    },
    {
        "org": "Meridian Financial Group",
        "raw_title": "Meridian Bank login clone kit with SMS bypass",
        "category": ThreatCategory.PHISHING.value,
        "severity": ThreatSeverity.HIGH.value,
        "status": AlertStatus.TRIAGED.value,
        "title": "Phishing kit targeting Meridian Bank portal with 2FA bypass capability",
        "summary": (
            "A phishing kit replicating the Meridian Bank customer portal is being sold on Telegram. "
            "The kit includes a real-time SMS OTP interception module and is specifically designed to "
            "target portal.meridianfg.com. A lookalike domain merid1an-secure.com is already registered."
        ),
        "confidence": 0.91,
        "matched_entities": {
            "domain": "portal.meridianfg.com specifically targeted",
            "lookalike domain": "merid1an-secure.com registered for campaign",
        },
        "recommended_actions": [
            "Submit takedown request for merid1an-secure.com to registrar and Cloudflare",
            "Add merid1an-secure.com to internal DNS blocklists and email filters",
            "Alert customer-facing teams to watch for phishing reports",
            "Consider proactive customer notification about phishing campaign",
            "Request Telegram channel takedown via Telegram abuse reporting",
        ],
        "agent_reasoning": (
            "High confidence phishing threat. The kit explicitly targets the org's customer portal "
            "URL and a typosquat domain has already been provisioned. The 2FA bypass capability "
            "makes this significantly more dangerous than typical phishing kits."
        ),
    },
    {
        "org": "Meridian Financial Group",
        "raw_title": "LockBit claims breach of financial services firm",
        "category": ThreatCategory.RANSOMWARE.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "status": AlertStatus.NEW.value,
        "title": "LockBit ransomware group claims breach — $3.5M ransom, 14-day countdown",
        "summary": (
            "LockBit ransomware group has posted Meridian Financial Group on their data leak site "
            "with a 14-day countdown timer and $3.5M ransom demand. Leaked screenshots show internal "
            "documents labeled 'Meridian Capital Advisors' and 'MFG Compliance Reports'. Sample data "
            "includes board meeting minutes, M&A documents, and customer PII."
        ),
        "confidence": 0.97,
        "matched_entities": {
            "organization name": "Meridian Capital Advisors — subsidiary/brand name match",
            "internal documents": "MFG Compliance Reports — matches org initials",
            "data type": "Board minutes, M&A docs, customer PII consistent with financial services",
        },
        "recommended_actions": [
            "Activate incident response plan immediately — this is a confirmed ransomware incident",
            "Engage external forensics firm for investigation and containment",
            "Isolate affected systems to prevent lateral movement",
            "Do NOT pay ransom without legal counsel and board approval",
            "Prepare SEC 8-K filing (4 business day deadline under new rules)",
            "Brief the board of directors within 24 hours",
            "Coordinate with FBI Cyber Division and CISA",
        ],
        "agent_reasoning": (
            "Near-certain confidence. LockBit's data leak site contains screenshots with documents "
            "explicitly referencing Meridian's subsidiary names. The document types (board minutes, "
            "M&A docs) are consistent with a financial services firm of this size. LockBit has a "
            "verified track record of legitimate breach claims. The 14-day countdown is standard "
            "for their double-extortion model."
        ),
    },
    {
        "org": "Meridian Financial Group",
        "raw_title": "Typosquat domain meridianfg-secure.com serving credential harvester",
        "category": ThreatCategory.BRAND_ABUSE.value,
        "severity": ThreatSeverity.HIGH.value,
        "status": AlertStatus.NEW.value,
        "title": "Active typosquat domain meridianfg-secure.com harvesting credentials",
        "summary": (
            "A newly registered domain meridianfg-secure.com is serving a pixel-perfect clone of the "
            "Meridian Financial Group customer login portal. The phishing page collects credentials "
            "and 2FA codes, exfiltrating them via WebSocket to a Flyservers IP address."
        ),
        "confidence": 0.96,
        "matched_entities": {
            "domain": "meridianfg.com — typosquat with -secure suffix",
            "login portal": "Pixel-perfect clone of customer login page",
        },
        "recommended_actions": [
            "Submit domain takedown request to Namecheap (registrar) and Cloudflare (hosting)",
            "Add to organization-wide DNS blocklist immediately",
            "Notify Google Safe Browsing and Microsoft SmartScreen for browser blocking",
            "Alert customers who may have visited the domain in the past 48 hours",
        ],
        "agent_reasoning": (
            "Very high confidence brand abuse. The domain is a clear typosquat of the organization's "
            "primary domain with a common social engineering suffix (-secure). Active credential "
            "harvesting confirmed with data exfiltration infrastructure."
        ),
    },
    {
        "org": "Meridian Financial Group",
        "raw_title": "Doxxing of Meridian Financial CEO David Chen",
        "category": ThreatCategory.DOXXING.value,
        "severity": ThreatSeverity.HIGH.value,
        "status": AlertStatus.NEW.value,
        "title": "CEO David Chen personal information exposed in viral Twitter thread",
        "summary": (
            "A Twitter/X thread with 4,200 retweets has exposed personal details of CEO David Chen "
            "including home address, personal phone, children's school, and vehicle details. The post "
            "was motivated by retaliation against Meridian's foreclosure actions."
        ),
        "confidence": 0.92,
        "matched_entities": {
            "VIP - David Chen": "Named directly with correct title (CEO)",
            "organization": "Meridian Financial Group referenced as employer",
        },
        "recommended_actions": [
            "Alert David Chen's executive protection team immediately",
            "Request Twitter/X content removal under their doxxing policy",
            "Engage reputation management firm for content scrubbing",
            "Consider temporary enhanced physical security measures",
            "Brief David Chen on potential social engineering attempts using leaked info",
        ],
        "agent_reasoning": (
            "Confirmed doxxing of a monitored VIP. David Chen is the CEO and the information "
            "exposed (home address, family details) creates a physical security risk. The viral "
            "nature of the post (4,200 retweets) means the information has been widely disseminated."
        ),
    },
    # NovaMed alerts
    {
        "org": "NovaMed Health Systems",
        "raw_title": "NovaMed patient records sample — 500 PHI records",
        "category": ThreatCategory.DATA_BREACH.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "status": AlertStatus.INVESTIGATING.value,
        "title": "2.3M patient records (PHI) for sale — sample verified on paste site",
        "summary": (
            "A threat actor 'ghost_data_vendor' is selling 2.3 million NovaMed patient records "
            "containing protected health information including SSNs, diagnoses, prescriptions, "
            "and insurance details. A 500-record sample has been posted on Rentry as proof."
        ),
        "confidence": 0.93,
        "matched_entities": {
            "organization name": "NovaMed Health Systems explicitly referenced",
            "data type": "PHI fields match EHR data structure — likely from Epic Systems",
            "insurance IDs": "BlueCross format consistent with NovaMed's insurer network",
        },
        "recommended_actions": [
            "Engage healthcare breach response counsel immediately (HIPAA mandatory notification)",
            "Verify whether the sample data matches actual patient records (with privacy controls)",
            "Report to HHS Office for Civil Rights within 60 days (HIPAA Breach Notification Rule)",
            "Engage forensics team to identify the breach vector",
            "Prepare patient notification letters per state breach notification laws",
            "Offer credit monitoring to affected patients",
        ],
        "agent_reasoning": (
            "Critical healthcare data breach. The data fields (ICD-10 codes, prescription details, "
            "SSNs) are consistent with EHR system output. NovaMed uses Epic Systems which matches "
            "the data structure. The seller has 23 confirmed sales on BreachForums. HIPAA breach "
            "notification obligations apply — this is a regulatory emergency."
        ),
        "analyst_notes": (
            "HIPAA breach response team activated. Legal counsel (Baker & McKenzie) engaged. "
            "Verifying sample data against patient database in isolated environment. "
            "HHS notification deadline tracked: 60 days from confirmation."
        ),
    },
    {
        "org": "NovaMed Health Systems",
        "raw_title": "CVE-2026-21543 — Epic Systems MyChart RCE",
        "category": ThreatCategory.STEALER_LOG.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "status": AlertStatus.TRIAGED.value,
        "title": "Critical RCE in Epic MyChart (CVE-2026-21543) — NovaMed runs affected version",
        "summary": (
            "A critical remote code execution vulnerability (CVSS 9.8) has been disclosed in Epic "
            "Systems MyChart versions 2024.1-2025.3. NovaMed Health Systems runs MyChart as their "
            "patient portal, and the vulnerability is being actively exploited in the wild."
        ),
        "confidence": 0.88,
        "matched_entities": {
            "tech stack": "Epic Systems MyChart — confirmed in org's tech stack",
            "product": "Patient portal at patient.novamed.health likely runs MyChart",
        },
        "recommended_actions": [
            "Verify current MyChart version and determine if affected",
            "Apply Epic patch (MyChart 2025.4) immediately if vulnerable",
            "Implement virtual patching via WAF rules for FHIR R4 endpoint",
            "Monitor logs for exploitation attempts against /api/FHIR/R4/Patient",
            "Contact Epic support for emergency patching assistance",
        ],
        "agent_reasoning": (
            "NovaMed's tech stack includes Epic Systems for their EMR/patient portal. The "
            "vulnerability has a CVSS score of 9.8 and is in CISA's Known Exploited Vulnerabilities "
            "catalog, meaning active exploitation is confirmed. The FHIR API endpoint is commonly "
            "exposed on patient-facing portals."
        ),
    },
    {
        "org": "NovaMed Health Systems",
        "raw_title": "NovaMed VPN + AD credentials — verified insider access",
        "category": ThreatCategory.INSIDER_THREAT.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "status": AlertStatus.NEW.value,
        "title": "Active insider selling NovaMed domain admin VPN access for $2K/week",
        "summary": (
            "A threat actor claiming to be an insider at NovaMed Health Systems is selling "
            "verified VPN and Active Directory domain admin credentials on DarkMarket. The listing "
            "includes proof of current access to EHR, billing, and internal SharePoint systems."
        ),
        "confidence": 0.89,
        "matched_entities": {
            "organization name": "NovaMed Health Systems explicitly named",
            "systems": "EHR, billing, SharePoint consistent with known infrastructure",
            "access type": "VPN + AD domain admin — matches Azure AD/Citrix setup",
        },
        "recommended_actions": [
            "Immediately audit all domain admin accounts for unauthorized access",
            "Review VPN connection logs for anomalous patterns (unusual hours, locations, devices)",
            "Reset all domain admin passwords and rotate Citrix access tokens",
            "Engage threat hunting team to search for indicators of compromise",
            "Consider employee behavioral analytics to identify the insider",
            "Brief HR and legal on potential insider threat investigation",
        ],
        "agent_reasoning": (
            "High-confidence insider threat. The seller provides proof of current access with "
            "today's timestamp. The subscription model ($2K/week) suggests ongoing access rather "
            "than a one-time exfiltration. The systems described match NovaMed's known infrastructure."
        ),
    },
    {
        "org": "NovaMed Health Systems",
        "raw_title": "Fake NovaMed Health careers site collecting applicant PII",
        "category": ThreatCategory.IMPERSONATION.value,
        "severity": ThreatSeverity.HIGH.value,
        "status": AlertStatus.NEW.value,
        "title": "Fraudulent NovaMed careers portal collecting SSNs and banking info",
        "summary": (
            "A fake careers website at novamed-careers.com is impersonating NovaMed Health Systems "
            "and collecting full applications including SSN, driver's license, and direct deposit "
            "information from job seekers. The site uses NovaMed's official branding."
        ),
        "confidence": 0.95,
        "matched_entities": {
            "organization name": "NovaMed Health — brand name used with official logos",
            "domain": "novamed-careers.com — uses org name in domain",
        },
        "recommended_actions": [
            "Submit domain takedown to GoDaddy (registrar) and Digital Ocean (host)",
            "Report to Google Safe Browsing and anti-phishing working groups",
            "Post warning on official NovaMed careers page about the fraudulent site",
            "Alert local law enforcement as this constitutes identity theft",
        ],
        "agent_reasoning": (
            "Very high confidence impersonation. The domain uses the organization's name and "
            "official branding. The data collection (SSN, banking info) goes far beyond typical "
            "phishing, constituting active identity theft of job seekers."
        ),
    },
    # Helios alerts
    {
        "org": "Helios Semiconductor",
        "raw_title": "Helios RISC-V RTL design files leaked on GitHub",
        "category": ThreatCategory.DARK_WEB_MENTION.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "status": AlertStatus.NEW.value,
        "title": "Proprietary H7 RISC-V processor RTL source code leaked on GitHub (847 stars)",
        "summary": (
            "A GitHub repository contains what appears to be the complete RTL source code for "
            "Helios Semiconductor's H7 RISC-V processor core. Files include SystemVerilog, "
            "constraints, testbenches, and synthesis scripts with Helios copyright headers. "
            "The repo has already gained 847 stars in 6 hours."
        ),
        "confidence": 0.96,
        "matched_entities": {
            "organization name": "'Helios Semiconductor Inc. Confidential' in copyright headers",
            "product": "H7 RISC-V processor core — matches known product line",
            "file structure": "RTL design files consistent with commercial ASIC development",
        },
        "recommended_actions": [
            "File DMCA takedown with GitHub immediately — repository URL: github.com/anon-leak/helios-rtl-v3",
            "Engage IP counsel to assess trade secret exposure and legal remedies",
            "Investigate how the source code was exfiltrated (insider vs. external breach)",
            "Audit access controls on internal GitLab for the H7 repository",
            "Assess competitive impact — determine if the leak enables counterfeit chips",
            "Brief the board on potential impact to competitive advantage and patent portfolio",
        ],
        "agent_reasoning": (
            "Near-certain confidence of proprietary code leak. The copyright headers explicitly "
            "reference Helios Semiconductor. The file structure and SystemVerilog contents are "
            "consistent with a commercial RISC-V implementation. The rapid star growth (847 in "
            "6 hours) indicates wide dissemination. This represents significant IP theft."
        ),
    },
    {
        "org": "Helios Semiconductor",
        "raw_title": "0-day in Helios chip firmware update mechanism",
        "category": ThreatCategory.EXPLOIT.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "status": AlertStatus.TRIAGED.value,
        "title": "0-day exploit for Helios H5/H7 secure boot bypass — $150K asking price",
        "summary": (
            "A researcher is selling a 0-day exploit for the Helios H5 and H7 secure boot chain. "
            "The vulnerability allows installation of unsigned firmware via a predictable nonce in "
            "the signature verification. Combined with a known JTAG issue, it creates a complete "
            "supply chain attack vector affecting all chips manufactured before February 2026."
        ),
        "confidence": 0.85,
        "matched_entities": {
            "products": "Helios H5 and H7 chip series — exact product names",
            "vulnerability": "Firmware update mechanism is a known component of Helios silicon",
        },
        "recommended_actions": [
            "Alert the hardware security team to assess the reported vulnerability",
            "Review the secure boot signature verification implementation in H5/H7 firmware",
            "Consider engaging the seller through a vulnerability disclosure program",
            "Prepare firmware update to remediate the predictable nonce issue",
            "Assess the scope of affected devices in the field and plan recall/update strategy",
            "Coordinate with customer support for proactive advisory to OEM partners",
        ],
        "agent_reasoning": (
            "High confidence. The threat actor demonstrates specific knowledge of Helios's secure "
            "boot architecture (nonce-based signature verification) that is not publicly documented. "
            "The reference to CVE-2025-41122 (JTAG debug port issue) is a real vulnerability "
            "affecting Helios chips. The $150K price point is consistent with hardware 0-days."
        ),
    },
    {
        "org": "Helios Semiconductor",
        "raw_title": "APT group targeting semiconductor companies — Helios mentioned",
        "category": ThreatCategory.DARK_WEB_MENTION.value,
        "severity": ThreatSeverity.HIGH.value,
        "status": AlertStatus.NEW.value,
        "title": "APT41 campaign targeting Helios via fake EDA tool updates",
        "summary": (
            "Intelligence report on XSS.is identifies Helios Semiconductor as a confirmed target "
            "of an APT41 (Winnti) campaign dubbed 'Operation Silicon Harvest'. The attack uses "
            "spear-phishing with fake EDA tool updates deploying a modified ShadowPad backdoor."
        ),
        "confidence": 0.82,
        "matched_entities": {
            "organization name": "Helios Semiconductor explicitly named as confirmed target",
            "tech stack": "EDA tools (Synopsys, Cadence) match org's known tool chain",
            "C2 indicators": "eda-update.heliossemi-support[.]com — uses org name in C2 domain",
        },
        "recommended_actions": [
            "Block IOC domains immediately: eda-update.heliossemi-support.com, synopsys-patch.com",
            "Hunt for ShadowPad indicators across the network (check EDR for known signatures)",
            "Alert engineering staff about the spear-phishing vector (fake EDA tool updates)",
            "Review email logs for messages referencing EDA tool updates in the past 90 days",
            "Engage Mandiant or CrowdStrike for APT41 threat hunting engagement",
        ],
        "agent_reasoning": (
            "Moderately high confidence. APT41/Winnti is a well-documented threat group with "
            "known interest in semiconductor IP. The C2 domain uses a typosquat of the org's "
            "name, and the phishing vector (fake EDA updates) is specifically tailored to "
            "semiconductor engineers who regularly update these expensive, niche tools."
        ),
    },
    # Extra lower-severity alerts
    {
        "org": "Meridian Financial Group",
        "raw_title": None,
        "category": ThreatCategory.DARK_WEB_MENTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "status": AlertStatus.RESOLVED.value,
        "title": "Meridian Financial mentioned in ransomware targeting discussion",
        "summary": (
            "Forum thread on Exploit.in discussing potential targets in the US financial sector "
            "mentions Meridian Financial Group as having 'weak external posture'. No specific "
            "attack plans or capabilities shared."
        ),
        "confidence": 0.65,
        "matched_entities": {
            "organization name": "Meridian Financial Group mentioned by name",
        },
        "recommended_actions": [
            "Continue monitoring the thread for escalation",
            "Review and harden external-facing services as a precaution",
        ],
        "agent_reasoning": (
            "Moderate confidence. The mention is in a general targeting discussion without "
            "specific attack plans. The comment about 'weak external posture' may indicate "
            "prior reconnaissance but no active threat is confirmed."
        ),
        "analyst_notes": "Reviewed by senior analyst. Monitoring thread — no escalation observed after 5 days.",
    },
    {
        "org": "Helios Semiconductor",
        "raw_title": None,
        "category": ThreatCategory.UNDERGROUND_CHATTER.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "status": AlertStatus.FALSE_POSITIVE.value,
        "title": "Helios internal network diagram shared on paste site",
        "summary": (
            "A paste on Rentry contains what appears to be a network topology diagram for "
            "Helios Semiconductor's design lab. Upon analysis, the diagram matches publicly "
            "available conference presentation slides from IEEE ISSCC 2025."
        ),
        "confidence": 0.42,
        "matched_entities": {
            "organization name": "Helios Semiconductor referenced",
        },
        "recommended_actions": [
            "No action required — confirmed public information",
        ],
        "agent_reasoning": (
            "Initial analysis flagged this as a potential internal document leak. However, "
            "comparison with public sources shows the diagram matches conference presentation "
            "materials. Downgraded to false positive."
        ),
        "analyst_notes": "Confirmed false positive. Diagram is from public IEEE ISSCC 2025 talk by Dr. Li Wei.",
    },
    {
        "org": "NovaMed Health Systems",
        "raw_title": None,
        "category": ThreatCategory.STEALER_LOG.value,
        "severity": ThreatSeverity.LOW.value,
        "status": AlertStatus.RESOLVED.value,
        "title": "Informational SSL/TLS configuration weakness on telehealth subdomain",
        "summary": (
            "The telehealth.novamed.health subdomain supports TLS 1.0 and 1.1 in addition to "
            "TLS 1.2/1.3. While not immediately exploitable, this represents a configuration "
            "weakness that should be remediated."
        ),
        "confidence": 0.78,
        "matched_entities": {
            "domain": "telehealth.novamed.health — organization subdomain",
        },
        "recommended_actions": [
            "Disable TLS 1.0 and 1.1 on the telehealth load balancer",
        ],
        "agent_reasoning": (
            "Low-severity configuration issue. TLS 1.0/1.1 are deprecated but not immediately "
            "dangerous. This is a compliance concern (HIPAA requires strong encryption) rather "
            "than an active threat."
        ),
        "analyst_notes": "TLS 1.0/1.1 disabled on 2026-03-08. Verified with SSL Labs scan — A+ rating.",
    },
]


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------


async def seed():
    """Populate the database with realistic demo data."""
    await init_db()

    async for session in get_session():
        # Check if already seeded
        existing = await session.execute(select(Organization))
        if existing.scalars().first():
            print("Database already has data — skipping seed. "
                  "Drop tables first if you want to re-seed.")
            return

        org_map: dict[str, Organization] = {}
        raw_map: dict[str, RawIntel] = {}
        user_map: dict[str, User] = {}
        asset_map: dict[str, list[Asset]] = {}
        vip_map: dict[str, list[VIPTarget]] = {}
        alert_map: dict[str, Alert] = {}

        # 0. Create Users — adversarial audit D-4: random passwords per
        # run, printed once. Never store working credentials in source.
        existing_users = await session.execute(select(User))
        existing_user_rows = existing_users.scalars().all()
        for u in existing_user_rows:
            user_map[u.username] = u
        if not existing_user_rows:
            admin_pwd = _secrets.token_urlsafe(18)
            analyst_pwd = _secrets.token_urlsafe(18)
            admin_user = User(
                email="admin@argus.local",
                username="admin",
                password_hash=hash_password(admin_pwd),
                display_name="Argus Admin",
                role=UserRole.ADMIN.value,
                is_active=True,
            )
            session.add(admin_user)

            analyst_user = User(
                email="analyst@argus.local",
                username="analyst",
                password_hash=hash_password(analyst_pwd),
                display_name="Argus Analyst",
                role=UserRole.ANALYST.value,
                is_active=True,
            )
            session.add(analyst_user)
            await session.flush()
            print("============================================================")
            print("DEMO USERS (random passwords — copy now, shown only once):")
            print(f"  admin:    admin@argus.local  /  {admin_pwd}")
            print(f"  analyst:  analyst@argus.local  /  {analyst_pwd}")
            print("============================================================")

            await audit_log(
                session,
                AuditAction.USER_CREATE,
                user=admin_user,
                resource_type="user",
                resource_id=str(admin_user.id),
                details={"email": admin_user.email, "role": "admin", "source": "seed"},
            )
            await audit_log(
                session,
                AuditAction.USER_CREATE,
                user=admin_user,
                resource_type="user",
                resource_id=str(analyst_user.id),
                details={"email": analyst_user.email, "role": "analyst", "source": "seed"},
            )
            await session.flush()
            user_map["admin"] = admin_user
            user_map["analyst"] = analyst_user
            print(f"Created 2 users (admin + analyst)")
        else:
            print("Users already exist — skipping user seed")

        # 1. Create Organizations
        for org_data in ORGS:
            org = Organization(
                name=org_data["name"],
                domains=org_data["domains"],
                keywords=org_data["keywords"],
                industry=org_data["industry"],
                tech_stack=org_data["tech_stack"],
            )
            session.add(org)
            org_map[org_data["name"]] = org
        await session.flush()
        print(f"Created {len(ORGS)} organizations")

        # 2. Create VIPs
        vip_count = 0
        for org_name, vips in VIPS.items():
            org = org_map[org_name]
            vip_map.setdefault(org_name, [])
            for vip_data in vips:
                vip = VIPTarget(
                    organization_id=org.id,
                    name=vip_data["name"],
                    title=vip_data["title"],
                    emails=vip_data["emails"],
                    usernames=vip_data["usernames"],
                    phone_numbers=vip_data["phone_numbers"],
                )
                session.add(vip)
                vip_map[org_name].append(vip)
                vip_count += 1
        await session.flush()
        print(f"Created {vip_count} VIP targets")

        # 3. Create Assets
        asset_count = 0
        for org_name, assets in ASSETS.items():
            org = org_map[org_name]
            asset_map.setdefault(org_name, [])
            for asset_data in assets:
                asset = Asset(
                    organization_id=org.id,
                    asset_type=asset_data["asset_type"],
                    value=asset_data["value"],
                    details=asset_data["details"],
                    is_active=True,
                )
                session.add(asset)
                asset_map[org_name].append(asset)
                asset_count += 1
        await session.flush()
        print(f"Created {asset_count} assets")

        # 4. Create Raw Intel
        import hashlib
        for intel_data in RAW_INTEL:
            content_hash = hashlib.sha256(
                (intel_data["title"] + intel_data["content"]).encode()
            ).hexdigest()
            raw = RawIntel(
                source_type=intel_data["source_type"],
                source_url=intel_data["source_url"],
                source_name=intel_data["source_name"],
                title=intel_data["title"],
                content=intel_data["content"],
                author=intel_data["author"],
                published_at=intel_data["published_at"],
                raw_data=intel_data["raw_data"],
                content_hash=content_hash,
                is_processed=True,
            )
            session.add(raw)
            raw_map[intel_data["title"]] = raw
        await session.flush()
        print(f"Created {len(RAW_INTEL)} raw intel records")

        # 5. Create Alerts
        alert_count = 0
        for alert_data in ALERTS_DATA:
            org = org_map[alert_data["org"]]
            raw_intel_id = None
            if alert_data.get("raw_title") and alert_data["raw_title"] in raw_map:
                raw_intel_id = raw_map[alert_data["raw_title"]].id

            # Stagger created_at for realistic timeline
            created_offset = timedelta(
                hours=random.randint(0, 120),
                minutes=random.randint(0, 59),
            )
            created_at = datetime.now(timezone.utc) - created_offset

            alert = Alert(
                organization_id=org.id,
                raw_intel_id=raw_intel_id,
                category=alert_data["category"],
                severity=alert_data["severity"],
                status=alert_data["status"],
                title=alert_data["title"],
                summary=alert_data["summary"],
                confidence=alert_data["confidence"],
                matched_entities=alert_data["matched_entities"],
                recommended_actions=alert_data["recommended_actions"],
                agent_reasoning=alert_data["agent_reasoning"],
                analyst_notes=alert_data.get("analyst_notes"),
                details={
                    "triage_version": "1.0",
                    "model": "glm-5",
                    "provider": "z.ai",
                },
            )
            # Override created_at for realistic spread
            alert.created_at = created_at
            session.add(alert)
            alert_map[alert_data["title"]] = alert
            alert_count += 1
        await session.flush()
        print(f"Created {alert_count} alerts")

        # 6. Comprehensive seed — populate every dashboard-visible table
        # with rich, FK-correct data so list pages have rows and detail
        # pages resolve.
        print("Seeding remaining tables (this populates ~60 tables)...")
        extra_counts = await seed_extra(
            session,
            org_map=org_map,
            alert_map=alert_map,
            user_map=user_map,
            asset_map=asset_map,
            raw_intel_map=raw_map,
            vip_map=vip_map,
        )

        await session.commit()
        print("\nSeed complete! Your Argus demo is ready.")
        print(f"  Users:         {len(user_map)}")
        print(f"  Organizations: {len(ORGS)}")
        print(f"  VIP targets:   {vip_count}")
        print(f"  Assets:        {asset_count}")
        print(f"  Raw intel:     {len(RAW_INTEL)}")
        print(f"  Alerts:        {alert_count}")
        for k in sorted(extra_counts):
            print(f"  {k:<30} {extra_counts[k]}")


if __name__ == "__main__":
    _refuse_in_production()
    asyncio.run(seed())
