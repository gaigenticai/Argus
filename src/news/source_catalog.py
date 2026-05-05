"""Curated catalog of OSS RSS/Atom/JSON sources for the unified pipeline.

Three categories that map to the FE pages:

  * ``news``        — vendor blogs + community sites + research labs
                      → surfaces on /news (raw feed) + /intel (when org-relevant)
  * ``intel``       — high-signal CTI sources (CISA, NCSC, JPCERT, Securelist)
                      → surfaces on /intel (curated reports)
  * ``advisories``  — vendor PSIRTs + CISA KEV + GHSA + Red Hat CSAF
                      → surfaces on /advisories (CVE-driven; CVSS/EPSS/KEV)

Credibility scores are coarse (0-100) — used to break ties when sorting
the per-org relevance feed.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FeedDef:
    name: str
    url: str
    kind: str  # rss | atom | json_feed
    category: str  # news | intel | advisories
    credibility: int  # 0-100
    language: str = "en"
    description: str | None = None
    fetch_interval_seconds: int = 14400  # 4h default


CATALOG: tuple[FeedDef, ...] = (
    # ===== News (vendor blogs, community, research) =====
    FeedDef(
        "BleepingComputer",
        "https://www.bleepingcomputer.com/feed/",
        "rss", "news", 80, description="Breach + ransomware news desk."),
    FeedDef(
        "KrebsOnSecurity",
        "https://krebsonsecurity.com/feed/",
        "rss", "news", 90, description="Investigative cybersecurity reporting."),
    FeedDef(
        "The Hacker News",
        "https://feeds.feedburner.com/TheHackersNews",
        "rss", "news", 70),
    FeedDef(
        "DarkReading",
        "https://www.darkreading.com/rss.xml",
        "rss", "news", 75),
    FeedDef(
        "SecurityWeek",
        "https://www.securityweek.com/feed",
        "rss", "news", 75),
    FeedDef(
        "Schneier on Security",
        "https://www.schneier.com/feed/atom/",
        "atom", "news", 90),
    FeedDef(
        "Risky Business",
        "https://risky.biz/feeds/risky-business",
        "rss", "news", 80),
    FeedDef(
        "Sophos Naked Security",
        "https://news.sophos.com/en-us/category/threat-research/feed/",
        "rss", "news", 70),
    FeedDef(
        "ESET WeLiveSecurity",
        "https://www.welivesecurity.com/feed/",
        "rss", "news", 75),
    FeedDef(
        "Trend Micro Research",
        "https://www.trendmicro.com/en_us/research.rss",
        "rss", "news", 75),
    FeedDef(
        "Check Point Research",
        "https://research.checkpoint.com/feed/",
        "rss", "news", 80),
    FeedDef(
        "Sucuri Security",
        "https://blog.sucuri.net/feed",
        "rss", "news", 65),
    FeedDef(
        "VirusTotal Blog",
        "https://blog.virustotal.com/feeds/posts/default",
        "atom", "news", 75),
    FeedDef(
        "Have I Been Pwned",
        "https://www.troyhunt.com/rss",
        "rss", "news", 85),
    # ===== Intel (research labs, CTI shops) =====
    FeedDef(
        "Mandiant Threat Intelligence",
        "https://www.mandiant.com/resources/blog/rss.xml",
        "rss", "intel", 95,
        description="Mandiant/Google Cloud research."),
    FeedDef(
        "CrowdStrike Blog",
        "https://www.crowdstrike.com/en-us/blog/feed/",
        "rss", "intel", 90),
    FeedDef(
        "Cisco Talos",
        "https://blog.talosintelligence.com/feeds/posts/default",
        "atom", "intel", 90),
    FeedDef(
        "Palo Alto Unit 42",
        "https://unit42.paloaltonetworks.com/feed/",
        "rss", "intel", 90),
    FeedDef(
        "Symantec Threat Intelligence",
        "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/feed",
        "rss", "intel", 85),
    FeedDef(
        "Kaspersky Securelist",
        "https://securelist.com/feed/",
        "rss", "intel", 85),
    FeedDef(
        "Microsoft Security Blog",
        "https://www.microsoft.com/en-us/security/blog/feed/",
        "rss", "intel", 85),
    FeedDef(
        "Google TAG / Project Zero",
        "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "atom", "intel", 95,
        description="Google Project Zero vulnerability research."),
    FeedDef(
        "SANS Internet Storm Center",
        "https://isc.sans.edu/rssfeed_full.xml",
        "rss", "intel", 90),
    FeedDef(
        "CERT-EU Security Advisories",
        "https://cert.europa.eu/publications/security-advisories/rss",
        "rss", "intel", 90),
    FeedDef(
        "JPCERT/CC Alerts",
        "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
        "rss", "intel", 90),
    FeedDef(
        "AusCERT Bulletins",
        "https://www.auscert.org.au/bulletins/rss/",
        "rss", "intel", 85),
    # ===== Advisories (vendor PSIRTs + government catalogs) =====
    FeedDef(
        "CISA Cybersecurity Advisories",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "rss", "advisories", 100,
        description="CISA-issued vulnerability/threat advisories."),
    FeedDef(
        "CISA KEV Catalog",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "json_feed", "advisories", 100,
        description="Known Exploited Vulnerabilities — re-fetched daily.",
        fetch_interval_seconds=86400),
    FeedDef(
        "CISA ICS Advisories",
        "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        "rss", "advisories", 100),
    FeedDef(
        "NCSC UK Alerts",
        "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        "rss", "advisories", 95),
    FeedDef(
        "MSRC Security Updates",
        "https://api.msrc.microsoft.com/update-guide/rss",
        "rss", "advisories", 95),
    FeedDef(
        "Adobe Security Bulletins",
        "https://helpx.adobe.com/security/security-bulletin.rss",
        "rss", "advisories", 90),
    FeedDef(
        "Cisco Security Advisories",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "rss", "advisories", 90),
    FeedDef(
        "Oracle Critical Patch Updates",
        "https://www.oracle.com/security-alerts/rss-feed.xml",
        "rss", "advisories", 90),
    FeedDef(
        "VMware Security Advisories",
        "https://www.vmware.com/security/advisories.xml",
        "rss", "advisories", 90),
    FeedDef(
        "Red Hat Product Security",
        "https://access.redhat.com/security/data/csaf/v2/advisories/index.csv",
        "rss", "advisories", 90,
        description="Red Hat CSAF advisory feed (CSV-style index)."),
    FeedDef(
        "GitHub Security Advisories (high-severity)",
        "https://github.com/advisories.atom?type=reviewed&severity=high",
        "atom", "advisories", 85,
        description="GHSA reviewed advisories at high severity."),
    FeedDef(
        "Debian Security Advisories",
        "https://www.debian.org/security/dsa.en.rdf",
        "rss", "advisories", 85),
    FeedDef(
        "Ubuntu Security Notices",
        "https://ubuntu.com/security/notices/rss.xml",
        "rss", "advisories", 85),
    FeedDef(
        "SUSE Security Advisories",
        "https://www.suse.com/feeds/security.xml",
        "rss", "advisories", 80),
    FeedDef(
        "BSI WID-CERT (DE)",
        "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
        "rss", "advisories", 90, language="de"),
)


def by_category(category: str) -> tuple[FeedDef, ...]:
    return tuple(f for f in CATALOG if f.category == category)


__all__ = ["FeedDef", "CATALOG", "by_category"]
