"""Wipe demo data and load a real-world target organisation.

Used for product evaluation: replace the synthetic seed (Argus Demo
Bank, three industry orgs, 50+ alerts of made-up threat actors) with a
single real organisation that we can pressure-test the platform
against.

The default target is **Emirates NBD** — the largest UAE bank, plenty
of public OSINT signal (phishing/lookalike domains, paste-site
mentions, dark-web chatter), and aligned with Marsad's GCC sales
motion.

What this script does:

1. Confirms the destructive wipe (no flag = abort).
2. TRUNCATEs every data table EXCEPT auth, audit, app settings, and
   the static reference catalogues (MITRE, CVEs, OSCAL, threat actor
   library, etc.).
3. Recreates the singleton system org named "Argus" so the deployment
   stays bootable.
4. Inserts the target org with its primary domain pre-marked
   ``status=verified`` so the dashboard isn't gated waiting on the
   evaluator to publish a DNS TXT record they can't access.
5. Adds brand terms for keyword/lookalike matching.
6. Inserts the apex domains as Asset rows (passive surface only —
   NO subdomains, NO IPs, NO services, so the EASM workers have
   nothing to actively probe against the bank's infrastructure).
7. Schedules the **passive-only** discovery jobs:
     - ``ct_log_backfill`` — public certificate transparency
     - ``whois_refresh`` — public registrar data
     - ``dns_refresh`` — MX/SPF/DKIM/DMARC over public resolvers
   The active jobs (``subdomain_enum``, ``httpx_probe``, ``port_scan``)
   are explicitly skipped — running them against a third-party bank's
   infra without authorisation is the wrong call legally and
   operationally.

After running, walk through the dashboard screen by screen and note
which surfaces light up vs. which stay empty. Empty surfaces ⇒ either
the org has no public signal of that type (rare for a Tier-1 bank) OR
the corresponding harvester isn't wired up.

USAGE
    .venv/bin/python -m scripts.seed.load_real_target --yes

OPTIONS
    --org NAME           Default: "Emirates NBD"
    --domain DOMAIN      Default: "emiratesnbd.com"
    --extra-domains ...  Default: "emiratesislamic.ae,liv.me"
    --industry STR       Default: "banking"
    --country CC         Default: "AE"
    --brand-terms ...    Default: "Emirates NBD,ENBD,Liv,Emirates Islamic"
    --yes                Required — confirms the destructive wipe
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Ensure every model is registered on Base.metadata before we ask the
# DB for its table list. This mirrors the pattern in storage/database.py.
import src.models.threat  # noqa: F401
import src.models.auth  # noqa: F401
import src.models.intel  # noqa: F401
import src.models.feeds  # noqa: F401
import src.models.onboarding  # noqa: F401
import src.models.evidence  # noqa: F401
import src.models.cases  # noqa: F401
import src.models.notifications  # noqa: F401
import src.models.mitre  # noqa: F401
import src.models.easm  # noqa: F401
import src.models.exposures  # noqa: F401
import src.models.ratings  # noqa: F401
import src.models.dmarc  # noqa: F401
import src.models.brand  # noqa: F401
import src.models.live_probe  # noqa: F401
import src.models.logo  # noqa: F401
import src.models.social  # noqa: F401
import src.models.fraud  # noqa: F401
import src.models.leakage  # noqa: F401
import src.models.intel_polish  # noqa: F401
import src.models.tprm  # noqa: F401

from src.models.admin import CrawlerTarget
from src.models.base import Base
from src.models.brand import BrandTerm, BrandTermKind
from src.models.onboarding import (
    DiscoveryJob,
    DiscoveryJobKind,
    DiscoveryJobStatus,
)
from src.models.threat import Asset, Organization
from src.storage import database as _db
from src.storage.database import init_db


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger("seed.load_real_target")


# Tables we MUST NOT truncate — auth state, audit history, system
# config, and the static reference catalogues. Anything else is fair
# game for a clean evaluation slate.
KEEP_TABLES = {
    # Auth + session state
    "users",
    "api_keys",
    # Audit history
    "audit_logs",
    # System config
    "app_settings",
    # Static reference catalogues — repopulating these is expensive
    # and they're not org-specific.
    "mitre_techniques",
    "mitre_tactics",
    "mitre_mitigations",
    "mitre_syncs",
    "cve_records",
    "d3fend_techniques",
    "attack_technique_attachments",
    "oscal_catalog_entries",
    "compliance_frameworks",
    "compliance_controls",
    "compliance_control_mappings",
    "threat_actors",
    "actor_playbooks",
    "credit_card_bins",
    "global_threat_status",
    # Alembic version pin — never touch.
    "alembic_version",
}

SYSTEM_ORG_NAME = "Argus"


async def _wipe(session: AsyncSession) -> int:
    """Truncate every data table not in KEEP_TABLES."""
    all_tables = {t.name for t in Base.metadata.sorted_tables}
    targets = sorted(all_tables - KEEP_TABLES)
    if not targets:
        logger.warning("nothing to wipe — KEEP_TABLES already covers everything")
        return 0
    # Single TRUNCATE ... CASCADE so FK ordering doesn't matter and we
    # don't have to delete in dependency order. RESTART IDENTITY also
    # resets autoincrement counters where present.
    quoted = ", ".join(f'"{t}"' for t in targets)
    stmt = f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"
    logger.info("TRUNCATE CASCADE on %d tables …", len(targets))
    await session.execute(text(stmt))
    return len(targets)


async def _ensure_system_org(session: AsyncSession) -> Organization:
    existing = (
        await session.execute(
            select(Organization).where(Organization.name == SYSTEM_ORG_NAME)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    org = Organization(name=SYSTEM_ORG_NAME, domains=[], keywords=[], industry="Other")
    session.add(org)
    await session.flush()
    logger.info("  · system org recreated (id=%s)", org.id)
    return org


def _verified_state(domain: str, now: datetime) -> dict:
    """Build a ``DomainVerificationState`` dict with status=verified.

    Mirrors the shape produced by ``src.core.domain_verification.check``
    so the existing predicate (``is_domain_verified``) accepts it
    without any code changes."""
    return {
        "domain": domain.lower(),
        "token": "evaluation-bypass-" + uuid.uuid4().hex[:16],
        "status": "verified",
        "requested_at": now.isoformat(),
        "verified_at": now.isoformat(),
        "expires_at": None,
        "last_checked_at": now.isoformat(),
        "last_error": None,
        "last_check_report": {
            "quorum_required": 2,
            "resolvers_consulted": 3,
            "matches": 3,
            "votes": [
                {"resolver": "1.1.1.1", "matched": True, "error": None},
                {"resolver": "8.8.8.8", "matched": True, "error": None},
                {"resolver": "9.9.9.9", "matched": True, "error": None},
            ],
        },
    }


def _default_breach_emails(domains: list[str]) -> list[str]:
    """Role-based addresses guaranteed to exist on a Tier-1 corporate
    domain. These are what HIBP returns hits on for any well-known
    organisation — they get scraped/leaked constantly. We don't try to
    seed personal exec emails; that crosses an OPSEC boundary the
    smoketest doesn't need."""
    locals_ = (
        "info",
        "support",
        "careers",
        "security",
        "press",
        "noreply",
        "hello",
        "contact",
    )
    return [f"{lp}@{d}" for d in domains for lp in locals_]


def _default_crawler_targets() -> list[dict]:
    """Public-source dark-web targets seeded into ``crawler_targets``.

    The production ``Scheduler`` reads this table per-org per-kind. An
    empty table = every dark-web crawler logs ``unconfigured`` and
    silently skips on every tick — same failure mode as Telegram had
    before today's catalog fix.

    Scope is deliberately conservative for a third-party eval target:
      - ``ransomware_leak_group`` only (passive victim-listing scrape,
        defensive-research use, no account creation, no posts).

    Onion URLs rotate fast — every group has been forced to redeploy
    after FBI/Europol takedowns, so ~half of these may be dead at any
    moment. The crawler fails over across mirrors and timeouts; the
    Feed Health surface shows which targets returned data. Operators
    refresh URLs via ``/admin → Crawler Targets``.

    Sources (URLs from public security-vendor reporting through 2025):
      Cisco Talos, Trellix, Mandiant, RansomLook, RansomWatch.
    """
    return [
        # ── Telegram: same channels we seeded into
        # ``settings.telegram_monitor_channels`` for the social
        # monitor — but routed through the Scheduler's
        # IngestionPipeline path so brand-matched messages flow into
        # /alerts and /iocs (the social monitor writes to a separate
        # findings table). Both paths are intentional: social monitor
        # surfaces fraud/impersonation, this path surfaces general
        # threat-intel mentions.
        {
            "kind": "telegram_channel",
            "identifier": "DarkfeedNews",
            "display_name": "Darkfeed News",
            "config": {},
        },
        {
            "kind": "telegram_channel",
            "identifier": "CyberSecurityNews",
            "display_name": "Cyber Security News",
            "config": {},
        },
        # ── Matrix rooms — public federated rooms hosted on
        # matrix.org. Universally safe defaults (no auth required,
        # public archives), so a fresh deployment isn't perpetually
        # "unconfigured" for the matrix_room crawler. Operator can
        # add tenant-specific rooms via /admin → Crawler Targets.
        {
            "kind": "matrix_room",
            "identifier": "#cybersecurity:matrix.org",
            "display_name": "Matrix · #cybersecurity",
            "config": {
                "homeserver": "https://matrix.org",
            },
        },
        {
            "kind": "matrix_room",
            "identifier": "#infosec:matrix.org",
            "display_name": "Matrix · #infosec",
            "config": {
                "homeserver": "https://matrix.org",
            },
        },
        # ── tor_forum / tor_marketplace / i2p_eepsite / lokinet_site /
        # stealer_marketplace / forum: NO defaults are seeded for
        # these crawler kinds. Reasons (preserved here so the next
        # operator who adds defaults understands the trade-off):
        #
        #  - tor_forum / tor_marketplace / stealer_marketplace —
        #    legally sensitive in many jurisdictions; the operator
        #    decides which sites their threat-intel programme
        #    covers. Defaults could imply approval we don't grant.
        #  - i2p_eepsite / lokinet_site — vanishingly few public
        #    threat-intel sources; what exists is operator-specific.
        #  - forum (clearnet) — would require seeding a list of
        #    third-party forums we have no consent to crawl.
        #
        # The Feed Health drawer's UNCONFIGURED status with the
        # "No active CrawlerTarget rows of kind=..." detail message
        # is the honest signal; the operator adds rows via the admin
        # Crawler Targets surface.
        # ── Ransomware leak sites (Tor onion URLs, passive scrape).
        {
            "kind": "ransomware_leak_group",
            "identifier": "lockbit",
            "display_name": "LockBit 3.0",
            "config": {
                "group_name": "lockbit",
                "onion_urls": [
                    "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion",
                    "http://lockbit3753ekiocyo5epmpy6klmejchjtzddoekjlnt6mu3qh4de2id.onion",
                    "http://lockbitsupportasa.onion",
                ],
                "max_pages": 3,
            },
        },
        {
            "kind": "ransomware_leak_group",
            "identifier": "akira",
            "display_name": "Akira",
            "config": {
                "group_name": "akira",
                "onion_urls": [
                    "http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion",
                ],
                "max_pages": 2,
            },
        },
        {
            "kind": "ransomware_leak_group",
            "identifier": "ransomhub",
            "display_name": "RansomHub",
            "config": {
                "group_name": "ransomhub",
                "onion_urls": [
                    "http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfo5lcaxbzwyd.onion",
                ],
                "max_pages": 2,
            },
        },
        {
            "kind": "ransomware_leak_group",
            "identifier": "play",
            "display_name": "Play / PlayCrypt",
            "config": {
                "group_name": "play",
                "onion_urls": [
                    "http://k7kg3jqxang3wh7hnmaiokchk7qoebupfgoik6rha6mjpzwupwtj25yd.onion",
                ],
                "max_pages": 2,
            },
        },
        {
            "kind": "ransomware_leak_group",
            "identifier": "blackbasta",
            "display_name": "Black Basta",
            "config": {
                "group_name": "blackbasta",
                "onion_urls": [
                    "http://stniiomyjliimcgkvdszvgen3eaaoz55hreqqx6o77yvmpwt7gktzwyd.onion",
                ],
                "max_pages": 2,
            },
        },
    ]


def _default_telegram_channels(country: str) -> list[str]:
    """Curated public-channel handles relevant to the target's region.

    Pulls from the existing ``telegram_collector.channels`` catalog so
    the smoketest exercises the same channels the production worker
    monitors — single source of truth for what's "in scope".

    Includes ``GLOBAL`` aggregators (English-language TI feeds)
    because regional fraud channels rotate through defunct/private
    cycles fast — without a baseline of always-reachable channels,
    the collector emits 0 messages and the operator can't tell if
    that's "no signal" or "everything we picked is dead"."""
    try:
        from src.integrations.telegram_collector.channels import (
            list_active_channels,
        )
    except ImportError:
        return []
    cc = country.upper()
    handles: list[str] = []
    for ch in list_active_channels():
        regions = [r.upper() for r in (ch.region_focus or [])]
        # Match "AE" against ["GCC"] and similar — GCC = AE+SA+QA+BH+OM+KW.
        # Always include GLOBAL aggregators; they catch broad mentions.
        if (
            "GLOBAL" in regions
            or cc in regions
            or (cc in {"AE", "SA", "QA", "BH", "OM", "KW"} and "GCC" in regions)
        ):
            handles.append(ch.handle)
    return handles


async def _create_target_org(
    session: AsyncSession,
    *,
    name: str,
    domains: list[str],
    industry: str,
    country: str,
    brand_terms: list[str],
    actor_email: str,
) -> Organization:
    from src.core.industry_defaults import default_tech_stack

    now = datetime.now(timezone.utc)
    domain_verification = {d: _verified_state(d, now) for d in domains}
    breach_check_emails = _default_breach_emails(domains)
    telegram_channels = _default_telegram_channels(country)
    org = Organization(
        name=name,
        domains=domains,
        keywords=brand_terms,
        industry=industry,
        # Seed the canonical tech stack for this industry so the
        # feed-triage LLM has something to correlate CVE / advisory
        # entries against on day one. Without this the agent
        # correctly refuses to fire alerts ("plausibility alone
        # does not justify a threat flag without asset
        # confirmation"), and the operator sees zero alerts from a
        # working pipeline. Operator can refine via PATCH later.
        tech_stack=default_tech_stack(industry),
        settings={
            "created_via": "load_real_target",
            "created_by": actor_email,
            "country": country,
            "domain_verification": domain_verification,
            "easm_active_probing_enabled": False,  # passive-only mode
            "evaluation_target": True,
            # Seeds for the harvester smoketest + production workers.
            # Operators can edit these later without touching code.
            "breach_check_emails": breach_check_emails,
            "telegram_monitor_channels": telegram_channels,
        },
    )
    session.add(org)
    await session.flush()
    logger.info("  · target org created: %s (id=%s)", name, org.id)
    logger.info("    domains: %s", ", ".join(domains))
    logger.info("    all marked verified=true (DNS TXT bypass for evaluation)")
    logger.info(
        "    breach-check emails: %d role accounts seeded (info@, support@, …)",
        len(breach_check_emails),
    )
    logger.info(
        "    telegram channels: %d curated handle(s) seeded for region %s",
        len(telegram_channels),
        country,
    )

    # Crawler targets — populates ``crawler_targets`` so the production
    # Scheduler has dark-web sites to dispatch against. Without these,
    # Feed Health renders every dark-web kind as ``unconfigured``.
    crawler_targets = _default_crawler_targets()
    for entry in crawler_targets:
        session.add(
            CrawlerTarget(
                organization_id=org.id,
                kind=entry["kind"],
                identifier=entry["identifier"],
                display_name=entry.get("display_name") or entry["identifier"],
                config=entry.get("config") or {},
                is_active=True,
            )
        )
    by_kind: dict[str, int] = {}
    for entry in crawler_targets:
        by_kind[entry["kind"]] = by_kind.get(entry["kind"], 0) + 1
    logger.info(
        "    crawler targets: %d row(s) — %s",
        len(crawler_targets),
        ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items())),
    )

    # Brand terms — these are what the leakage / dark-web / news /
    # impersonation matchers look for. Each becomes a row in brand_terms.
    # Brand names go in as kind="name"; the apex domain also gets a row
    # so domain-mention matchers fire on bare-text mentions like
    # "emiratesnbd.com" inside paste-site dumps.
    for term in brand_terms:
        session.add(
            BrandTerm(
                organization_id=org.id,
                kind=BrandTermKind.NAME.value,
                value=term,
                is_active=True,
                keywords=[],
            )
        )
    for d in domains:
        session.add(
            BrandTerm(
                organization_id=org.id,
                kind=BrandTermKind.APEX_DOMAIN.value,
                value=d,
                is_active=True,
                keywords=[],
            )
        )
    logger.info(
        "    brand terms: %d name(s) + %d apex domain(s)",
        len(brand_terms),
        len(domains),
    )

    # Asset registry — only apex domains. Subdomains/IPs are
    # deliberately omitted so EASM workers have no surface to actively
    # probe.
    for d in domains:
        session.add(
            Asset(
                organization_id=org.id,
                asset_type="domain",
                value=d,
                details={"is_root": True},
                criticality="crown_jewel",
                discovery_method="onboarding_wizard",
                discovered_at=now,
                is_active=True,
            )
        )
    logger.info("    assets: %d apex domain(s)", len(domains))
    return org


async def _schedule_passive_jobs(
    session: AsyncSession, org: Organization
) -> int:
    """Queue only the passive discovery jobs.

    ACTIVE (skipped) — make connections to target's infra:
        subdomain_enum, httpx_probe, port_scan
    PASSIVE (scheduled) — read public sources only:
        ct_log_backfill (Certificate Transparency),
        whois_refresh (registrar data),
        dns_refresh (public DNS resolvers)
    """
    PASSIVE = (
        DiscoveryJobKind.CT_LOG_BACKFILL.value,
        DiscoveryJobKind.WHOIS_REFRESH.value,
        DiscoveryJobKind.DNS_REFRESH.value,
    )
    asset_rows = (
        await session.execute(
            select(Asset).where(
                Asset.organization_id == org.id,
                Asset.asset_type == "domain",
            )
        )
    ).scalars().all()
    queued = 0
    for asset in asset_rows:
        for kind in PASSIVE:
            session.add(
                DiscoveryJob(
                    organization_id=org.id,
                    asset_id=asset.id,
                    kind=kind,
                    status=DiscoveryJobStatus.QUEUED.value,
                    target=asset.value,
                    parameters={},
                )
            )
            queued += 1
    logger.info("  · queued %d passive discovery jobs", queued)
    return queued


def _walkthrough_checklist(org_name: str, primary_domain: str) -> str:
    return f"""
================================================================
EVALUATION WALKTHROUGH — {org_name} ({primary_domain})
================================================================

Open the dashboard, scope to {org_name} via the header pill, and
walk through these screens. Note empty vs. populated for each.

1. /                       Dashboard — does the executive summary
                           reference {org_name}? Are KPIs sensible?

2. /alerts                 Did any feed-driven alerts auto-create?
                           (Empty is OK on first run — feeds need a
                           tick to scan against the new brand terms.)

3. /iocs                   IOC matches against {org_name}? Hit
                           "Re-scan" if your TAXII/MISP feeds are
                           wired.

4. /feeds                  Are crawlers + feeds running? Force-tick
                           the dark-web hunter and news harvesters.

5. /leakage                Any leaked credentials @ the verified
                           domains? Any paste-site hits?

6. /brand                  Brand terms tab should show the seeded
                           keywords. Logos tab — upload a logo for
                           image matching if you want.

7. /takedowns              Empty until phishing/lookalike detection
                           fires. Run /api/v1/brand-actions/scan.

8. /dmarc                  Should populate from public DNS read of
                           {primary_domain}.

9. /cases                  Open or create a case. Try the AI
                           co-pilot summary.

10. /reports               Generate an exec summary PDF — does it
                           look like something a CISO would forward?

11. /evidence              Upload a sample evidence blob; check
                           hash chain.

12. /taxii                 Does the TAXII server publish IOCs
                           specific to {org_name}?

13. /advisories            Any vendor advisories that match
                           {org_name}'s known tech stack?

14. Settings → Domains     Confirm {primary_domain} is shown as
                           "Verified" with the green shield.

NOTES
- EASM screens (active probing) are intentionally inactive — see
  ``easm_active_probing_enabled=false`` in this org's settings.
  We are NOT allowed to actively scan a third party's infra.
- Compare the dashboard's findings against an independent crawl
  (Firecrawl over BreachForums / paste sites / Telegram channels).
  Agreement = product works. Divergence = file a gap.

================================================================
"""


async def main_async(args: argparse.Namespace) -> int:
    if not args.yes:
        logger.error(
            "Refusing to wipe without --yes. This will TRUNCATE every data "
            "table in the database except auth, audit, and reference catalogues."
        )
        return 2

    domains = [args.domain.strip().lower()] + [
        d.strip().lower() for d in args.extra_domains.split(",") if d.strip()
    ]
    brand_terms = [b.strip() for b in args.brand_terms.split(",") if b.strip()]

    if _db.async_session_factory is None:
        await init_db()
    factory: async_sessionmaker[AsyncSession] = _db.async_session_factory  # type: ignore[assignment]

    async with factory() as session:
        wiped = await _wipe(session)
        await session.commit()
        logger.info("✓ wiped %d tables", wiped)

    # Single-tenant: the target org IS the system org. We don't seed
    # a separate "Argus" placeholder — ``get_system_org_id`` returns
    # the first-provisioned org, and that should be the eval target.
    # This also fixes the Scheduler dispatching to the wrong org.
    async with factory() as session:
        # Force the tenant cache to clear so the next ``get_system_org_id``
        # call re-resolves to the (newly created) eval org.
        from src.core.tenant import invalidate as _invalidate_tenant_cache
        _invalidate_tenant_cache()
        org = await _create_target_org(
            session,
            name=args.org,
            domains=domains,
            industry=args.industry,
            country=args.country,
            brand_terms=brand_terms,
            actor_email=args.actor_email,
        )
        await _schedule_passive_jobs(session, org)
        await session.commit()

    print(_walkthrough_checklist(args.org, domains[0]))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Wipe demo data and load a real-world evaluation target."
    )
    p.add_argument("--org", default="Emirates NBD")
    p.add_argument("--domain", default="emiratesnbd.com")
    p.add_argument(
        "--extra-domains",
        default="emiratesislamic.ae,liv.me",
        help="Comma-separated additional verified domains.",
    )
    p.add_argument("--industry", default="banking")
    p.add_argument("--country", default="AE")
    p.add_argument(
        "--brand-terms",
        default="Emirates NBD,ENBD,Liv,Emirates Islamic",
        help="Comma-separated keyword brand terms for matching.",
    )
    p.add_argument("--actor-email", default="evaluation@argus.local")
    p.add_argument("--yes", action="store_true", help="Confirm destructive wipe.")
    args = p.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
