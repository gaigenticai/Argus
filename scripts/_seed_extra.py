"""Comprehensive demo seed — populates every dashboard-visible table.

Imported by ``scripts/seed_demo.py`` after the core orgs / users / VIPs /
assets / raw_intel / alerts have been created. Everything in this module
is FK-correct: each row references existing parents from the maps the
caller hands over.

Quantities are tuned for "demo looks rich, queries stay fast" — every
list page should return at least a handful of rows and every detail
page reachable from a list page should resolve to a non-empty record.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _now_minus(days: int = 0, hours: int = 0, minutes: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days, hours=hours, minutes=minutes)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


async def _has_rows(session: AsyncSession, model) -> bool:
    """Cheap existence probe — used as a per-section idempotency guard."""
    res = await session.execute(select(model.id).limit(1))
    return res.scalar_one_or_none() is not None


async def _has_rows_for_org(session: AsyncSession, model, org_id) -> bool:
    res = await session.execute(
        select(model.id).where(model.organization_id == org_id).limit(1)
    )
    return res.scalar_one_or_none() is not None


async def seed_extra(
    session: AsyncSession,
    *,
    org_map: dict,
    alert_map: dict,
    user_map: dict,
    asset_map: dict,
    raw_intel_map: dict,
    vip_map: dict,
) -> dict:
    """Populate every secondary table with realistic demo data.

    Each section short-circuits via ``_has_rows`` so the function is
    safe to re-run, and safe to layer on top of ``scripts.seed.realistic``
    which also seeds many of these tables. The first time it runs on a
    fresh DB it fills every gap; subsequent invocations are no-ops.

    Returns a summary dict of counts (used by the caller for a final
    progress message). Sections that were skipped report ``0``.
    """
    # Late imports keep the seed_demo bootstrap fast and avoid importing
    # all model modules at process-start.
    from src.models.intel import (
        IOC,
        ThreatActor,
        ActorSighting,
        CrawlerSource,
        TriageRun,
        TriageFeedback,
        RetentionPolicy,
        WebhookEndpoint,
        WebhookDelivery,
        IntegrationConfig,
        VulnerabilityScan,
        Vulnerability,
    )
    from src.models.feeds import ThreatFeedEntry, ThreatLayer, GlobalThreatStatus
    from src.models.news import NewsFeed, NewsArticle, ArticleRelevance, Advisory
    from src.models.mitre import (
        MitreTactic,
        MitreTechnique,
        MitreMitigation,
        MitreSync,
        AttackTechniqueAttachment,
    )
    from src.models.intel_polish import (
        ActorPlaybook,
        HardeningRecommendation,
        CveRecord,
        IntelSync,
    )
    from src.models.cases import (
        Case,
        CaseFinding,
        CaseComment,
        CaseStateTransition,
        CaseState,
    )
    from src.models.case_copilot import CaseCopilotRun
    from src.models.investigations import Investigation
    from src.models.takedown import TakedownTicket
    from src.models.exposures import ExposureFinding
    from src.models.evidence import EvidenceBlob
    from src.models.easm import AssetChange, DiscoveryFinding, ChangeKind, FindingState
    from src.models.onboarding import (
        OnboardingSession,
        DiscoveryJob,
        DiscoveryJobKind,
        DiscoveryJobStatus,
        OnboardingState,
    )
    from src.models.live_probe import LiveProbe
    from src.models.ratings import SecurityRating, RatingFactor
    from src.models.tprm import (
        VendorScorecard,
        QuestionnaireTemplate,
        QuestionnaireInstance,
        QuestionnaireAnswer,
        VendorOnboardingWorkflow,
    )
    from src.models.sla import SlaPolicy, ExternalTicketBinding, SlaBreachEvent
    from src.models.brand import (
        BrandTerm,
        SuspectDomain,
        BrandTermKind,
        SuspectDomainState,
        SuspectDomainSource,
    )
    from src.models.logo import BrandLogo, LogoMatch
    from src.models.brand_actions import (
        BrandAction,
        BrandActionStatus,
        BrandActionRecommendation,
    )
    from src.models.social import (
        VipProfile,
        SocialAccount,
        ImpersonationFinding,
        MobileAppFinding,
        SocialPlatform,
        ImpersonationKind,
        ImpersonationState,
        MobileAppStore,
        MobileAppFindingState,
    )
    from src.models.leakage import (
        CreditCardBin,
        CardLeakageFinding,
        DlpPolicy,
        DlpFinding,
        CardScheme,
        CardType,
        LeakageState,
        DlpPolicyKind,
    )
    from src.models.fraud import FraudFinding, FraudKind, FraudState
    from src.models.dmarc import DmarcReport, DmarcReportRecord
    from src.models.admin import (
        AppSetting,
        AppSettingCategory,
        AppSettingType,
        CrawlerTarget,
        FeedHealth,
        SubsidiaryAllowlist,
    )
    from src.models.org_agent_settings import OrganizationAgentSettings
    from src.models.notifications import (
        NotificationChannel,
        NotificationRule,
        NotificationDelivery,
    )
    from src.models.threat import Asset, Report
    from src.models.threat_hunts import ThreatHuntRun
    from src.models.auth import APIKey

    counts: dict[str, int] = {}
    now = datetime.now(timezone.utc)

    # Top-level idempotency: ``crawler_sources`` is unique to this
    # module. If at least one row exists, an earlier run already
    # populated the long-tail fixtures and we'd just be racing unique
    # constraints on the per-org sections below — bail out.
    from src.models.intel import CrawlerSource as _CrawlerSourceMarker
    if await _has_rows(session, _CrawlerSourceMarker):
        return {"already_seeded": 1}

    # Make sure the social_platforms lookup table is populated and the
    # legacy ``social_platform`` Postgres enum exists. The enum was
    # dropped in migration c3d4e5f6a7b8 but SQLAlchemy still emits
    # ``$N::social_platform`` casts during insertmany because the model
    # still declares it as ``Enum(name="social_platform")``. Re-creating
    # the type alongside the lookup keeps both the cast and the FK happy.
    from sqlalchemy import text as _text
    await session.execute(
        _text(
            "DO $$ BEGIN "
            "  CREATE TYPE social_platform AS ENUM "
            "  ('twitter','x','facebook','instagram','linkedin','tiktok','youtube',"
            "   'telegram','discord','github','reddit','mastodon','bluesky');"
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        )
    )
    await session.execute(
        _text(
            "INSERT INTO social_platforms (id, name, label, scraper_module, is_active, created_at, updated_at) "
            "VALUES "
            "  (gen_random_uuid(),'twitter','Twitter','twitter',true,now(),now()),"
            "  (gen_random_uuid(),'x','X','x',true,now(),now()),"
            "  (gen_random_uuid(),'facebook','Facebook','facebook',true,now(),now()),"
            "  (gen_random_uuid(),'instagram','Instagram','instagram',true,now(),now()),"
            "  (gen_random_uuid(),'linkedin','LinkedIn','linkedin',true,now(),now()),"
            "  (gen_random_uuid(),'tiktok','TikTok','tiktok',true,now(),now()),"
            "  (gen_random_uuid(),'youtube','YouTube','youtube',true,now(),now()),"
            "  (gen_random_uuid(),'telegram','Telegram','telegram',true,now(),now()),"
            "  (gen_random_uuid(),'discord','Discord','discord',true,now(),now()),"
            "  (gen_random_uuid(),'github','GitHub','github',true,now(),now()),"
            "  (gen_random_uuid(),'reddit','Reddit','reddit',true,now(),now()),"
            "  (gen_random_uuid(),'mastodon','Mastodon','mastodon',true,now(),now()),"
            "  (gen_random_uuid(),'bluesky','Bluesky','bluesky',true,now(),now())"
            "ON CONFLICT (name) DO NOTHING"
        )
    )
    await session.flush()

    # Demo Bank is fully owned by ``scripts.seed.realistic._seed_demo_bank``
    # — when seed_extra runs alongside realistic.py we'd otherwise collide
    # on its brand_terms / vip_profiles / cases / etc. Filter it out of
    # the per-org loops so we only seed orgs that need filling.
    _DEMO_BANK_NAME = "Argus Demo Bank"
    orgs = [o for o in org_map.values() if o.name != _DEMO_BANK_NAME]
    if not orgs:
        orgs = list(org_map.values())  # standalone use (no Demo Bank)
    users = list(user_map.values())
    admin_user = user_map.get("admin")
    analyst_user = user_map.get("analyst")
    primary_org = orgs[0]

    # ------------------------------------------------------------------
    # 1. THREAT ACTORS (global) + ACTOR SIGHTINGS + IOCs
    # ------------------------------------------------------------------
    actors_data = [
        {
            "primary_alias": "darkvendor77",
            "aliases": ["DarkVendor", "DV77", "darkvend0r"],
            "description": "Prolific BreachForums vendor specialising in financial-sector employee credential dumps. Active since 2023, 47+ verified sales.",
            "forums_active": ["BreachForums", "XSS.is", "Exploit.in"],
            "languages": ["en", "ru"],
            "pgp_fingerprints": ["A1B2 C3D4 E5F6 7890 1234  5678 9ABC DEF0 1122 3344"],
            "known_ttps": ["T1078", "T1589", "T1212"],
            "risk_score": 88.0,
        },
        {
            "primary_alias": "LockBitSupp",
            "aliases": ["LockBit Support", "LB-Admin"],
            "description": "Public-facing operator for the LockBit 3.0 ransomware-as-a-service program. Manages affiliates, victim negotiations and the data leak site.",
            "forums_active": ["LockBit Blog", "XSS.is", "RAMP"],
            "languages": ["ru", "en"],
            "pgp_fingerprints": [],
            "known_ttps": ["T1486", "T1489", "T1567", "T1071", "T1059"],
            "risk_score": 95.0,
        },
        {
            "primary_alias": "ghost_data_vendor",
            "aliases": ["GhostData", "g_data_v"],
            "description": "Healthcare PHI broker operating across BreachForums and Dread. Specialises in EHR exfiltration from US hospital systems.",
            "forums_active": ["BreachForums", "Dread"],
            "languages": ["en"],
            "pgp_fingerprints": [],
            "known_ttps": ["T1078", "T1567", "T1213"],
            "risk_score": 79.0,
        },
        {
            "primary_alias": "silicon_ghost",
            "aliases": ["si_ghost", "silicon-g"],
            "description": "Hardware vulnerability researcher selling 0-days in semiconductor secure-boot chains. Attribution suspected to overlap with state-sponsored groups.",
            "forums_active": ["Exploit.in", "0day.today"],
            "languages": ["en", "zh"],
            "pgp_fingerprints": ["FFEE DDCC BBAA 9988  7766 5544 3322 1100 AABB CCDD"],
            "known_ttps": ["T1542", "T1195", "T1190"],
            "risk_score": 84.0,
        },
        {
            "primary_alias": "phish_master_x",
            "aliases": ["PhishMaster", "PhMx"],
            "description": "Telegram channel operator distributing phishing kits with SMS-OTP interception modules.",
            "forums_active": ["Telegram", "DarkMarket"],
            "languages": ["en", "es"],
            "pgp_fingerprints": [],
            "known_ttps": ["T1566", "T1111", "T1204"],
            "risk_score": 72.0,
        },
        {
            "primary_alias": "APT41",
            "aliases": ["Winnti", "Barium", "BRONZE ATLAS"],
            "description": "China-nexus state-sponsored group with dual cyber-espionage and financially-motivated activity. Targets healthcare, semiconductor, and gaming sectors.",
            "forums_active": ["XSS.is"],
            "languages": ["zh", "en"],
            "pgp_fingerprints": [],
            "known_ttps": ["T1190", "T1059.001", "T1505.003", "T1027", "T1071.001"],
            "risk_score": 92.0,
        },
        {
            "primary_alias": "inside_man_med",
            "aliases": ["insideman", "i_med"],
            "description": "Self-described insider broker selling ongoing VPN/AD admin access to healthcare networks. Subscription model; weekly proof-of-access screenshots.",
            "forums_active": ["DarkMarket", "AlphaBay V2"],
            "languages": ["en"],
            "pgp_fingerprints": [],
            "known_ttps": ["T1078.002", "T1133", "T1021"],
            "risk_score": 81.0,
        },
        {
            "primary_alias": "silicon_liberator",
            "aliases": ["si_liberator"],
            "description": "Anonymous 'hacktivist' operator running an I2P eepsite that publishes leaked semiconductor IP weekly.",
            "forums_active": ["I2P", "Telegram"],
            "languages": ["en"],
            "pgp_fingerprints": [],
            "known_ttps": ["T1213", "T1567"],
            "risk_score": 68.0,
        },
    ]
    actors = []
    if await _has_rows(session, ThreatActor):
        # Reuse existing actors so later sections (sightings, hunts) can
        # still link to them without inserting duplicates.
        actors = list(
            (await session.execute(select(ThreatActor))).scalars().all()
        )
        counts["threat_actors"] = 0
    else:
        for ad in actors_data:
            actor = ThreatActor(
                primary_alias=ad["primary_alias"],
                aliases=ad["aliases"],
                description=ad["description"],
                forums_active=ad["forums_active"],
                languages=ad["languages"],
                pgp_fingerprints=ad["pgp_fingerprints"],
                known_ttps=ad["known_ttps"],
                risk_score=ad["risk_score"],
                first_seen=_now_minus(days=random.randint(180, 720)),
                last_seen=_now_minus(days=random.randint(0, 5)),
                total_sightings=random.randint(3, 47),
                profile_data={"reputation": random.randint(20, 100), "first_observed_forum": ad["forums_active"][0]},
            )
            session.add(actor)
            actors.append(actor)
        await session.flush()
        counts["threat_actors"] = len(actors)

    # IOCs — some linked to actors, some standalone
    iocs_data = [
        ("domain", "merid1an-secure.com", 0.96, ["phishing", "typosquat"], 0),
        ("domain", "novamed-careers.com", 0.95, ["impersonation", "phishing"], None),
        ("domain", "eda-update.heliossemi-support.com", 0.93, ["apt41", "c2"], 5),
        ("domain", "synopsys-patch.com", 0.93, ["apt41", "c2"], 5),
        ("ipv4", "185.234.72.19", 0.88, ["phishing-infra", "flyservers"], 4),
        ("ipv4", "164.90.131.44", 0.85, ["phishing-infra", "digitalocean"], None),
        ("ipv4", "45.95.169.42", 0.82, ["c2", "ransomware"], 1),
        ("url", "http://breachforums.onion/thread/48291", 0.99, ["credential-leak"], 0),
        ("url", "http://lockbit.onion/blog/meridian-financial", 0.99, ["ransomware-leak"], 1),
        ("sha256", "5d41402abc4b2a76b9719d911017c592b8e6f6c2c95cf66f4cd0a4c7b7da4dd9", 0.91, ["malware", "shadowpad"], 5),
        ("sha256", "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef", 0.78, ["stealer", "redline"], 2),
        ("md5", "44d88612fea8a8f36de82e1278abb02f", 0.65, ["malware-sample"], None),
        ("email", "darkvendor77@protonmail.com", 0.85, ["actor-contact"], 0),
        ("btc_address", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", 0.72, ["ransom-payment"], 1),
        ("xmr_address", "44AFFq5kSiGBoZ4wMeqZBGz1XR8gC8oj3gM4iZNp1234567890aBcDeFg", 0.68, ["ransom-payment"], 1),
        ("cve", "CVE-2026-21543", 0.97, ["epic-mychart", "rce"], None),
        ("cve", "CVE-2025-41122", 0.92, ["helios-jtag"], 3),
        ("cve", "CVE-2026-1001", 0.95, ["sso-rce", "kev"], None),
        ("ipv6", "2001:db8::dead:beef", 0.55, ["scanner"], None),
        ("cidr", "185.234.72.0/24", 0.80, ["phishing-asn"], 4),
        ("asn", "AS208091", 0.74, ["bulletproof-hosting"], 4),
        ("filename", "ShadowPadLoader.dll", 0.86, ["apt41", "loader"], 5),
        ("user_agent", "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko", 0.45, ["scraper"], None),
        ("ja3", "e7d705a3286e19ea42f587b344ee6865", 0.70, ["c2-tls"], 5),
        ("mutex", "Global\\ShadowPad-v3-mutex", 0.88, ["malware-runtime"], 5),
        ("registry_key", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\sysupd", 0.75, ["persistence"], 5),
        ("domain", "lockbit-leak.onion", 0.98, ["ransomware-leak"], 1),
        ("ipv4", "203.0.113.42", 0.62, ["suspect-host"], None),
        ("domain", "argusdemo-secure.bank", 0.91, ["typosquat"], None),
        ("url", "https://novamed-careers.com/apply", 0.94, ["impersonation"], None),
    ]
    ioc_objs: list = []
    if await _has_rows(session, IOC):
        ioc_objs = list((await session.execute(select(IOC).limit(60))).scalars().all())
        counts["iocs"] = 0
    else:
        for ioc_type, value, conf, tags, actor_idx in iocs_data:
            ioc = IOC(
                ioc_type=ioc_type,
                value=value,
                confidence=conf,
                first_seen=_now_minus(days=random.randint(2, 60)),
                last_seen=_now_minus(hours=random.randint(0, 72)),
                sighting_count=random.randint(1, 12),
                tags=tags,
                context={"observed_via": random.choice(["crawler", "feed", "analyst"]), "geo": "US"},
                threat_actor_id=actors[actor_idx].id if actor_idx is not None and actor_idx < len(actors) else None,
            )
            session.add(ioc)
            ioc_objs.append(ioc)
        await session.flush()
        counts["iocs"] = len(ioc_objs)

    # Actor sightings — link actors to alerts so the actor detail page
    # shows real-looking timeline + linked alerts.
    alerts_list = list(alert_map.values())
    if await _has_rows(session, ActorSighting):
        counts["actor_sightings"] = 0
    else:
        sightings_count = 0
        for actor in actors:
            # 2-4 sightings per actor
            for _ in range(random.randint(2, 4)):
                alert = random.choice(alerts_list) if alerts_list else None
                session.add(
                    ActorSighting(
                        threat_actor_id=actor.id,
                        raw_intel_id=None,
                        alert_id=alert.id if alert else None,
                        source_platform=random.choice(actor.forums_active) if actor.forums_active else "BreachForums",
                        alias_used=random.choice([actor.primary_alias, *(actor.aliases or [])]) if actor.aliases else actor.primary_alias,
                        context={
                            "post_id": random.randint(10000, 99999),
                            "thread_title": "Latest credential dump" if "vendor" in actor.primary_alias else "Operational update",
                            "language": actor.languages[0] if actor.languages else "en",
                        },
                    )
                )
                sightings_count += 1
        await session.flush()
        counts["actor_sightings"] = sightings_count

    # ------------------------------------------------------------------
    # 2. CRAWLER SOURCES (global) — only seed_extra populates these
    # ------------------------------------------------------------------
    if await _has_rows(session, CrawlerSource):
        counts["crawler_sources"] = 0
    else:
        crawler_sources_data = [
            ("BreachForums", "tor_forum", "http://breachforums27l532gqj4r2pz3rhx2zudwz5tjuzqyxpvpazjbz.onion", "healthy", 8472),
            ("XSS.is", "underground_forum", "https://xss.is", "healthy", 5219),
            ("Exploit.in", "underground_forum", "https://exploit.in", "degraded", 3104),
            ("LockBit Leak Site", "ransomware_leak", "http://lockbitsupportasa.onion", "healthy", 1287),
            ("Dread", "tor_forum", "http://dread.onion", "blocked", 422),
            ("Russian Market", "stealer_market", "http://russianmarket.onion", "healthy", 12048),
            ("Genesis Market 2", "stealer_market", "http://genesis2.onion", "unreachable", 0),
            ("PhishKits", "telegram_channel", "https://t.me/phishkits", "healthy", 642),
            ("Helios Leaks", "i2p_eepsite", "http://helios-leaks.i2p", "healthy", 342),
            ("Doxbin Ops", "matrix_room", "matrix:r/doxbin-ops:matrix.org", "degraded", 187),
        ]
        for name, kind, url, health, items in crawler_sources_data:
            session.add(
                CrawlerSource(
                    name=name,
                    source_type=kind,
                    url=url,
                    language="en",
                    enabled=health != "unreachable",
                    priority=random.randint(10, 90),
                    crawl_interval_minutes=random.choice([15, 30, 60, 120]),
                    max_pages=random.choice([5, 10, 20]),
                    last_crawled_at=_now_minus(hours=random.randint(0, 24)) if health != "unreachable" else None,
                    last_success_at=_now_minus(hours=random.randint(0, 48)) if health == "healthy" else _now_minus(days=random.randint(2, 14)),
                    health_status=health,
                    consecutive_failures=0 if health == "healthy" else random.randint(1, 8),
                    total_items_collected=items,
                    notes=f"Production crawler for {name}",
                    selectors={"thread": ".thread-list .thread", "title": "h2.thread-title"},
                )
            )
        await session.flush()
        counts["crawler_sources"] = len(crawler_sources_data)

    # ------------------------------------------------------------------
    # 3. THREAT FEEDS / LAYERS / GLOBAL STATUS (global)
    # ------------------------------------------------------------------
    layers_data = [
        ("ransomware", "Ransomware Victims", "Skull", "#FF5630", ["lockbit", "blackcat", "play"], 3600, "Active ransomware victim postings worldwide"),
        ("c2", "C2 Servers", "ServerCog", "#FFAB00", ["feodotracker", "threatfox"], 1800, "Live malware command-and-control infrastructure"),
        ("phishing", "Phishing Campaigns", "Hook", "#00BBD9", ["phishtank", "openphish", "urlhaus"], 1200, "Active credential-harvesting campaigns"),
        ("malware", "Malware URLs", "Bug", "#B71D18", ["urlhaus", "abuseip"], 1800, "URLs hosting malware samples"),
        ("exploited_cves", "Exploited CVEs", "ShieldAlert", "#9C27B0", ["cisa-kev"], 86400, "Vulnerabilities in CISA's KEV catalog"),
        ("tor_exits", "Tor Exit Nodes", "EyeOff", "#607D8B", ["tor-bulk-exits"], 3600, "Active Tor exit relays"),
    ]
    if await _has_rows(session, ThreatLayer):
        counts["threat_layers"] = 0
    else:
        for name, display, icon, color, feeds, interval, desc in layers_data:
            session.add(
                ThreatLayer(
                    name=name,
                    display_name=display,
                    icon=icon,
                    color=color,
                    enabled=True,
                    feed_names=feeds,
                    refresh_interval_seconds=interval,
                    description=desc,
                    entry_count=random.randint(20, 200),
                )
            )
        await session.flush()
        counts["threat_layers"] = len(layers_data)

    # Global threat status singleton
    if await _has_rows(session, GlobalThreatStatus):
        counts["global_threat_status"] = 0
    else:
        session.add(
            GlobalThreatStatus(
                infocon_level="yellow",
                active_ransomware_groups=42,
                active_c2_servers=1287,
                active_phishing_campaigns=512,
                exploited_cves_count=68,
                tor_exit_nodes_count=1842,
                malware_urls_count=4291,
                malicious_ips_count=18203,
            )
        )
        counts["global_threat_status"] = 1

    # Threat feed entries — geo-distributed
    feed_entry_specs = [
        # ransomware victims
        ("lockbit", "ransomware", "victim", "acme-corp.com", "Acme Corp listed on LockBit DLS", "high", 0.92, 40.7128, -74.0060, "US", "New York"),
        ("lockbit", "ransomware", "victim", "tech-eu.de", "Tech EU on LockBit DLS — 14 day timer", "critical", 0.95, 52.5200, 13.4050, "DE", "Berlin"),
        ("blackcat", "ransomware", "victim", "shipping-jp.co.jp", "BlackCat lists Japanese shipping firm", "high", 0.88, 35.6762, 139.6503, "JP", "Tokyo"),
        ("play", "ransomware", "victim", "manufacturer.it", "Play group claims Italian manufacturer", "high", 0.87, 41.9028, 12.4964, "IT", "Rome"),
        # C2 servers
        ("feodotracker", "c2", "ip", "45.95.169.42", "Cobalt Strike beacon", "high", 0.91, 50.4501, 30.5234, "UA", "Kyiv"),
        ("feodotracker", "c2", "ip", "194.31.107.18", "Emotet C2", "high", 0.89, 55.7558, 37.6173, "RU", "Moscow"),
        ("threatfox", "c2", "domain", "secure-update-cdn.com", "ShadowPad C2 domain", "critical", 0.93, 22.3193, 114.1694, "HK", "Hong Kong"),
        # Phishing
        ("phishtank", "phishing", "url", "https://meridianfg-secure.com/login", "Meridian credential harvester", "critical", 0.96, 37.7749, -122.4194, "US", "San Francisco"),
        ("openphish", "phishing", "url", "https://novamed-careers.com/apply", "NovaMed careers impersonation", "high", 0.94, 42.3601, -71.0589, "US", "Boston"),
        ("urlhaus", "phishing", "url", "https://login-helios-portal.cn/", "Helios employee portal phish", "high", 0.86, 39.9042, 116.4074, "CN", "Beijing"),
        # Malware URLs
        ("urlhaus", "malware", "url", "http://malware-cdn.ru/dropper.exe", "AsyncRAT dropper", "high", 0.84, 59.9311, 30.3609, "RU", "Saint Petersburg"),
        ("urlhaus", "malware", "hash", "5d41402abc4b2a76b9719d911017c592b8e6f6c2c95cf66f4cd0a4c7b7da4dd9", "ShadowPad sample", "critical", 0.95, None, None, None, None),
        # Exploited CVEs
        ("cisa-kev", "exploited_cves", "cve", "CVE-2026-21543", "Epic MyChart RCE — actively exploited", "critical", 0.99, None, None, None, None),
        ("cisa-kev", "exploited_cves", "cve", "CVE-2026-1001", "SSO RCE — KEV addition", "critical", 0.99, None, None, None, None),
        # Tor exits
        ("tor-bulk-exits", "tor_exits", "ip", "199.249.230.84", "Tor exit relay", "low", 0.99, 51.5074, -0.1278, "GB", "London"),
        ("tor-bulk-exits", "tor_exits", "ip", "185.220.101.45", "Tor exit relay", "low", 0.99, 50.1109, 8.6821, "DE", "Frankfurt"),
    ]
    feed_entry_count = 0
    if await _has_rows(session, ThreatFeedEntry):
        counts["threat_feed_entries"] = 0
    else:
        for feed_name, layer, etype, value, label, sev, conf, lat, lng, cc, city in feed_entry_specs:
            session.add(
                ThreatFeedEntry(
                    feed_name=feed_name,
                    layer=layer,
                    entry_type=etype,
                    value=value,
                    label=label,
                    description=f"Detected via {feed_name}",
                    severity=sev,
                    confidence=conf,
                    latitude=lat,
                    longitude=lng,
                    country_code=cc,
                    city=city,
                    asn=f"AS{random.randint(1000, 65000)}" if cc else None,
                    feed_metadata={"source": feed_name, "first_observed": _now_minus(days=random.randint(0, 7)).isoformat()},
                    first_seen=_now_minus(days=random.randint(1, 14)),
                    last_seen=_now_minus(hours=random.randint(0, 24)),
                    expires_at=_now_minus(days=-30),  # +30 days
                )
            )
            feed_entry_count += 1
        await session.flush()
        counts["threat_feed_entries"] = feed_entry_count

    # ------------------------------------------------------------------
    # 4. CVEs + INTEL SYNCS + HARDENING + ACTOR PLAYBOOKS (global)
    # ------------------------------------------------------------------
    cves_data = [
        ("CVE-2026-21543", "Epic MyChart Patient Portal RCE", "Unauthenticated remote code execution in Epic MyChart FHIR R4 API endpoint allows arbitrary code execution as the application user.", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical", True, 0.94, 0.98),
        ("CVE-2026-1001", "Argus SSO Endpoint RCE", "Server-side template injection in legacy SSO endpoint enables full pre-auth RCE.", 9.6, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical", True, 0.91, 0.96),
        ("CVE-2025-41122", "Helios H5/H7 JTAG Debug Port Exposure", "JTAG debug interface left enabled in shipped silicon allows physical-access bypass of secure boot.", 7.1, "AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "high", False, 0.12, 0.42),
        ("CVE-2025-30432", "Cisco AnyConnect Privilege Escalation", "Local privilege escalation via insecure DLL loading.", 7.8, "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "high", True, 0.55, 0.81),
        ("CVE-2026-3318", "Atlassian Confluence SSRF", "Authenticated SSRF in Confluence webhook handler.", 6.5, "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", "medium", False, 0.18, 0.47),
        ("CVE-2025-9912", "Apache Tomcat RCE via deserialization", "Insecure deserialization in session manager.", 9.0, "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "critical", True, 0.88, 0.93),
    ]
    if await _has_rows(session, CveRecord):
        counts["cve_records"] = 0
    else:
        for cve_id, title, desc, score, vec, sev, kev, epss, epss_pct in cves_data:
            session.add(
                CveRecord(
                    cve_id=cve_id,
                    title=title,
                    description=desc,
                    cvss3_score=score,
                    cvss3_vector=vec,
                    cvss_severity=sev,
                    published_at=_now_minus(days=random.randint(7, 180)),
                    last_modified_at=_now_minus(days=random.randint(0, 7)),
                    cwe_ids=["CWE-78", "CWE-94"] if "RCE" in title else ["CWE-200"],
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                    cpes=["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"],
                    is_kev=kev,
                    kev_added_at=_now_minus(days=random.randint(7, 30)) if kev else None,
                    epss_score=epss,
                    epss_percentile=epss_pct,
                )
            )
        counts["cve_records"] = len(cves_data)

    # Intel syncs — show last few NVD/EPSS/KEV pulls
    if await _has_rows(session, IntelSync):
        counts["intel_syncs"] = 0
    else:
        for source in ("nvd", "epss", "kev"):
            for i in range(3):
                session.add(
                    IntelSync(
                        source=source,
                        source_url={
                            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            "epss": "https://api.first.org/data/v1/epss",
                            "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                        }[source],
                        rows_ingested=random.randint(50, 500),
                        rows_updated=random.randint(10, 100),
                        succeeded=i != 0 or source != "epss",  # one EPSS failure for demo
                        error_message=None if (i != 0 or source != "epss") else "rate limited (HTTP 429)",
                        triggered_by_user_id=admin_user.id if admin_user else None,
                    )
                )
        counts["intel_syncs"] = 9

    # Actor playbooks (global) — uniqueness on (organization_id, actor_alias)
    if await _has_rows(session, ActorPlaybook):
        counts["actor_playbooks"] = 0
    else:
        playbooks = [
            ("LockBit 3.0", "Ransomware-as-a-service active since June 2022.", ["LockBit", "LockBit Black"], ["finance", "manufacturing", "healthcare"], ["US", "EU", "JP"], ["T1486", "T1489", "T1071"], ["LockBit Locker", "StealBit"]),
            ("APT41", "China-nexus dual espionage/financial group.", ["Winnti", "Barium"], ["semiconductor", "healthcare", "gaming"], ["TW", "US", "KR"], ["T1190", "T1505.003", "T1027"], ["ShadowPad", "PlugX", "Winnti"]),
            ("FIN7", "Financially motivated, retail/hospitality focus.", ["Carbanak"], ["retail", "hospitality"], ["US", "EU"], ["T1566.001", "T1059.005"], ["Carbanak", "Tirion", "Domino"]),
            ("Lazarus", "DPRK state-sponsored — financial theft + espionage.", ["Hidden Cobra"], ["finance", "crypto", "defense"], ["KR", "US", "Global"], ["T1566", "T1071", "T1490"], ["AppleJeus", "Manuscrypt"]),
        ]
        for alias, desc, aliases, sectors, geos, ttps, malware in playbooks:
            session.add(
                ActorPlaybook(
                    organization_id=None,  # global
                    actor_alias=alias,
                    description=desc,
                    aliases=aliases,
                    targeted_sectors=sectors,
                    targeted_geos=geos,
                    attack_techniques=ttps,
                    associated_malware=malware,
                    infra_iocs=[f"c2-{i}.example.com" for i in range(3)],
                    references=["https://attack.mitre.org/groups/" + alias.replace(" ", "_")],
                    risk_score=random.uniform(60, 95),
                    last_observed_at=_now_minus(days=random.randint(0, 30)),
                )
            )
        counts["actor_playbooks"] = len(playbooks)

    # ------------------------------------------------------------------
    # 5. MITRE TACTICS / TECHNIQUES / MITIGATIONS / SYNCS (global)
    # ``scripts.seed.realistic._seed_mitre`` already populates the
    # canonical Enterprise subset. Skip if it has run.
    # ------------------------------------------------------------------
    _skip_mitre = await _has_rows(session, MitreTactic)
    tactics_data = [
        ("TA0001", "initial-access", "Initial Access"),
        ("TA0002", "execution", "Execution"),
        ("TA0003", "persistence", "Persistence"),
        ("TA0004", "privilege-escalation", "Privilege Escalation"),
        ("TA0005", "defense-evasion", "Defense Evasion"),
        ("TA0006", "credential-access", "Credential Access"),
        ("TA0007", "discovery", "Discovery"),
        ("TA0008", "lateral-movement", "Lateral Movement"),
        ("TA0009", "collection", "Collection"),
        ("TA0010", "exfiltration", "Exfiltration"),
        ("TA0040", "impact", "Impact"),
    ]
    if _skip_mitre:
        counts["mitre_tactics"] = 0
    else:
        for ext_id, short, name in tactics_data:
            session.add(
                MitreTactic(
                    matrix="enterprise",
                    external_id=ext_id,
                    short_name=short,
                    name=name,
                    description=f"The adversary is trying to {name.lower()}.",
                    url=f"https://attack.mitre.org/tactics/{ext_id}/",
                    sync_version="v15.1",
                    raw={"version": "15.1"},
                )
            )
        counts["mitre_tactics"] = len(tactics_data)

    techniques_data = [
        ("T1190", None, "Exploit Public-Facing Application", ["initial-access"], ["Linux", "Windows", "macOS"], ["Application Log"], False),
        ("T1566", None, "Phishing", ["initial-access"], ["Linux", "Windows", "macOS"], ["Application Log", "Network Traffic"], False),
        ("T1566.001", "T1566", "Spearphishing Attachment", ["initial-access"], ["Linux", "Windows", "macOS"], ["File"], True),
        ("T1059", None, "Command and Scripting Interpreter", ["execution"], ["Linux", "Windows", "macOS"], ["Process"], False),
        ("T1059.001", "T1059", "PowerShell", ["execution"], ["Windows"], ["Module", "Process"], True),
        ("T1078", None, "Valid Accounts", ["defense-evasion", "persistence", "privilege-escalation", "initial-access"], ["Linux", "Windows", "macOS"], ["Logon Session"], False),
        ("T1486", None, "Data Encrypted for Impact", ["impact"], ["Linux", "Windows", "macOS"], ["File", "Process"], False),
        ("T1505.003", "T1505", "Web Shell", ["persistence"], ["Linux", "Windows", "macOS"], ["File", "Process"], True),
        ("T1071.001", "T1071", "Web Protocols", ["command-and-control"], ["Linux", "Windows", "macOS"], ["Network Traffic"], True),
        ("T1027", None, "Obfuscated Files or Information", ["defense-evasion"], ["Linux", "Windows", "macOS"], ["File", "Module"], False),
        ("T1542", None, "Pre-OS Boot", ["defense-evasion", "persistence"], ["Linux", "Windows"], ["Drive"], False),
        ("T1195", None, "Supply Chain Compromise", ["initial-access"], ["Linux", "Windows", "macOS"], ["File"], False),
        ("T1567", None, "Exfiltration Over Web Service", ["exfiltration"], ["Linux", "Windows", "macOS"], ["Network Traffic"], False),
        ("T1212", None, "Exploitation for Credential Access", ["credential-access"], ["Linux", "Windows", "macOS"], ["Application Log"], False),
        ("T1133", None, "External Remote Services", ["initial-access", "persistence"], ["Linux", "Windows", "macOS"], ["Logon Session"], False),
    ]
    if _skip_mitre:
        counts["mitre_techniques"] = 0
    else:
        for ext_id, parent, name, tactics_, plats, ds, is_sub in techniques_data:
            session.add(
                MitreTechnique(
                    matrix="enterprise",
                    external_id=ext_id,
                    parent_external_id=parent,
                    is_subtechnique=is_sub,
                    name=name,
                    description=f"{name} — see ATT&CK for full description.",
                    tactics=tactics_,
                    platforms=plats,
                    data_sources=ds,
                    detection=f"Monitor {ds[0].lower()} sources for indicators of {name.lower()}.",
                    deprecated=False,
                    revoked=False,
                    url=f"https://attack.mitre.org/techniques/{ext_id.replace('.', '/')}/",
                    sync_version="v15.1",
                )
            )
        counts["mitre_techniques"] = len(techniques_data)

    mitigations_data = [
        ("M1041", "Encrypt Sensitive Information", "Protect data with strong encryption at rest and in transit."),
        ("M1049", "Antivirus/Antimalware", "Use signatures or heuristics to detect malicious software."),
        ("M1030", "Network Segmentation", "Architect networks to isolate critical systems."),
        ("M1032", "Multi-factor Authentication", "Require additional authentication factors."),
        ("M1051", "Update Software", "Patch and update software regularly."),
        ("M1017", "User Training", "Train users to recognize phishing and social engineering."),
    ]
    if _skip_mitre:
        counts["mitre_mitigations"] = 0
        counts["mitre_syncs"] = 0
    else:
        for ext_id, name, desc in mitigations_data:
            session.add(
                MitreMitigation(
                    matrix="enterprise",
                    external_id=ext_id,
                    name=name,
                    description=desc,
                    url=f"https://attack.mitre.org/mitigations/{ext_id}/",
                    sync_version="v15.1",
                )
            )
        counts["mitre_mitigations"] = len(mitigations_data)

        # MITRE syncs (audit history)
        for matrix, ok in (("enterprise", True), ("mobile", True), ("ics", True), ("enterprise", True)):
            session.add(
                MitreSync(
                    matrix=matrix,
                    source_url=f"https://github.com/mitre/cti/raw/master/{matrix}-attack/{matrix}-attack.json",
                    sync_version="v15.1",
                    tactics_count=11 if matrix == "enterprise" else 8,
                    techniques_count=204 if matrix == "enterprise" else 75,
                    subtechniques_count=415 if matrix == "enterprise" else 120,
                    mitigations_count=43 if matrix == "enterprise" else 12,
                    deprecated_count=18,
                    succeeded=ok,
                    triggered_by_user_id=admin_user.id if admin_user else None,
                )
            )
        counts["mitre_syncs"] = 4

    # Attack technique attachments — link some alerts to MITRE techniques per org
    attach_count = 0
    common_techs = ["T1190", "T1566", "T1078", "T1486", "T1505.003"]
    for org in orgs:
        org_alerts = [a for a in alerts_list if a.organization_id == org.id][:3]
        for alert in org_alerts:
            tech = random.choice(common_techs)
            session.add(
                AttackTechniqueAttachment(
                    organization_id=org.id,
                    entity_type="alert",
                    entity_id=alert.id,
                    matrix="enterprise",
                    technique_external_id=tech,
                    confidence=random.uniform(0.7, 1.0),
                    source="triage_agent",
                    note=f"Tagged automatically by triage agent on {alert.title[:40]}",
                    attached_by_user_id=analyst_user.id if analyst_user else None,
                )
            )
            attach_count += 1
    counts["attack_technique_attachments"] = attach_count

    # ------------------------------------------------------------------
    # 6. NEWS FEEDS / ARTICLES / RELEVANCE / ADVISORIES
    # ------------------------------------------------------------------
    feeds_data = [
        ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog/feed", "rss", ["cisa", "kev", "vulnerabilities"]),
        ("NCSC UK Threat Reports", "https://www.ncsc.gov.uk/api/1/services/v1/threat-reports.rss", "rss", ["ncsc", "uk"]),
        ("Microsoft Security Response Center", "https://msrc.microsoft.com/blog/feed", "rss", ["microsoft", "vendor"]),
        ("BleepingComputer Security", "https://www.bleepingcomputer.com/feed/", "rss", ["news"]),
        ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/", "rss", ["news"]),
    ]
    feeds: list = []
    if await _has_rows(session, NewsFeed):
        # realistic.py already seeded the canonical news feeds — reuse
        # them as parents for the article inserts below.
        feeds = list(
            (await session.execute(select(NewsFeed).limit(20))).scalars().all()
        )
        counts["news_feeds"] = 0
    else:
        for name, url, kind, tags in feeds_data:
            feed = NewsFeed(
                organization_id=None,
                name=name,
                url=url,
                kind=kind,
                enabled=True,
                last_fetched_at=_now_minus(hours=random.randint(1, 12)),
                last_status="ok",
                tags=tags,
            )
            session.add(feed)
            feeds.append(feed)
        await session.flush()
        counts["news_feeds"] = len(feeds)

    articles_data = [
        ("CISA adds CVE-2026-21543 to KEV catalog", "Epic MyChart RCE actively exploited in healthcare networks.", ["CVE-2026-21543"], ["epic", "healthcare", "kev"]),
        ("LockBit 3.0 affiliate operations expand into Asia", "Researchers track new affiliate cluster targeting Japanese and Korean victims.", [], ["lockbit", "ransomware", "apt"]),
        ("APT41 deploys updated ShadowPad in semiconductor sector", "Chinese-nexus group continues semiconductor IP theft campaigns.", [], ["apt41", "shadowpad"]),
        ("Critical RCE in Argus SSO endpoint (CVE-2026-1001)", "Server-side template injection enables pre-auth RCE.", ["CVE-2026-1001"], ["sso", "rce"]),
        ("FIN7 targets retail with new domino loader", "Financially-motivated group expands toolkit.", [], ["fin7", "loader"]),
        ("Lazarus group targets cryptocurrency exchanges via fake job listings", "DPRK actors use LinkedIn lures.", [], ["lazarus", "crypto"]),
        ("Confluence SSRF disclosed (CVE-2026-3318)", "Authenticated SSRF requires plugin auth.", ["CVE-2026-3318"], ["confluence", "atlassian"]),
        ("Cisco AnyConnect privilege escalation patched", "DLL hijacking flaw in client update mechanism.", ["CVE-2025-30432"], ["cisco", "vpn"]),
    ]
    articles: list = []
    if await _has_rows(session, NewsArticle) or not feeds:
        articles = list(
            (await session.execute(select(NewsArticle).limit(20))).scalars().all()
        )
        counts["news_articles"] = 0
    else:
        for i, (title, summary, cves, tags) in enumerate(articles_data):
            url = f"https://news.example/{i}/{title.lower().replace(' ', '-')[:60]}"
            article = NewsArticle(
                url_sha256=_sha256_hex(url),
                url=url,
                feed_id=random.choice(feeds).id,
                title=title,
                summary=summary,
                author=random.choice(["CISA Staff", "Brian Krebs", "MS-ISAC", "Lawrence Abrams"]),
                published_at=_now_minus(days=random.randint(0, 14)),
                fetched_at=_now_minus(hours=random.randint(0, 24)),
                cve_ids=cves,
                tags=tags,
            )
            session.add(article)
            articles.append(article)
        await session.flush()
        counts["news_articles"] = len(articles)

    # Article relevance per org — only seed_extra populates this.
    if await _has_rows(session, ArticleRelevance) or not articles:
        counts["news_article_relevance"] = 0
    else:
        rel_count = 0
        for org in orgs:
            for article in articles[:5]:
                session.add(
                    ArticleRelevance(
                        organization_id=org.id,
                        article_id=article.id,
                        relevance_score=random.uniform(0.4, 0.95),
                        matched_brand_terms=random.sample(org.keywords or ["argus"], k=min(2, len(org.keywords or ["argus"]))),
                        matched_cves=article.cve_ids,
                        matched_tech_keywords=["epic", "azure"] if "Health" in org.name else ["aws", "kubernetes"],
                        is_read=random.choice([False, False, True]),
                        bookmarked=random.choice([False, False, True]),
                    )
                )
                rel_count += 1
        counts["news_article_relevance"] = rel_count

    # Advisories — only insert per-org tenant advisories (realistic.py
    # already creates the global ``argus-2026-00N`` set). For each org,
    # check if our tenant advisory slug already exists before inserting.
    advisory_count = 0
    for i, org in enumerate(orgs):
        slug = f"{org.name.lower().replace(' ', '-')[:30]}-2026-{i+1:03}"
        existing = (await session.execute(
            select(Advisory.id).where(
                Advisory.organization_id == org.id, Advisory.slug == slug
            )
        )).scalar_one_or_none()
        if existing is not None:
            continue
        title = f"Tenant advisory for {org.name} — critical exposure remediation"
        session.add(
            Advisory(
                organization_id=org.id,
                slug=slug,
                title=title,
                body_markdown=f"# {title}\n\n## Summary\n\nReview your environment for affected systems and apply the recommended mitigations.\n\n## Affected\n\n- All production environments\n\n## Mitigation\n\n1. Apply vendor patch.\n2. Rotate exposed credentials.\n3. Monitor for indicators of compromise.\n",
                severity="high",
                state="published",
                tags=["security", "patch"],
                cve_ids=[],
                references=["https://www.cisa.gov/", "https://nvd.nist.gov/"],
                published_at=_now_minus(days=random.randint(1, 14)),
                author_user_id=admin_user.id if admin_user else None,
            )
        )
        advisory_count += 1
    counts["advisories"] = advisory_count

    # ------------------------------------------------------------------
    # 7. CASES + FINDINGS + COMMENTS + STATE TRANSITIONS + COPILOT
    # ------------------------------------------------------------------
    case_count = 0
    finding_count = 0
    comment_count = 0
    transition_count = 0
    copilot_count = 0
    for org in orgs:
        org_alerts = [a for a in alerts_list if a.organization_id == org.id]
        org_assets = asset_map.get(org.name, [])
        # Create 4-5 cases per org with mixed states
        case_specs = [
            ("Investigate credential leak — employee accounts on BreachForums", "critical", CaseState.IN_PROGRESS.value, ["credential-leak", "ir"]),
            ("Phishing campaign targeting customer portal", "high", CaseState.TRIAGED.value, ["phishing", "brand-abuse"]),
            ("Ransomware incident response — LockBit listing", "critical", CaseState.IN_PROGRESS.value, ["ransomware", "ir", "board-briefing"]),
            ("Typosquat domain takedown coordination", "high", CaseState.REMEDIATED.value, ["takedown", "phishing"]),
            ("Resolved: TLS configuration weakness on telehealth", "low", CaseState.CLOSED.value, ["compliance", "tls"]),
        ]
        for i, (title, sev, state, tags) in enumerate(case_specs):
            owner = analyst_user
            assignee = analyst_user
            asset = org_assets[i % len(org_assets)] if org_assets else None
            sla_due = _now_minus(hours=-random.randint(-48, 72)) if state not in (CaseState.CLOSED.value,) else None
            first_resp = _now_minus(hours=random.randint(1, 24)) if state != CaseState.OPEN.value else None
            closed_at = _now_minus(days=random.randint(1, 5)) if state == CaseState.CLOSED.value else None
            case = Case(
                organization_id=org.id,
                title=title,
                summary=f"{title} — analyst-led investigation tracking signals across multiple intel feeds.",
                severity=sev,
                state=state,
                owner_user_id=owner.id if owner else None,
                assignee_user_id=assignee.id if assignee else None,
                tags=tags,
                sla_due_at=sla_due,
                first_response_at=first_resp,
                closed_at=closed_at,
                closed_by_user_id=admin_user.id if (admin_user and closed_at) else None,
                close_reason="Remediated and verified — TLS config updated, scan confirms A+ grade." if state == CaseState.CLOSED.value else None,
                primary_asset_id=asset.id if asset else None,
                extra={"priority": "P0" if sev == "critical" else "P2", "external_ref": f"INC-{random.randint(1000, 9999)}"},
                legal_hold=False,
            )
            session.add(case)
            await session.flush()
            case_count += 1
            # Findings (link 1-2 alerts to each case)
            for alert in org_alerts[i : i + 2]:
                session.add(
                    CaseFinding(
                        case_id=case.id,
                        alert_id=alert.id,
                        is_primary=(alert == org_alerts[i] if i < len(org_alerts) else False),
                        linked_by_user_id=analyst_user.id if analyst_user else None,
                        link_reason="Triage agent associated this alert with the case based on entity overlap.",
                    )
                )
                finding_count += 1
            # Comments
            for j in range(random.randint(2, 4)):
                session.add(
                    CaseComment(
                        case_id=case.id,
                        author_user_id=random.choice([admin_user, analyst_user]).id,
                        body=random.choice([
                            "Engaging IR team. Initial scope assessment in progress.",
                            "Confirmed exposure — escalating to CISO. Will brief at next standup.",
                            "Forensics has artifacts. Awaiting timeline reconstruction.",
                            "Patch deployed to staging — production rollout scheduled for tonight's change window.",
                            "External counsel engaged. Drafting customer notification per state breach laws.",
                        ]),
                    )
                )
                comment_count += 1
            # State transitions (open → ... → current state)
            transitions_path = {
                CaseState.OPEN.value: [(None, "open")],
                CaseState.TRIAGED.value: [(None, "open"), ("open", "triaged")],
                CaseState.IN_PROGRESS.value: [(None, "open"), ("open", "triaged"), ("triaged", "in_progress")],
                CaseState.REMEDIATED.value: [(None, "open"), ("open", "triaged"), ("triaged", "in_progress"), ("in_progress", "remediated")],
                CaseState.VERIFIED.value: [(None, "open"), ("open", "triaged"), ("triaged", "in_progress"), ("in_progress", "remediated"), ("remediated", "verified")],
                CaseState.CLOSED.value: [(None, "open"), ("open", "triaged"), ("triaged", "in_progress"), ("in_progress", "remediated"), ("remediated", "verified"), ("verified", "closed")],
            }.get(state, [(None, state)])
            for k, (frm, to) in enumerate(transitions_path):
                session.add(
                    CaseStateTransition(
                        case_id=case.id,
                        from_state=frm,
                        to_state=to,
                        reason=f"Automatic transition by analyst" if frm else "Initial creation",
                        transitioned_by_user_id=(admin_user if k == 0 else analyst_user).id if admin_user and analyst_user else None,
                        transitioned_at=_now_minus(days=random.randint(0, 7), hours=random.randint(0, 23)),
                    )
                )
                transition_count += 1
            # Case copilot run
            if i < 3:
                session.add(
                    CaseCopilotRun(
                        organization_id=org.id,
                        case_id=case.id,
                        status="completed",
                        summary=f"Auto-generated investigation summary for case '{title[:60]}'. Highlights blast radius and recommended next steps.",
                        timeline_events=[
                            {"at": _now_minus(days=2).isoformat(), "source": "alert", "text": "Initial alert triggered."},
                            {"at": _now_minus(days=1).isoformat(), "source": "analyst", "text": "Analyst assigned and began triage."},
                            {"at": _now_minus(hours=3).isoformat(), "source": "system", "text": "Containment actions executed."},
                        ],
                        suggested_mitre_ids=["T1190", "T1566", "T1078"],
                        draft_next_steps=[
                            "Reset all exposed credentials.",
                            "Apply vendor patch in production.",
                            "Notify legal & compliance per disclosure rules.",
                            "Brief executive leadership at next standup.",
                        ],
                        similar_case_ids=[],
                        confidence=random.uniform(0.7, 0.95),
                        iterations=random.randint(3, 7),
                        model_id="glm-5",
                        duration_ms=random.randint(8000, 28000),
                        started_at=_now_minus(hours=4),
                        finished_at=_now_minus(hours=3, minutes=42),
                    )
                )
                copilot_count += 1
    await session.flush()
    counts["cases"] = case_count
    counts["case_findings"] = finding_count
    counts["case_comments"] = comment_count
    counts["case_state_transitions"] = transition_count
    counts["case_copilot_runs"] = copilot_count

    # ------------------------------------------------------------------
    # 8. INVESTIGATIONS (linked to alerts)
    # ------------------------------------------------------------------
    inv_count = 0
    for org in orgs:
        org_alerts = [a for a in alerts_list if a.organization_id == org.id][:4]
        for i, alert in enumerate(org_alerts):
            status = ["completed", "completed", "running", "queued"][i % 4]
            session.add(
                Investigation(
                    organization_id=org.id,
                    alert_id=alert.id,
                    case_id=None,
                    status=status,
                    final_assessment=f"After {random.randint(3, 8)} iterations, the agent confirms this represents an active threat with {random.choice(['high', 'medium-high'])} confidence. Recommend immediate containment steps." if status == "completed" else None,
                    severity_assessment=alert.severity if status == "completed" else None,
                    correlated_iocs=[ioc_objs[j].value for j in range(min(3, len(ioc_objs)))] if status == "completed" else [],
                    correlated_actors=[actors[0].primary_alias, actors[2].primary_alias] if status == "completed" else [],
                    recommended_actions=[
                        "Block listed IPs at perimeter",
                        "Reset exposed credentials",
                        "Engage IR retainer",
                        "Coordinate disclosure timeline with legal",
                    ] if status == "completed" else [],
                    iterations=random.randint(3, 8) if status == "completed" else random.randint(0, 2),
                    trace=[
                        {"iteration": k, "thought": "Analyzing entity overlap...", "tool": "search_iocs", "args": {"q": alert.title[:30]}, "result": "found 3 matches"}
                        for k in range(random.randint(3, 6))
                    ] if status == "completed" else None,
                    model_id="glm-5",
                    duration_ms=random.randint(6000, 24000) if status == "completed" else None,
                    started_at=_now_minus(hours=random.randint(0, 12)) if status != "queued" else None,
                    finished_at=_now_minus(hours=random.randint(0, 6)) if status == "completed" else None,
                )
            )
            inv_count += 1
    counts["investigations"] = inv_count

    # ------------------------------------------------------------------
    # 9. TAKEDOWN TICKETS
    # ------------------------------------------------------------------
    takedown_count = 0
    for org in orgs:
        targets = [
            ("merid1an-secure.com", "suspect_domain", "netcraft", "submitted"),
            ("novamed-careers.com", "suspect_domain", "phishlabs", "in_progress"),
            ("@meridian_ceo_fake", "impersonation", "internal_legal", "succeeded"),
            ("com.heliosfraud.app", "mobile_app", "manual", "rejected"),
            ("https://t.me/argusdemo_offers", "fraud", "group_ib", "acknowledged"),
        ]
        for ident, kind, partner, state in targets:
            submitted = _now_minus(days=random.randint(1, 14))
            ack = _now_minus(days=random.randint(0, 5)) if state in ("acknowledged", "in_progress", "succeeded", "rejected", "failed") else None
            ok = _now_minus(days=random.randint(0, 2)) if state == "succeeded" else None
            failed = _now_minus(days=random.randint(0, 3)) if state in ("rejected", "failed") else None
            session.add(
                TakedownTicket(
                    organization_id=org.id,
                    partner=partner,
                    state=state,
                    target_kind=kind,
                    target_identifier=ident,
                    partner_reference=f"NTC-{random.randint(100000, 999999)}",
                    partner_url=f"https://partner.{partner}.example/tickets/{random.randint(10000, 99999)}",
                    submitted_by_user_id=analyst_user.id if analyst_user else None,
                    submitted_at=submitted,
                    acknowledged_at=ack,
                    succeeded_at=ok,
                    failed_at=failed,
                    notes=f"Filed via {partner} dashboard with brand abuse evidence pack.",
                    raw={"evidence_count": random.randint(1, 5), "screenshots_attached": True},
                )
            )
            takedown_count += 1
    counts["takedown_tickets"] = takedown_count

    # ------------------------------------------------------------------
    # 10. EXPOSURE FINDINGS + DISCOVERY JOBS + DISCOVERY FINDINGS + ASSET CHANGES
    # ------------------------------------------------------------------
    exposure_count = 0
    discovery_job_count = 0
    discovery_finding_count = 0
    asset_change_count = 0
    for org in orgs:
        org_assets = asset_map.get(org.name, [])
        # Discovery jobs
        for i, asset in enumerate(org_assets[:5]):
            statuses = ["succeeded", "succeeded", "running", "queued", "failed"]
            status = statuses[i]
            session.add(
                DiscoveryJob(
                    organization_id=org.id,
                    asset_id=asset.id,
                    kind=random.choice([k.value for k in DiscoveryJobKind]),
                    status=status,
                    target=asset.value,
                    parameters={"depth": 2, "concurrency": 5},
                    started_at=_now_minus(hours=random.randint(1, 24)) if status != "queued" else None,
                    finished_at=_now_minus(hours=random.randint(0, 12)) if status in ("succeeded", "failed") else None,
                    result_summary={"new_findings": random.randint(0, 8), "raw_count": random.randint(5, 50)} if status == "succeeded" else None,
                    error_message="Connection timeout after 30s" if status == "failed" else None,
                    requested_by_user_id=admin_user.id if admin_user else None,
                )
            )
            discovery_job_count += 1
        # Exposures
        exposure_specs = [
            ("critical", "vulnerability", "open", "nuclei", "CVE-2026-1001-rce", "RCE in legacy SSO endpoint", 9.6, ["CVE-2026-1001"]),
            ("high", "weak_crypto", "acknowledged", "testssl", "tls10-enabled", "TLS 1.0 enabled — should be disabled", None, []),
            ("medium", "misconfiguration", "open", "nuclei", "missing-security-headers", "Missing CSP / HSTS headers", None, []),
            ("low", "version_disclosure", "open", "nuclei", "nginx-version-leak", "nginx version disclosed in Server header", None, []),
            ("info", "other", "fixed", "manual", "robots-disallow-references-admin", "robots.txt references /admin", None, []),
            ("high", "exposed_service", "open", "nmap", "redis-exposed", "Redis service exposed without authentication", None, []),
            ("critical", "default_credential", "open", "nuclei", "default-creds-jenkins", "Default Jenkins admin credentials accepted", 9.0, []),
        ]
        for sev, cat, state, src, rule, title, cvss, cves in exposure_specs:
            asset = random.choice(org_assets) if org_assets else None
            session.add(
                ExposureFinding(
                    organization_id=org.id,
                    asset_id=asset.id if asset else None,
                    discovery_job_id=None,
                    severity=sev,
                    category=cat,
                    state=state,
                    source=src,
                    rule_id=rule,
                    title=title,
                    description=f"Detected by {src}. {title}. Review and remediate per organization policy.",
                    target=asset.value if asset else f"https://example.{org.domains[0]}",
                    matched_at=_now_minus(days=random.randint(1, 30)),
                    last_seen_at=_now_minus(hours=random.randint(0, 24)),
                    occurrence_count=random.randint(1, 8),
                    cvss_score=cvss,
                    cve_ids=cves,
                    cwe_ids=["CWE-200"] if cat == "version_disclosure" else (["CWE-326"] if cat == "weak_crypto" else []),
                    references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves],
                    matcher_data={"matched_value": "version 1.18.0"},
                    state_changed_by_user_id=analyst_user.id if (analyst_user and state != "open") else None,
                    state_changed_at=_now_minus(days=random.randint(0, 5)) if state != "open" else None,
                    state_reason="Acknowledged — patch scheduled for next change window." if state == "acknowledged" else ("Verified fixed via re-scan" if state == "fixed" else None),
                )
            )
            exposure_count += 1
        # Discovery findings
        new_findings = [
            ("subdomain", f"staging.{org.domains[0]}", "subfinder"),
            ("subdomain", f"qa.{org.domains[0]}", "ct-log"),
            ("ip", "10.42.118.7", "amass"),
            ("service", f"{org.domains[0]}:8080", "httpx"),
        ]
        for atype, val, via in new_findings:
            parent = org_assets[0] if org_assets else None
            session.add(
                DiscoveryFinding(
                    organization_id=org.id,
                    parent_asset_id=parent.id if parent else None,
                    asset_type=atype,
                    value=val,
                    details={"first_seen": _now_minus(days=2).isoformat(), "discovered_via": via},
                    state=FindingState.NEW.value,
                    confidence=random.uniform(0.6, 0.95),
                    discovered_via=via,
                )
            )
            discovery_finding_count += 1
        # Asset changes
        change_specs = [
            (ChangeKind.PORT_OPENED.value, "high", "Port 8080 newly open on api.{}".format(org.domains[0])),
            (ChangeKind.TLS_EXPIRY_NEAR.value, "medium", "TLS cert expires in 21 days for {}".format(org.domains[0])),
            (ChangeKind.HTTP_TECH_CHANGED.value, "info", "Server header changed: nginx 1.18 → nginx 1.24"),
            (ChangeKind.DNS_A_CHANGED.value, "low", "DNS A record changed for mail.{}".format(org.domains[0])),
        ]
        for kind, sev, summary in change_specs:
            asset = random.choice(org_assets) if org_assets else None
            session.add(
                AssetChange(
                    organization_id=org.id,
                    asset_id=asset.id if asset else None,
                    kind=kind,
                    severity=sev,
                    summary=summary,
                    before={"value": "previous"},
                    after={"value": "current"},
                    detected_at=_now_minus(days=random.randint(1, 14)),
                )
            )
            asset_change_count += 1
    await session.flush()
    counts["exposure_findings"] = exposure_count
    counts["discovery_jobs"] = discovery_job_count
    counts["discovery_findings"] = discovery_finding_count
    counts["asset_changes"] = asset_change_count

    # ------------------------------------------------------------------
    # 11. EVIDENCE BLOBS (per org, multiple kinds)
    # ------------------------------------------------------------------
    evidence_count = 0
    for org in orgs:
        org_assets = asset_map.get(org.name, [])
        kinds = ["screenshot", "html_snapshot", "whois_history", "cert_chain", "takedown_proof_pdf", "leaked_document", "executive_photo", "brand_logo"]
        for i, kind in enumerate(kinds):
            sha = _sha256_hex(f"{org.name}-{kind}-{i}-{uuid.uuid4()}")
            asset = random.choice(org_assets) if org_assets else None
            session.add(
                EvidenceBlob(
                    organization_id=org.id,
                    asset_id=asset.id if asset else None,
                    sha256=sha,
                    size_bytes=random.randint(50_000, 5_000_000),
                    content_type={
                        "screenshot": "image/png",
                        "html_snapshot": "text/html",
                        "whois_history": "application/json",
                        "cert_chain": "application/x-pem-file",
                        "takedown_proof_pdf": "application/pdf",
                        "leaked_document": "application/zip",
                        "executive_photo": "image/jpeg",
                        "brand_logo": "image/png",
                    }[kind],
                    original_filename=f"{kind}-{i+1}.{kind.split('_')[-1] if 'pdf' in kind else 'bin'}",
                    kind=kind,
                    s3_bucket="argus-evidence-vault",
                    s3_key=f"{org.id}/{sha[:2]}/{sha}",
                    captured_at=_now_minus(days=random.randint(0, 30)),
                    captured_by_user_id=analyst_user.id if analyst_user else None,
                    capture_source=random.choice(["live_probe", "manual_upload", "logo_match", "dmarc_pull"]),
                    description=f"{kind.replace('_', ' ').title()} captured during routine monitoring of {org.name}.",
                    extra={"campaign": "weekly-sweep"},
                )
            )
            evidence_count += 1
    await session.flush()
    counts["evidence_blobs"] = evidence_count

    # ------------------------------------------------------------------
    # 12. BRAND TERMS + SUSPECT DOMAINS + LIVE PROBES + LOGOS + LOGO MATCHES + BRAND ACTIONS
    # ------------------------------------------------------------------
    brand_term_count = 0
    suspect_count = 0
    probe_count = 0
    logo_count = 0
    match_count = 0
    action_count = 0
    suspect_map = {}
    logo_map = {}
    for org in orgs:
        primary_kw = (org.keywords or [org.name.split()[0]])[0]
        primary_dom = (org.domains or ["example.com"])[0]
        first_word = org.name.split()[0]
        # Dedupe to satisfy uq_brand_term_org_kind_value
        name_terms = list({primary_kw, first_word})
        terms_specs = [(BrandTermKind.NAME.value, v) for v in name_terms]
        terms_specs += [
            (BrandTermKind.APEX_DOMAIN.value, primary_dom),
            (BrandTermKind.PRODUCT.value, f"{primary_kw} Cloud"),
        ]
        for kind, value in terms_specs:
            session.add(
                BrandTerm(
                    organization_id=org.id,
                    kind=kind,
                    value=value,
                    is_active=True,
                    keywords=[value, value.lower()],
                )
            )
            brand_term_count += 1
        # Suspect domains
        suspect_specs = [
            (f"{primary_kw.lower()}-secure.com", 0.91, "homoglyph", SuspectDomainState.OPEN.value, SuspectDomainSource.DNSTWIST.value),
            (f"{primary_kw.lower()}-login.net", 0.86, "addition", SuspectDomainState.CONFIRMED_PHISHING.value, SuspectDomainSource.CERTSTREAM.value),
            (f"{primary_kw.lower()}.support", 0.78, "tld-swap", SuspectDomainState.OPEN.value, SuspectDomainSource.WHOISDS.value),
            (f"{primary_kw.lower()}fg-secure.com", 0.94, "addition", SuspectDomainState.TAKEDOWN_REQUESTED.value, SuspectDomainSource.PHISHTANK.value),
            (f"{primary_kw.lower()}-cleared.com", 0.65, "addition", SuspectDomainState.CLEARED.value, SuspectDomainSource.MANUAL.value),
        ]
        org_suspects = []
        for dom, sim, perm, state, source in suspect_specs:
            sd = SuspectDomain(
                organization_id=org.id,
                domain=dom,
                matched_term_value=primary_kw,
                similarity=sim,
                permutation_kind=perm,
                is_resolvable=True,
                a_records=[f"185.234.72.{random.randint(10, 250)}"],
                mx_records=[],
                nameservers=["ns1.cloudflare.com", "ns2.cloudflare.com"],
                first_seen_at=_now_minus(days=random.randint(2, 14)),
                last_seen_at=_now_minus(hours=random.randint(0, 24)),
                state=state,
                source=source,
                state_reason=f"Set to {state} by analyst" if state != SuspectDomainState.OPEN.value else None,
                state_changed_by_user_id=analyst_user.id if (analyst_user and state != SuspectDomainState.OPEN.value) else None,
                state_changed_at=_now_minus(days=random.randint(0, 5)) if state != SuspectDomainState.OPEN.value else None,
                raw={"registrar": random.choice(["Namecheap", "GoDaddy", "Tucows"])},
            )
            session.add(sd)
            org_suspects.append(sd)
            suspect_count += 1
        await session.flush()
        suspect_map[org.name] = org_suspects
        # Live probes for the suspects
        for sd in org_suspects[:3]:
            html_sha = _sha256_hex(f"html-{sd.domain}")
            shot_sha = _sha256_hex(f"shot-{sd.domain}")
            session.add(
                LiveProbe(
                    organization_id=org.id,
                    suspect_domain_id=sd.id,
                    domain=sd.domain,
                    url=f"https://{sd.domain}/login",
                    fetched_at=_now_minus(hours=random.randint(0, 24)),
                    http_status=random.choice([200, 200, 200, 302, 404]),
                    final_url=f"https://{sd.domain}/login",
                    title=f"Login — {primary_kw}",
                    html_evidence_sha256=html_sha,
                    screenshot_evidence_sha256=shot_sha,
                    verdict=random.choice(["phishing", "suspicious", "benign", "phishing"]),
                    classifier_name="brand_clone_v2",
                    confidence=random.uniform(0.7, 0.97),
                    signals=["pixel_match", "asset_reuse", "credential_form"],
                    matched_brand_terms=[primary_kw],
                    rationale=f"Page contains pixel-perfect clone of {primary_kw} login portal with credential exfiltration JS.",
                )
            )
            probe_count += 1
        # Brand logos
        for label in [f"{primary_kw} primary", f"{primary_kw} mono"]:
            logo = BrandLogo(
                organization_id=org.id,
                label=label,
                description=f"{label} logo asset registered for abuse monitoring",
                width=512,
                height=128,
                image_evidence_sha256=_sha256_hex(f"logo-{org.name}-{label}"),
                phash_hex="a3" * 16,
                dhash_hex="b4" * 16,
                ahash_hex="c5" * 16,
                color_histogram=[0.1] * 16,
            )
            session.add(logo)
            logo_count += 1
        await session.flush()
        org_logos = (await session.execute(__import__("sqlalchemy").select(BrandLogo).where(BrandLogo.organization_id == org.id))).scalars().all()
        logo_map[org.name] = org_logos
        # Logo matches (on suspects)
        for sd in org_suspects[:2]:
            for logo in org_logos[:1]:
                session.add(
                    LogoMatch(
                        organization_id=org.id,
                        brand_logo_id=logo.id,
                        suspect_domain_id=sd.id,
                        live_probe_id=None,
                        candidate_image_sha256=_sha256_hex(f"candidate-{sd.domain}"),
                        phash_distance=random.randint(0, 8),
                        dhash_distance=random.randint(0, 8),
                        ahash_distance=random.randint(0, 8),
                        color_distance=random.uniform(0.0, 0.3),
                        similarity=random.uniform(0.78, 0.97),
                        verdict=random.choice(["likely_abuse", "possible_abuse"]),
                        matched_at=_now_minus(hours=random.randint(0, 48)),
                    )
                )
                match_count += 1
        # Brand actions
        for sd in org_suspects[:3]:
            session.add(
                BrandAction(
                    organization_id=org.id,
                    suspect_domain_id=sd.id,
                    status=BrandActionStatus.COMPLETED.value,
                    recommendation=random.choice([
                        BrandActionRecommendation.TAKEDOWN_NOW.value,
                        BrandActionRecommendation.TAKEDOWN_AFTER_REVIEW.value,
                        BrandActionRecommendation.MONITOR.value,
                    ]),
                    recommendation_reason=f"Live probe + logo match + WHOIS age <30d → {sd.domain} likely active phishing.",
                    confidence=random.uniform(0.7, 0.97),
                    risk_signals=["live_probe_phishing", "logo_match", "young_whois", "credential_form"],
                    suggested_partner=random.choice(["netcraft", "phishlabs", "group_ib"]),
                    iterations=random.randint(2, 5),
                    trace=[{"iteration": 0, "thought": "Triggered by new SuspectDomain", "tool": "live_probe", "result": "phishing"}],
                    model_id="glm-5",
                    duration_ms=random.randint(2000, 8000),
                    started_at=_now_minus(hours=random.randint(0, 12)),
                    finished_at=_now_minus(hours=random.randint(0, 6)),
                )
            )
            action_count += 1
    counts["brand_terms"] = brand_term_count
    counts["suspect_domains"] = suspect_count
    counts["live_probes"] = probe_count
    counts["brand_logos"] = logo_count
    counts["logo_matches"] = match_count
    counts["brand_actions"] = action_count

    # ------------------------------------------------------------------
    # 13. SOCIAL: VIP PROFILES, ACCOUNTS, IMPERSONATIONS, MOBILE APPS
    # ------------------------------------------------------------------
    vp_count = 0
    sa_count = 0
    imp_count = 0
    ma_count = 0
    vip_profile_map = {}
    for org in orgs:
        org_vips_legacy = vip_map.get(org.name, [])
        org_profiles = []
        for v in org_vips_legacy:
            vp = VipProfile(
                organization_id=org.id,
                full_name=v.name,
                title=v.title,
                aliases=[v.name.split()[0]],
                bio_keywords=[v.title.split()[0] if v.title else "executive", org.name.split()[0]],
                photo_evidence_sha256s=[_sha256_hex(f"photo-{v.name}")],
                photo_phashes=["d6" * 16],
            )
            session.add(vp)
            org_profiles.append(vp)
            vp_count += 1
        await session.flush()
        vip_profile_map[org.name] = org_profiles
        # Social accounts (official)
        for vp in org_profiles:
            for plat in [SocialPlatform.LINKEDIN.value, SocialPlatform.TWITTER.value]:
                session.add(
                    SocialAccount(
                        organization_id=org.id,
                        vip_profile_id=vp.id,
                        platform=plat,
                        handle=f"{vp.full_name.lower().replace(' ', '')}_{plat[:2]}",
                        profile_url=f"https://{plat}.com/in/{vp.full_name.lower().replace(' ', '-')}",
                        is_official=True,
                        keywords=[vp.full_name],
                    )
                )
                sa_count += 1
        # Impersonation findings
        for vp in org_profiles:
            for plat in [SocialPlatform.TWITTER.value, SocialPlatform.LINKEDIN.value, SocialPlatform.INSTAGRAM.value]:
                session.add(
                    ImpersonationFinding(
                        organization_id=org.id,
                        vip_profile_id=vp.id,
                        kind=ImpersonationKind.EXECUTIVE.value,
                        platform=plat,
                        candidate_handle=f"{vp.full_name.lower().replace(' ', '')}_real",
                        candidate_display_name=f"{vp.full_name} (Verified)",
                        candidate_bio=f"{vp.title} at {org.name}",
                        candidate_url=f"https://{plat}.com/{vp.full_name.lower().replace(' ', '_')}_real",
                        name_similarity=random.uniform(0.85, 0.99),
                        handle_similarity=random.uniform(0.6, 0.9),
                        bio_similarity=random.uniform(0.5, 0.85),
                        photo_similarity=random.uniform(0.7, 0.95),
                        aggregate_score=random.uniform(0.7, 0.95),
                        signals=["name_match", "photo_match", "title_match"],
                        state=random.choice([ImpersonationState.OPEN.value, ImpersonationState.CONFIRMED.value, ImpersonationState.TAKEDOWN_REQUESTED.value]),
                        detected_at=_now_minus(days=random.randint(0, 14)),
                    )
                )
                imp_count += 1
        # Mobile apps
        for store in [MobileAppStore.APPLE.value, MobileAppStore.GOOGLE_PLAY.value]:
            for n in range(2):
                primary_kw_lc = (org.keywords or [org.name.split()[0]])[0].lower()
                session.add(
                    MobileAppFinding(
                        organization_id=org.id,
                        store=store,
                        app_id=f"com.fake.{primary_kw_lc}-app{n}",
                        title=f"{primary_kw_lc.title()} Wallet (unofficial)",
                        publisher=f"FakeDev {n}",
                        description=f"Unofficial app impersonating {org.name}. Listed on {store}.",
                        url=f"https://apps.{store}.com/app/{primary_kw_lc}-{n}",
                        rating=random.uniform(2.0, 4.5),
                        install_estimate=random.choice(["1K-5K", "10K-50K", "50K-100K"]),
                        matched_term=primary_kw_lc,
                        matched_term_kind="name",
                        is_official_publisher=False,
                        state=random.choice([MobileAppFindingState.OPEN.value, MobileAppFindingState.CONFIRMED.value, MobileAppFindingState.TAKEDOWN_REQUESTED.value]),
                    )
                )
                ma_count += 1
    counts["vip_profiles"] = vp_count
    counts["social_accounts"] = sa_count
    counts["impersonation_findings"] = imp_count
    counts["mobile_app_findings"] = ma_count

    # ------------------------------------------------------------------
    # 14. LEAKAGE: BINS, CARD FINDINGS, DLP POLICIES + FINDINGS
    # ------------------------------------------------------------------
    bin_count = 0
    if await _has_rows(session, CreditCardBin):
        counts["credit_card_bins"] = 0
    else:
        bins_data = [
            ("411111", "Chase Bank", CardScheme.VISA.value, CardType.CREDIT.value, "US"),
            ("424242", "Stripe Test Bank", CardScheme.VISA.value, CardType.CREDIT.value, "US"),
            ("555555", "Bank of America", CardScheme.MASTERCARD.value, CardType.DEBIT.value, "US"),
            ("378282", "American Express", CardScheme.AMEX.value, CardType.CREDIT.value, "US"),
            ("601100", "Discover Bank", CardScheme.DISCOVER.value, CardType.CREDIT.value, "US"),
            ("491722", "Barclays UK", CardScheme.VISA.value, CardType.DEBIT.value, "GB"),
            ("352800", "JCB Japan", CardScheme.JCB.value, CardType.CREDIT.value, "JP"),
        ]
        for prefix, issuer, scheme, ctype, cc in bins_data:
            session.add(
                CreditCardBin(
                    organization_id=None,
                    bin_prefix=prefix,
                    issuer=issuer,
                    scheme=scheme,
                    card_type=ctype,
                    country_code=cc,
                )
            )
            bin_count += 1
        counts["credit_card_bins"] = bin_count

    card_count = 0
    dlp_pol_count = 0
    dlp_find_count = 0
    fraud_count = 0
    for org in orgs:
        for i in range(4):
            first6 = random.choice(["411111", "555555", "378282", "424242"])
            last4 = f"{random.randint(1000, 9999)}"
            pan = f"{first6}{random.randint(100000, 999999)}{last4}"
            session.add(
                CardLeakageFinding(
                    organization_id=org.id,
                    pan_first6=first6,
                    pan_last4=last4,
                    pan_sha256=_sha256_hex(pan + str(uuid.uuid4())),
                    issuer="Issuer Demo",
                    scheme="visa" if first6.startswith("4") else "mastercard",
                    card_type="credit",
                    source_url=f"https://pastebin.example/leak/{random.randint(10000, 99999)}",
                    source_kind="paste",
                    excerpt="…leaked dump from breach…",
                    expiry=f"{random.randint(1,12):02}/{random.randint(26, 30)}",
                    state=random.choice([LeakageState.OPEN.value, LeakageState.NOTIFIED.value, LeakageState.REISSUED.value]),
                    detected_at=_now_minus(days=random.randint(0, 21)),
                )
            )
            card_count += 1
        # DLP policies
        policy_specs = [
            ("Internal API key pattern", "regex", r"argusdemo_[A-Za-z0-9]{32}", "high"),
            ("Customer SSN pattern", "regex", r"\b\d{3}-\d{2}-\d{4}\b", "critical"),
            ("Project codename keyword", "keyword", "PROJECT_NIGHTHAWK", "medium"),
        ]
        org_policies = []
        for name, kind, pattern, sev in policy_specs:
            p = DlpPolicy(
                organization_id=org.id,
                name=name,
                kind=kind,
                pattern=pattern,
                severity=sev,
                description=f"{name} — {sev} severity DLP policy",
                enabled=True,
            )
            session.add(p)
            org_policies.append(p)
            dlp_pol_count += 1
        await session.flush()
        for policy in org_policies:
            for j in range(2):
                session.add(
                    DlpFinding(
                        organization_id=org.id,
                        policy_id=policy.id,
                        policy_name=policy.name,
                        severity=policy.severity,
                        source_url=f"https://github.example/repo/blob/main/.env-{j}",
                        source_kind="github",
                        matched_count=random.randint(1, 3),
                        matched_excerpts=[f"argusdemo_{'X'*32}", "REDACTED"],
                        state=random.choice([LeakageState.OPEN.value, LeakageState.NOTIFIED.value]),
                        detected_at=_now_minus(days=random.randint(0, 14)),
                    )
                )
                dlp_find_count += 1
        # Fraud findings
        for kind, channel in [(FraudKind.CRYPTO_GIVEAWAY.value, "telegram"), (FraudKind.JOB_OFFER.value, "social"), (FraudKind.INVESTMENT_SCAM.value, "website")]:
            primary_kw = (org.keywords or [org.name.split()[0]])[0]
            session.add(
                FraudFinding(
                    organization_id=org.id,
                    kind=kind,
                    channel=channel,
                    target_identifier=f"@fake_{primary_kw.lower()}_offer",
                    title=f"Fake {kind.replace('_', ' ')} impersonating {org.name}",
                    excerpt=f"Claim your reward by submitting your card to fake-{primary_kw.lower()}.example...",
                    matched_brand_terms=[primary_kw],
                    matched_keywords=["giveaway", "reward", "claim"],
                    score=random.uniform(0.7, 0.95),
                    rationale=f"High keyword density + brand mention + {channel} typical scam pattern.",
                    detected_at=_now_minus(days=random.randint(0, 7)),
                    state=random.choice([FraudState.OPEN.value, FraudState.CONFIRMED.value, FraudState.TAKEDOWN_REQUESTED.value]),
                )
            )
            fraud_count += 1
    counts["card_leakage_findings"] = card_count
    counts["dlp_policies"] = dlp_pol_count
    counts["dlp_findings"] = dlp_find_count
    counts["fraud_findings"] = fraud_count

    # ------------------------------------------------------------------
    # 15. DMARC REPORTS + RECORDS
    # ------------------------------------------------------------------
    dmarc_report_count = 0
    dmarc_record_count = 0
    for org in orgs:
        for i in range(3):
            dom = (org.domains or ["example.com"])[0]
            total = random.randint(10000, 50000)
            fail = random.randint(50, 800)
            quar = random.randint(10, 200)
            rej = random.randint(5, 100)
            passed = max(0, total - fail - quar - rej)
            report = DmarcReport(
                organization_id=org.id,
                kind="aggregate",
                domain=dom,
                org_name=random.choice(["google.com", "outlook.com", "yahoo.com"]),
                report_id=f"{random.randint(1000000000000, 9999999999999)}",
                date_begin=_now_minus(days=i * 7 + 7),
                date_end=_now_minus(days=i * 7),
                policy_p=random.choice(["none", "quarantine", "reject"]),
                policy_pct=100,
                total_messages=total,
                pass_count=passed,
                fail_count=fail,
                quarantine_count=quar,
                reject_count=rej,
                parsed={"version": "1.0"},
            )
            session.add(report)
            await session.flush()
            dmarc_report_count += 1
            for j in range(5):
                session.add(
                    DmarcReportRecord(
                        report_id=report.id,
                        organization_id=org.id,
                        domain=dom,
                        source_ip=f"198.51.100.{random.randint(1, 254)}",
                        count=random.randint(1, 5000),
                        disposition=random.choice(["none", "quarantine", "reject"]),
                        spf_result=random.choice(["pass", "fail", "neutral"]),
                        dkim_result=random.choice(["pass", "fail", "neutral"]),
                        spf_aligned=random.choice([True, False]),
                        dkim_aligned=random.choice([True, False]),
                        header_from=dom,
                        envelope_from=f"bounce@{dom}",
                    )
                )
                dmarc_record_count += 1
    counts["dmarc_reports"] = dmarc_report_count
    counts["dmarc_report_records"] = dmarc_record_count

    # ------------------------------------------------------------------
    # 16. ADMIN: APP SETTINGS + CRAWLER TARGETS + FEED HEALTH + ALLOWLIST
    # ------------------------------------------------------------------
    setting_count = 0
    target_count = 0
    feed_health_count = 0
    allowlist_count = 0
    org_agent_count = 0
    setting_specs = [
        ("rating.exposure_penalty.critical", AppSettingCategory.RATING.value, AppSettingType.FLOAT.value, 15.0, "Penalty per critical exposure"),
        ("rating.exposure_penalty.high", AppSettingCategory.RATING.value, AppSettingType.FLOAT.value, 8.0, "Penalty per high exposure"),
        ("brand.similarity_threshold", AppSettingCategory.BRAND.value, AppSettingType.FLOAT.value, 0.85, "Min similarity to flag domain"),
        ("auto_case.enabled", AppSettingCategory.AUTO_CASE.value, AppSettingType.BOOLEAN.value, True, "Auto-create cases for critical alerts"),
        ("crawler.max_concurrency", AppSettingCategory.CRAWLER.value, AppSettingType.INTEGER.value, 8, "Max concurrent crawler workers"),
        ("fraud.score_threshold", AppSettingCategory.FRAUD.value, AppSettingType.FLOAT.value, 0.7, "Min score to confirm fraud"),
    ]
    crawler_target_specs = [
        ("tor_forum", "http://breachforums27l532gqj4r2pz3rhx2zudwz5tjuzqyxpvpazjbz.onion", "BreachForums root"),
        ("telegram_channel", "@phishkits", "PhishKits Telegram channel"),
        ("ransomware_leak_group", "lockbit", "LockBit data leak site"),
        ("matrix_room", "!doxbin-ops:matrix.org", "Doxbin Operations room"),
    ]
    feed_specs = [
        ("phishtank", "ok", 1207),
        ("openphish", "ok", 412),
        ("urlhaus", "ok", 887),
        ("cisa-kev", "ok", 12),
        ("feodotracker", "rate_limited", 0),
        ("threatfox", "ok", 320),
    ]
    for org in orgs:
        for key, cat, vt, value, desc in setting_specs:
            session.add(
                AppSetting(
                    organization_id=org.id,
                    key=key,
                    category=cat,
                    value_type=vt,
                    value=value,
                    description=desc,
                )
            )
            setting_count += 1
        for kind, ident, name in crawler_target_specs:
            session.add(
                CrawlerTarget(
                    organization_id=org.id,
                    kind=kind,
                    identifier=ident,
                    display_name=name,
                    config={"interval_minutes": 30, "max_pages": 5},
                    is_active=True,
                    last_run_at=_now_minus(hours=random.randint(0, 12)),
                    last_run_status="ok",
                    last_run_summary={"items_collected": random.randint(5, 80)},
                    consecutive_failures=0,
                )
            )
            target_count += 1
        # Feed health rows — last 5 runs per feed
        for feed_name, status, ingested in feed_specs:
            for r in range(3):
                session.add(
                    FeedHealth(
                        organization_id=org.id,
                        feed_name=feed_name,
                        status=status if r == 0 else "ok",
                        detail=None if status == "ok" else "Rate limited (429)",
                        rows_ingested=ingested if r == 0 else random.randint(50, 1000),
                        duration_ms=random.randint(800, 4500),
                        observed_at=_now_minus(hours=r * 6),
                    )
                )
                feed_health_count += 1
        # Subsidiary allowlist
        for kind, value, note in [
            ("domain", f"subsidiary-{org.name.split()[0].lower()}.com", "Known subsidiary domain"),
            ("brand_name", f"{org.name.split()[0]} Holdings", "Parent company"),
            ("email_domain", f"{org.name.split()[0].lower()}-mail.com", "Marketing email domain"),
        ]:
            session.add(
                SubsidiaryAllowlist(
                    organization_id=org.id,
                    kind=kind,
                    value=value,
                    note=note,
                    added_by_user_id=admin_user.id if admin_user else None,
                )
            )
            allowlist_count += 1
        # Organization agent settings (1 per org)
        session.add(
            OrganizationAgentSettings(
                organization_id=org.id,
                investigation_enabled=True,
                brand_defender_enabled=True,
                case_copilot_enabled=True,
                threat_hunter_enabled=True,
                chain_investigation_to_hunt=True,
                auto_promote_critical=False,
                auto_takedown_high_confidence=False,
                threat_hunt_interval_seconds=86400,
            )
        )
        org_agent_count += 1
    counts["app_settings"] = setting_count
    counts["crawler_targets"] = target_count
    counts["feed_health"] = feed_health_count
    counts["subsidiary_allowlist"] = allowlist_count
    counts["organization_agent_settings"] = org_agent_count

    # ------------------------------------------------------------------
    # 17. NOTIFICATIONS: CHANNELS + RULES + DELIVERIES
    # ------------------------------------------------------------------
    chan_count = 0
    rule_count = 0
    delivery_count = 0
    for org in orgs:
        chans = []
        for kind, name, cfg in [
            ("slack", "SOC Slack", {"webhook_url": "https://hooks.slack.com/services/T01/B01/XXX", "channel": "#soc-alerts"}),
            ("email", "SOC Email", {"recipients": ["soc@example.com", "ciso@example.com"]}),
            ("pagerduty", "PagerDuty Critical", {"routing_key": "REDACTED", "service_id": "PXY1234"}),
        ]:
            c = NotificationChannel(
                organization_id=org.id,
                name=name,
                kind=kind,
                enabled=True,
                config=cfg,
                description=f"{kind.title()} channel for {org.name}",
                last_used_at=_now_minus(hours=random.randint(0, 24)),
                last_status="succeeded",
            )
            session.add(c)
            chans.append(c)
            chan_count += 1
        await session.flush()
        # Rules
        for name, evk, sev, dedup in [
            ("Critical alerts → Slack + PD", ["alert"], "critical", 300),
            ("SLA breach → Email", ["sla_breach"], "high", 600),
            ("Brand abuse → Slack", ["impersonation_detection", "phishing_detection"], "medium", 300),
        ]:
            session.add(
                NotificationRule(
                    organization_id=org.id,
                    name=name,
                    enabled=True,
                    event_kinds=evk,
                    min_severity=sev,
                    asset_criticalities=[],
                    asset_types=[],
                    tags_any=[],
                    channel_ids=[c.id for c in chans],
                    dedup_window_seconds=dedup,
                    description=name,
                )
            )
            rule_count += 1
        # Deliveries
        for i in range(8):
            chan = random.choice(chans)
            status = random.choice(["succeeded", "succeeded", "succeeded", "failed", "skipped"])
            session.add(
                NotificationDelivery(
                    organization_id=org.id,
                    rule_id=None,
                    channel_id=chan.id,
                    event_kind=random.choice(["alert", "sla_breach", "phishing_detection"]),
                    event_severity=random.choice(["critical", "high", "medium"]),
                    event_dedup_key=f"alert-{uuid.uuid4()}",
                    event_payload={"title": "Demo event", "summary": "Routed via notification engine"},
                    status=status,
                    attempts=1 if status != "failed" else 3,
                    latency_ms=random.randint(120, 2400),
                    response_status=200 if status == "succeeded" else 500,
                    response_body="OK" if status == "succeeded" else "Internal Server Error",
                    error_message=None if status != "failed" else "HTTP 500 from upstream",
                    delivered_at=_now_minus(hours=random.randint(0, 24)) if status == "succeeded" else None,
                )
            )
            delivery_count += 1
    counts["notification_channels"] = chan_count
    counts["notification_rules"] = rule_count
    counts["notification_deliveries"] = delivery_count

    # ------------------------------------------------------------------
    # 18. WEBHOOKS, INTEGRATIONS, RETENTION POLICIES, VULN SCANS, REPORTS
    # ------------------------------------------------------------------
    webhook_endpoints = []
    for org in orgs[:2]:
        for ep_type in ["slack", "siem", "generic"]:
            ep = WebhookEndpoint(
                name=f"{org.name} {ep_type.upper()}",
                url=f"https://hooks.example/{ep_type}/{uuid.uuid4()}",
                endpoint_type=ep_type,
                secret="whsec_" + uuid.uuid4().hex,
                headers={"X-Argus-Source": "demo"},
                enabled=True,
                min_severity="medium",
                organization_id=org.id,
                last_delivery_at=_now_minus(hours=random.randint(0, 12)),
                failure_count=0,
            )
            session.add(ep)
            webhook_endpoints.append(ep)
    await session.flush()
    counts["webhook_endpoints"] = len(webhook_endpoints)

    wd_count = 0
    for ep in webhook_endpoints:
        for _ in range(3):
            alert = random.choice(alerts_list)
            status = random.choice(["delivered", "delivered", "failed"])
            session.add(
                WebhookDelivery(
                    endpoint_id=ep.id,
                    alert_id=alert.id,
                    payload={"id": str(alert.id), "title": alert.title, "severity": alert.severity},
                    status=status,
                    status_code=200 if status == "delivered" else 503,
                    response_body="ok" if status == "delivered" else "service unavailable",
                    attempt_count=1 if status == "delivered" else 4,
                    delivered_at=_now_minus(hours=random.randint(0, 8)) if status == "delivered" else None,
                    next_retry_at=_now_minus(minutes=-15) if status != "delivered" else None,
                )
            )
            wd_count += 1
    counts["webhook_deliveries"] = wd_count

    # IntegrationConfig has unique tool_name; realistic.py also seeds
    # these. Insert only the tools that don't already exist.
    integrations_data = [
        ("OpenCTI", True, "https://opencti.example", "ok"),
        ("Wazuh", True, "https://wazuh.example", "ok"),
        ("Shuffle", False, "", "unconfigured"),
        ("MISP", True, "https://misp.example", "error"),
        ("Slack", True, "https://hooks.slack.com/services/T01/B02/XYZ", "ok"),
    ]
    integrations_added = 0
    for tool, enabled, url, health in integrations_data:
        existing = (await session.execute(
            select(IntegrationConfig.id).where(IntegrationConfig.tool_name == tool)
        )).scalar_one_or_none()
        if existing is not None:
            continue
        ic = IntegrationConfig(
            tool_name=tool,
            enabled=enabled,
            api_url=url,
            extra_settings={"sync_threat_feeds": True},
            health_status=health,
            last_sync_at=_now_minus(hours=random.randint(0, 24)) if enabled else None,
            last_error="HTTP 401: invalid API token" if health == "error" else None,
            sync_interval_seconds=3600,
        )
        if enabled:
            ic.set_api_key(f"demo-key-{tool.lower()}")
        session.add(ic)
        integrations_added += 1
    counts["integration_configs"] = integrations_added

    # Retention policies — global default may already exist; per-org rows
    # are unique on organization_id but not strictly enforced. Skip if
    # already populated.
    retention_added = 0
    has_global = (await session.execute(
        select(RetentionPolicy.id).where(RetentionPolicy.organization_id.is_(None))
    )).scalar_one_or_none() is not None
    if not has_global:
        session.add(
            RetentionPolicy(
                organization_id=None,
                raw_intel_days=90,
                alerts_days=365,
                audit_logs_days=730,
                iocs_days=365,
                redact_pii=True,
                auto_cleanup_enabled=True,
                last_cleanup_at=_now_minus(days=1),
            )
        )
        retention_added += 1
    for org in orgs:
        if await _has_rows_for_org(session, RetentionPolicy, org.id):
            continue
        session.add(
            RetentionPolicy(
                organization_id=org.id,
                raw_intel_days=120,
                alerts_days=540,
                audit_logs_days=2555,  # 7 years
                iocs_days=540,
                redact_pii=True,
                auto_cleanup_enabled=True,
                last_cleanup_at=_now_minus(days=2),
            )
        )
        retention_added += 1
    counts["retention_policies"] = retention_added

    # Vulnerability scans + vulnerabilities
    vuln_count = 0
    for org in orgs:
        for i in range(2):
            scan = VulnerabilityScan(
                organization_id=org.id,
                target=(org.domains or ["example.com"])[0],
                scanner="nuclei",
                status="completed",
                started_at=_now_minus(hours=24),
                completed_at=_now_minus(hours=22),
                findings_count=random.randint(2, 8),
                scan_output={"templates_run": 4500, "matches": 7},
            )
            session.add(scan)
            await session.flush()
            for j, (name, sev, cves) in enumerate([
                ("Apache Struts RCE (CVE-2023-50164)", "critical", ["CVE-2023-50164"]),
                ("Outdated jQuery 1.12.4", "low", []),
                ("Missing X-Frame-Options", "medium", []),
                ("HSTS not enabled", "medium", []),
            ]):
                session.add(
                    Vulnerability(
                        scan_id=scan.id,
                        organization_id=org.id,
                        template_id=f"nuclei-template-{j}",
                        name=name,
                        severity=sev,
                        description=f"{name} detected on target.",
                        url=f"https://{(org.domains or ['example.com'])[0]}/path/{j}",
                        matched_at=f"https://{(org.domains or ['example.com'])[0]}/path/{j}",
                        remediation="Upgrade vendor package and re-scan.",
                        cve_ids=cves,
                    )
                )
                vuln_count += 1
    counts["vulnerability_scans"] = len(orgs) * 2
    counts["vulnerabilities"] = vuln_count

    # Reports
    report_count = 0
    for org in orgs:
        for i in range(3):
            session.add(
                Report(
                    organization_id=org.id,
                    title=f"{org.name} — Q{(now.month - 1) // 3 + 1} Threat Intelligence Brief",
                    date_from=_now_minus(days=(i + 1) * 30),
                    date_to=_now_minus(days=i * 30),
                    file_path=f"argus-reports/{org.id}/q{(now.month - 1) // 3 + 1}-{i}.pdf",
                    summary="Quarterly executive summary of threat exposure, brand abuse, and remediation posture.",
                )
            )
            report_count += 1
    counts["reports"] = report_count

    # ------------------------------------------------------------------
    # 19. SLA POLICIES + BREACH EVENTS + EXTERNAL TICKET BINDINGS
    # ------------------------------------------------------------------
    sla_pol_count = 0
    sla_breach_count = 0
    ext_ticket_count = 0
    # Need to query existing cases
    from src.models.cases import Case
    from sqlalchemy import select as _select
    cases_by_org = {}
    for org in orgs:
        rows = (await session.execute(_select(Case).where(Case.organization_id == org.id))).scalars().all()
        cases_by_org[org.id] = rows

    for org in orgs:
        for sev, fr_min, rem_min in [("critical", 30, 240), ("high", 60, 480), ("medium", 240, 1440), ("low", 1440, 7200)]:
            session.add(
                SlaPolicy(
                    organization_id=org.id,
                    severity=sev,
                    first_response_minutes=fr_min,
                    remediation_minutes=rem_min,
                    description=f"Default {sev} SLA",
                )
            )
            sla_pol_count += 1
        for case in cases_by_org[org.id][:2]:
            session.add(
                SlaBreachEvent(
                    organization_id=org.id,
                    case_id=case.id,
                    kind="first_response",
                    severity=case.severity,
                    threshold_minutes=30 if case.severity == "critical" else 60,
                    detected_at=_now_minus(hours=random.randint(0, 12)),
                    notified=True,
                )
            )
            sla_breach_count += 1
            session.add(
                ExternalTicketBinding(
                    organization_id=org.id,
                    case_id=case.id,
                    system="jira",
                    external_id=f"SOC-{random.randint(1000, 9999)}-{uuid.uuid4().hex[:6]}",
                    external_url=f"https://argus.atlassian.net/browse/SOC-{random.randint(1000, 9999)}",
                    project_key="SOC",
                    status="In Progress",
                    last_synced_at=_now_minus(hours=random.randint(0, 6)),
                    last_sync_status="ok",
                )
            )
            ext_ticket_count += 1
    counts["sla_policies"] = sla_pol_count
    counts["sla_breach_events"] = sla_breach_count
    counts["external_ticket_bindings"] = ext_ticket_count

    # ------------------------------------------------------------------
    # 20. SECURITY RATINGS + RATING FACTORS (per org)
    # ------------------------------------------------------------------
    rating_count = 0
    factor_count = 0
    for org in orgs:
        score = random.uniform(58, 88)
        grade = "A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 60 else "D"))
        rating = SecurityRating(
            organization_id=org.id,
            scope="organization",
            rubric_version="v1",
            score=score,
            grade=grade,
            is_current=True,
            summary={
                "pillars": {"exposures": int(score * 0.9), "hygiene": int(score * 1.05), "governance": int(score * 0.95), "brand": int(score)},
                "delta_30d": round(random.uniform(-3.0, 4.0), 2),
            },
            computed_at=_now_minus(hours=2),
            inputs_hash=_sha256_hex(f"{org.id}-rating"),
        )
        session.add(rating)
        await session.flush()
        rating_count += 1
        for key, pillar, label, weight, raw, desc in [
            ("critical_exposures", "exposures", "Open Critical Exposures", 0.30, max(0, 100 - random.randint(0, 30)), "Open critical-severity exposure findings"),
            ("tls_hygiene", "hygiene", "TLS Configuration Hygiene", 0.20, random.uniform(70, 100), "TLS 1.2+/strong cipher coverage"),
            ("dmarc_enforcement", "governance", "DMARC Enforcement", 0.20, random.uniform(60, 100), "Domains with quarantine/reject DMARC"),
            ("brand_abuse", "brand", "Active Brand Abuse", 0.15, random.uniform(50, 95), "Open suspect domains and impersonations"),
            ("patch_velocity", "governance", "Patch Velocity", 0.15, random.uniform(50, 90), "Median time to remediation"),
        ]:
            session.add(
                RatingFactor(
                    rating_id=rating.id,
                    factor_key=key,
                    pillar=pillar,
                    label=label,
                    description=desc,
                    weight=weight,
                    raw_score=raw,
                    weighted_score=raw * weight,
                    evidence={"sample_size": random.randint(50, 500)},
                )
            )
            factor_count += 1
    counts["security_ratings"] = rating_count
    counts["rating_factors"] = factor_count

    # ------------------------------------------------------------------
    # 21. TPRM: VENDOR ASSETS + SCORECARDS + QUESTIONNAIRES + WORKFLOWS
    # ------------------------------------------------------------------
    vendor_assets = []
    for org in orgs:
        for vname in [f"{org.name.split()[0]} Cloud Provider", f"{org.name.split()[0]} Payroll SaaS", f"{org.name.split()[0]} Email Vendor"]:
            va = Asset(
                organization_id=org.id,
                asset_type="vendor",
                value=vname,
                details={"industry": "saas", "data_classification": "confidential"},
                criticality="high",
                tags=["tprm", "vendor"],
                discovery_method="manual",
                is_active=True,
                monitoring_enabled=True,
            )
            session.add(va)
            vendor_assets.append(va)
    await session.flush()
    counts["vendor_assets"] = len(vendor_assets)

    template_specs = [
        ("SIG Lite", "sig_lite", "Standardized Information Gathering — Lite questionnaire (50 questions)"),
        ("CAIQ v4", "caiq_v4", "Cloud Security Alliance Consensus Assessments Initiative Questionnaire"),
        ("Internal Vendor Risk", "custom", "Argus internal vendor risk template"),
    ]
    # Reuse existing templates if any (realistic.py seeds at least one).
    templates: list = []
    existing_templates = (await session.execute(
        select(QuestionnaireTemplate)
    )).scalars().all()
    existing_by_name = {t.name: t for t in existing_templates}
    new_templates = 0
    for name, kind, desc in template_specs:
        if name in existing_by_name:
            templates.append(existing_by_name[name])
            continue
        questions = [
            {"id": f"q{i}", "text": f"Question {i}: {desc}", "answer_kind": "yes_no", "weight": 1.0, "required": True}
            for i in range(1, 11)
        ]
        t = QuestionnaireTemplate(
            organization_id=None,
            name=name,
            kind=kind,
            description=desc,
            questions=questions,
            is_active=True,
        )
        session.add(t)
        templates.append(t)
        new_templates += 1
    # If we somehow ended up with no templates (no existing + nothing
    # added because list was empty), fall back to whatever exists.
    if not templates and existing_templates:
        templates = list(existing_templates)
    await session.flush()
    counts["questionnaire_templates"] = new_templates

    scorecard_count = 0
    instance_count = 0
    answer_count = 0
    workflow_count = 0
    for va in vendor_assets:
        score = random.uniform(50, 92)
        grade = "A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 60 else "D"))
        session.add(
            VendorScorecard(
                organization_id=va.organization_id,
                vendor_asset_id=va.id,
                score=score,
                grade=grade,
                is_current=True,
                pillar_scores={"security": score, "compliance": score - 5, "operational": score + 3},
                summary={"reviewed_at": _now_minus(days=2).isoformat()},
                computed_at=_now_minus(hours=4),
            )
        )
        scorecard_count += 1
        # Workflow + instance + answers
        template = random.choice(templates)
        instance = QuestionnaireInstance(
            organization_id=va.organization_id,
            template_id=template.id,
            vendor_asset_id=va.id,
            state=random.choice(["sent", "received", "reviewed"]),
            sent_at=_now_minus(days=14),
            received_at=_now_minus(days=4),
            due_at=_now_minus(days=-7),
            reviewed_at=_now_minus(days=2),
            reviewed_by_user_id=admin_user.id if admin_user else None,
            score=random.uniform(50, 95),
            notes="Initial review complete; minor follow-ups outstanding.",
        )
        session.add(instance)
        await session.flush()
        instance_count += 1
        for q in template.questions[:6]:
            session.add(
                QuestionnaireAnswer(
                    instance_id=instance.id,
                    question_id=q["id"],
                    answer_value=random.choice(["yes", "no", "n/a"]),
                    answer_score=random.uniform(0, 100),
                    notes="Vendor provided supporting evidence in attached SOC2.",
                )
            )
            answer_count += 1
        session.add(
            VendorOnboardingWorkflow(
                organization_id=va.organization_id,
                vendor_asset_id=va.id,
                stage=random.choice(["analyst_review", "approved", "questionnaire_received"]),
                questionnaire_instance_id=instance.id,
                notes="Awaiting final analyst sign-off.",
                decided_by_user_id=None,
            )
        )
        workflow_count += 1
    counts["vendor_scorecards"] = scorecard_count
    counts["questionnaire_instances"] = instance_count
    counts["questionnaire_answers"] = answer_count
    counts["vendor_onboarding_workflows"] = workflow_count

    # ------------------------------------------------------------------
    # 22. THREAT HUNT RUNS
    # ------------------------------------------------------------------
    hunt_count = 0
    for org in orgs:
        for actor in actors[:3]:
            session.add(
                ThreatHuntRun(
                    organization_id=org.id,
                    primary_actor_id=actor.id,
                    primary_actor_alias=actor.primary_alias,
                    status="completed",
                    summary=f"Hunt for {actor.primary_alias} activity in {org.name} environment surfaced 3 IOC overlaps and 2 weak signals.",
                    confidence=random.uniform(0.6, 0.92),
                    findings=[
                        {
                            "title": f"IOC overlap: {ioc_objs[0].value}",
                            "description": f"Asset query matched {actor.primary_alias} TTP profile.",
                            "relevance": "high",
                            "mitre_ids": actor.known_ttps[:2],
                            "ioc_ids": [str(ioc_objs[0].id)],
                            "recommended_action": "Hunt deeper across endpoint logs.",
                        }
                    ],
                    iterations=random.randint(3, 8),
                    trace=[{"iter": 1, "tool": "query_iocs", "result": "3 matches"}],
                    model_id="glm-5",
                    duration_ms=random.randint(8000, 25000),
                    started_at=_now_minus(hours=random.randint(1, 12)),
                    finished_at=_now_minus(hours=random.randint(0, 6)),
                )
            )
            hunt_count += 1
    counts["threat_hunt_runs"] = hunt_count

    # ------------------------------------------------------------------
    # 23. HARDENING RECOMMENDATIONS
    # ------------------------------------------------------------------
    hardening_count = 0
    from sqlalchemy import select as _select2
    from src.models.exposures import ExposureFinding as _EF
    for org in orgs:
        org_exps = (await session.execute(_select2(_EF).where(_EF.organization_id == org.id).limit(3))).scalars().all()
        for exp in org_exps:
            session.add(
                HardeningRecommendation(
                    organization_id=org.id,
                    exposure_finding_id=exp.id,
                    title=f"Remediate {exp.title}",
                    summary=f"Apply vendor patch and rotate impacted credentials. Validate via re-scan.",
                    cis_control_ids=["7.1", "7.2"],
                    d3fend_techniques=["D3-PA"],
                    nist_csf_subcats=["PR.IP-12"],
                    priority="high" if exp.severity in ("critical", "high") else "medium",
                    estimated_effort_hours=random.uniform(2, 16),
                    status="open",
                )
            )
            hardening_count += 1
    counts["hardening_recommendations"] = hardening_count

    # ------------------------------------------------------------------
    # 24. ONBOARDING SESSIONS + extra discovery jobs linked
    # ------------------------------------------------------------------
    ob_count = 0
    for org in orgs:
        for state, step in [("completed", 5), ("draft", 3), ("draft", 2)]:
            session.add(
                OnboardingSession(
                    organization_id=org.id,
                    started_by_user_id=admin_user.id if admin_user else None,
                    state=state,
                    current_step=step,
                    step_data={
                        "org": {"name": org.name, "industry": org.industry},
                        "infra": {"domains": org.domains, "tech_stack": org.tech_stack},
                        "people_brand": {"vips": ["David Chen", "Priya Sharma"], "brand_terms": org.keywords},
                        "vendors": {"vendor_count": 3},
                        "review": {"approved": state == "completed"},
                    },
                    completed_at=_now_minus(days=2) if state == "completed" else None,
                    notes="Auto-imported from sales handoff." if state == "completed" else "In-progress wizard session.",
                )
            )
            ob_count += 1
    counts["onboarding_sessions"] = ob_count

    # ------------------------------------------------------------------
    # 25. TRIAGE RUNS + TRIAGE FEEDBACK
    # ------------------------------------------------------------------
    triage_run_count = 0
    triage_fb_count = 0
    for trigger, hours, status in [("scheduled", 24, "completed"), ("manual", 48, "completed"), ("post_feed", 6, "completed"), ("scheduled", 24, "running")]:
        session.add(
            TriageRun(
                trigger=trigger,
                hours_window=hours,
                entries_processed=random.randint(20, 200),
                iocs_created=random.randint(5, 60),
                alerts_generated=random.randint(3, 20),
                duration_seconds=random.uniform(15.0, 240.0),
                status=status,
            )
        )
        triage_run_count += 1
    counts["triage_runs"] = triage_run_count

    # Triage feedback (need analyst user + alerts)
    if analyst_user:
        for alert in alerts_list[:6]:
            session.add(
                TriageFeedback(
                    alert_id=alert.id,
                    analyst_id=analyst_user.id,
                    original_category=alert.category,
                    original_severity=alert.severity,
                    original_confidence=alert.confidence,
                    corrected_category=None if random.random() > 0.3 else alert.category,
                    corrected_severity=None,
                    is_true_positive=random.random() > 0.2,
                    feedback_notes=random.choice(["Confirmed by analyst — leaving classification.", "Severity calibrated correctly.", "Lowered priority based on context."]),
                )
            )
            triage_fb_count += 1
    counts["triage_feedback"] = triage_fb_count

    # ------------------------------------------------------------------
    # 26. API KEYS (for users)
    # ------------------------------------------------------------------
    api_count = 0
    for u in users:
        for label in ("CLI", "CI/CD"):
            key_plain = uuid.uuid4().hex
            session.add(
                APIKey(
                    user_id=u.id,
                    name=f"{label} key",
                    key_hash=_sha256_hex(key_plain),
                    key_prefix=key_plain[:8],
                    is_active=True,
                    last_used_at=_now_minus(days=random.randint(0, 7)),
                    expires_at=_now_minus(days=-365),
                )
            )
            api_count += 1
    counts["api_keys"] = api_count

    await session.flush()
    return counts


__all__ = ["seed_extra"]
