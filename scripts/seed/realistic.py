"""Realistic seed — full demo dataset across every dashboard screen.

This composes the existing ``seed_demo.py`` (3 industry orgs + VIPs + assets
+ raw intel + alerts) and ``seed_full_demo.py`` (rich Argus Demo Bank with
brand/cases/SLA/exposures), then adds sections for the tables the legacy
seeds didn't cover: IOCs, threat actors, MITRE catalogue subset, TPRM
vendor scorecards, BIN registry, brand logos, notification channels,
webhook endpoints, news/advisories, sample reports, DMARC reports,
onboarding sessions, and an audit-log backfill.

Idempotent. Re-running on a populated DB is a no-op for each section
(checked via ``already_seeded``). To wipe and re-seed, pass ``--reset``.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from scripts.seed._common import (
    ago,
    already_seeded,
    deterministic_uuid,
    fake_md5,
    fake_sha256,
    logger,
    now,
    rng,
    section,
)
from src.core.auth import audit_log, hash_password


# ----------------------------------------------------------------------
# Top-level orchestration
# ----------------------------------------------------------------------


async def run(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    reset: bool = False,
    stress: bool = False,
) -> int:
    """Drive the full realistic seed.

    Each section opens its own short transaction so a partial failure
    doesn't leave the whole dataset unwritten.
    """
    if reset:
        async with session_factory() as session:
            await _wipe_demo_data(session)
            await session.commit()

    # Phase 0 — populate social_platforms lookup so any later phase
    # that inserts ImpersonationFinding / SocialAccount succeeds. The
    # table is seeded by migration c3d4e5f6a7b8 but TRUNCATE wipes it.
    async with session_factory() as session:
        await _seed_social_platforms_lookup(session)
        await session.commit()

    # Phase 1 — Argus Demo Bank goes first so ``get_system_org_id``
    # (which picks the row with the lowest ``created_at``) resolves to
    # it. We don't run ``_ensure_system_org`` here because that creates
    # the empty "Argus" placeholder org which would beat Demo Bank to
    # first-row and starve the dashboard. Demo Bank is the realistic
    # mode's tenant — it carries the brand suspects, cases, SLA, and
    # the agentic example runs.
    async with session_factory() as session:
        await _seed_demo_bank(session)

    # Phase 2 — admin user (no org dependency).
    from scripts.seed.minimal import _ensure_admin_user

    async with session_factory() as session:
        await _ensure_admin_user(session)
        await session.commit()

    # Phase 3 — industry demo orgs (Meridian/NovaMed/Helios) + their
    # alerts and assets. These show up in the multi-org pickers and
    # cross-org reports but the API surface scopes to Demo Bank.
    async with session_factory() as session:
        await _seed_industry_orgs(session)

    # Phase 4 — extras that fill the 14 RED screens
    async with session_factory() as session:
        await _seed_mitre(session)
        await _seed_threat_actors(session)
        await _seed_iocs(session)
        await session.commit()

    async with session_factory() as session:
        await _seed_tprm(session)
        await _seed_bin_registry(session)
        await _seed_brand_logos(session)
        await session.commit()

    async with session_factory() as session:
        await _seed_notifications(session)
        await _seed_webhooks(session)
        await _seed_integrations(session)
        await _seed_retention_policies(session)
        await session.commit()

    async with session_factory() as session:
        await _seed_news_and_advisories(session)
        await _seed_reports(session)
        await _seed_dmarc(session)
        await _seed_onboarding(session)
        await _seed_audit_backfill(session)
        await _seed_example_investigation(session)
        await _seed_example_brand_action(session)
        await _seed_example_copilot_run(session)
        await _seed_example_threat_hunt(session)
        await session.commit()

    # Phase 4b — augment Demo Bank with ~25 realistic alerts so the
    # dashboard KPI tiles (Total / Critical / New / Resolved) read as
    # a live install instead of "2 / 1 / 2 / 0".
    async with session_factory() as session:
        await _augment_demo_bank_phase(session)
        await session.commit()

    # Phase 5 — comprehensive seed_extra fills the long tail that the
    # phases above don't cover (per-industry-org cases, evidence,
    # exposures, brand abuse, dlp, fraud, vulnerability scans, ratings,
    # threat hunts, hardening recommendations, app settings, etc.).
    # seed_extra is internally idempotent on global tables and filters
    # Demo Bank out of its per-org loops to avoid colliding with
    # _seed_demo_bank.
    async with session_factory() as session:
        await _seed_extra_phase(session)
        await session.commit()

    # Phase 6 — Compliance Evidence Pack catalog (P1 #1.3). Seeds the
    # 12 framework definitions + their reachable controls + signal
    # mappings so the Compliance UI is populated immediately and a
    # fresh ``POST /compliance/exports`` produces a non-empty pack
    # against the demo alerts that already exist by this point in the
    # pipeline.
    async with session_factory() as session:
        from src.compliance.catalog import seed_compliance_catalog
        await seed_compliance_catalog(session)
        await session.commit()

    # Phase 7 — Iran-nexus APT pack (P1 #1.4). Curated APT33 / APT34 /
    # APT35 / MuddyWater / DEV-0270 / Cyber Av3ngers profiles with hand-
    # tagged MITRE ATT&CK TTPs. New alerts that link to these actors via
    # ``ActorSighting`` get their TTPs auto-attached via the hook in
    # ``src/enrichment/actor_tracker.py``.
    async with session_factory() as session:
        from src.intel.iran_apt_pack import seed_iran_apt_pack
        await seed_iran_apt_pack(session)
        await session.commit()

    logger.info("realistic seed complete (stress mode=%s)" % stress)
    return 0


@section("social_platforms lookup (twitter/linkedin/etc.)")
async def _seed_social_platforms_lookup(session: AsyncSession) -> None:
    """Re-create the social_platform Postgres enum and the
    social_platforms lookup table data. The migration c3d4e5f6a7b8
    drops the legacy enum and seeds the lookup table; a TRUNCATE on a
    dev database wipes the lookup. We re-insert via raw SQL so the
    foreign keys on ``social_accounts.platform`` and
    ``impersonation_findings.platform`` resolve."""
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


@section("Demo Bank realistic alert volume (full severity × status mix)")
async def _augment_demo_bank_phase(session: AsyncSession) -> None:
    from scripts._augment_demo_bank_alerts import augment_demo_bank_alerts

    added = await augment_demo_bank_alerts(session)
    if added:
        logger.info(f"    ↳ inserted {added} Demo Bank alerts")
    else:
        logger.info("    ↳ Demo Bank already has enough alerts; skipping")


@section("comprehensive seed_extra (long-tail per-industry-org fixtures)")
async def _seed_extra_phase(session: AsyncSession) -> None:
    """Run scripts/_seed_extra.seed_extra against the realistic dataset.

    seed_extra was originally written as the back-half of
    ``scripts/seed_demo.py`` and expects ``org_map`` / ``user_map`` /
    ``alert_map`` / ``asset_map`` / ``vip_map`` / ``raw_intel_map``
    to be handed in. Since realistic.py runs inside its own
    transactional sessions, rebuild those maps from the database so
    seed_extra can FK-link new rows correctly.
    """
    from src.models.threat import Alert, Asset, Organization, RawIntel, VIPTarget
    from src.models.auth import User
    from scripts._seed_extra import seed_extra

    orgs = (await session.execute(select(Organization))).scalars().all()
    users = (await session.execute(select(User))).scalars().all()
    alerts = (await session.execute(select(Alert))).scalars().all()
    raws = (await session.execute(select(RawIntel))).scalars().all()
    assets = (await session.execute(select(Asset))).scalars().all()
    vips = (await session.execute(select(VIPTarget))).scalars().all()

    org_map = {o.name: o for o in orgs}
    user_map: dict[str, User] = {}
    for u in users:
        user_map[u.username] = u
    # seed_extra reaches for ``user_map["admin"]`` / ``user_map["analyst"]``
    # by convention. realistic.py and minimal.py use different usernames
    # ("demo-admin", first-email-localpart, etc.) — alias the first
    # admin / analyst we find under the canonical keys so seed_extra
    # finds them.
    if "admin" not in user_map:
        admin = next((u for u in users if u.role == "admin"), None) or (users[0] if users else None)
        if admin is not None:
            user_map["admin"] = admin
    if "analyst" not in user_map:
        analyst = next((u for u in users if u.role == "analyst"), None) or user_map.get("admin")
        if analyst is not None:
            user_map["analyst"] = analyst
    alert_map = {a.title: a for a in alerts}
    raw_map = {r.title or str(r.id): r for r in raws}
    asset_map: dict[str, list] = {}
    for a in assets:
        org_name = next((n for n, o in org_map.items() if o.id == a.organization_id), None)
        if org_name is None:
            continue
        asset_map.setdefault(org_name, []).append(a)
    vip_map: dict[str, list] = {}
    for v in vips:
        org_name = next((n for n, o in org_map.items() if o.id == v.organization_id), None)
        if org_name is None:
            continue
        vip_map.setdefault(org_name, []).append(v)

    extra_counts = await seed_extra(
        session,
        org_map=org_map,
        alert_map=alert_map,
        user_map=user_map,
        asset_map=asset_map,
        raw_intel_map=raw_map,
        vip_map=vip_map,
    )
    nonzero = {k: v for k, v in extra_counts.items() if v}
    if nonzero:
        logger.info(f"    ↳ seed_extra inserted: {nonzero}")
    else:
        logger.info("    ↳ seed_extra: nothing to do (already populated)")


# ----------------------------------------------------------------------
# Phase 2 — Industry orgs (reuses data dicts from legacy seed_demo.py)
# ----------------------------------------------------------------------


@section("industry orgs (Meridian / NovaMed / Helios)")
async def _seed_industry_orgs(session: AsyncSession) -> None:
    from src.models.threat import (
        Alert,
        Asset,
        Organization,
        RawIntel,
        VIPTarget,
    )
    from scripts.seed_demo import ORGS, VIPS, ASSETS, RAW_INTEL, ALERTS_DATA

    if await already_seeded(
        session, Organization, where=Organization.name == ORGS[0]["name"]
    ):
        logger.info("    ↳ industry orgs already exist; skipping")
        return

    org_map: dict[str, Organization] = {}
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

    for org_name, vips in VIPS.items():
        org = org_map[org_name]
        for v in vips:
            session.add(
                VIPTarget(
                    organization_id=org.id,
                    name=v["name"],
                    title=v["title"],
                    emails=v["emails"],
                    usernames=v["usernames"],
                    phone_numbers=v["phone_numbers"],
                )
            )
    # The legacy seed_demo data uses ``asset_type="ip"`` which predates
    # the constrained AssetType enum. Translate to the canonical name
    # so the post-Audit ck_assets_asset_type CHECK accepts the row.
    _ASSET_TYPE_ALIASES = {"ip": "ip_address"}
    for org_name, assets in ASSETS.items():
        org = org_map[org_name]
        for a in assets:
            atype = _ASSET_TYPE_ALIASES.get(a["asset_type"], a["asset_type"])
            session.add(
                Asset(
                    organization_id=org.id,
                    asset_type=atype,
                    value=a["value"],
                    details=a["details"],
                    is_active=True,
                )
            )

    raw_map: dict[str, RawIntel] = {}
    for intel in RAW_INTEL:
        content_hash = hashlib.sha256(
            (intel["title"] + intel["content"]).encode()
        ).hexdigest()
        r = RawIntel(
            source_type=intel["source_type"],
            source_url=intel["source_url"],
            source_name=intel["source_name"],
            title=intel["title"],
            content=intel["content"],
            author=intel["author"],
            published_at=intel["published_at"],
            raw_data=intel["raw_data"],
            content_hash=content_hash,
            is_processed=True,
        )
        session.add(r)
        raw_map[intel["title"]] = r
    await session.flush()

    for a in ALERTS_DATA:
        org = org_map[a["org"]]
        raw_id = None
        if a.get("raw_title") and a["raw_title"] in raw_map:
            raw_id = raw_map[a["raw_title"]].id
        offset = timedelta(
            hours=rng.randint(0, 120), minutes=rng.randint(0, 59)
        )
        alert = Alert(
            organization_id=org.id,
            raw_intel_id=raw_id,
            category=a["category"],
            severity=a["severity"],
            status=a["status"],
            title=a["title"],
            summary=a["summary"],
            confidence=a["confidence"],
            matched_entities=a["matched_entities"],
            recommended_actions=a["recommended_actions"],
            agent_reasoning=a["agent_reasoning"],
            analyst_notes=a.get("analyst_notes"),
            details={"triage_version": "1.0", "model": "glm-5", "provider": "z.ai"},
        )
        alert.created_at = now() - offset
        session.add(alert)

    await session.commit()
    logger.info(
        f"    ↳ created {len(ORGS)} orgs, "
        f"{sum(len(v) for v in VIPS.values())} VIPs, "
        f"{sum(len(v) for v in ASSETS.values())} assets, "
        f"{len(RAW_INTEL)} raw_intel, {len(ALERTS_DATA)} alerts"
    )


# ----------------------------------------------------------------------
# Phase 3 — Argus Demo Bank (delegates to seed_full_demo._seed)
# ----------------------------------------------------------------------


@section("Argus Demo Bank (brand/cases/SLA/exposures)")
async def _seed_demo_bank(session: AsyncSession) -> None:
    from scripts.seed_full_demo import _seed as _seed_demo_bank_full

    await _seed_demo_bank_full(session)


# ----------------------------------------------------------------------
# Phase 4 — Missing tables that drive the 14 RED screens
# ----------------------------------------------------------------------


# --- MITRE ATT&CK (subset; full sync is operator-driven) -------------


_MITRE_TACTICS = [
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
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0040", "impact", "Impact"),
]

_MITRE_TECHNIQUES = [
    ("T1190", "Exploit Public-Facing Application", ["initial-access"]),
    ("T1566", "Phishing", ["initial-access"]),
    ("T1566.001", "Spearphishing Attachment", ["initial-access"]),
    ("T1566.002", "Spearphishing Link", ["initial-access"]),
    ("T1078", "Valid Accounts", ["initial-access", "persistence", "privilege-escalation", "defense-evasion"]),
    ("T1059", "Command and Scripting Interpreter", ["execution"]),
    ("T1059.001", "PowerShell", ["execution"]),
    ("T1059.003", "Windows Command Shell", ["execution"]),
    ("T1053", "Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"]),
    ("T1543", "Create or Modify System Process", ["persistence", "privilege-escalation"]),
    ("T1547", "Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"]),
    ("T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"]),
    ("T1003", "OS Credential Dumping", ["credential-access"]),
    ("T1003.001", "LSASS Memory", ["credential-access"]),
    ("T1110", "Brute Force", ["credential-access"]),
    ("T1110.003", "Password Spraying", ["credential-access"]),
    ("T1027", "Obfuscated Files or Information", ["defense-evasion"]),
    ("T1070", "Indicator Removal", ["defense-evasion"]),
    ("T1018", "Remote System Discovery", ["discovery"]),
    ("T1082", "System Information Discovery", ["discovery"]),
    ("T1083", "File and Directory Discovery", ["discovery"]),
    ("T1021", "Remote Services", ["lateral-movement"]),
    ("T1021.001", "Remote Desktop Protocol", ["lateral-movement"]),
    ("T1560", "Archive Collected Data", ["collection"]),
    ("T1041", "Exfiltration Over C2 Channel", ["exfiltration"]),
    ("T1567", "Exfiltration Over Web Service", ["exfiltration"]),
    ("T1071", "Application Layer Protocol", ["command-and-control"]),
    ("T1071.001", "Web Protocols", ["command-and-control"]),
    ("T1486", "Data Encrypted for Impact", ["impact"]),
    ("T1490", "Inhibit System Recovery", ["impact"]),
]


@section("MITRE ATT&CK catalogue (Enterprise subset)")
async def _seed_mitre(session: AsyncSession) -> None:
    from src.models.mitre import MitreSync, MitreTactic, MitreTechnique

    if await already_seeded(session, MitreTactic):
        logger.info("    ↳ MITRE catalogue already seeded; skipping")
        return

    for ext_id, short, name in _MITRE_TACTICS:
        session.add(
            MitreTactic(
                matrix="enterprise",
                external_id=ext_id,
                short_name=short,
                name=name,
                description=f"{name} — Enterprise tactic. Sample seed data.",
                url=f"https://attack.mitre.org/tactics/{ext_id}/",
                sync_version="seed-2026-04",
            )
        )

    for ext_id, name, tactics in _MITRE_TECHNIQUES:
        is_sub = "." in ext_id
        parent = ext_id.split(".")[0] if is_sub else None
        session.add(
            MitreTechnique(
                matrix="enterprise",
                external_id=ext_id,
                parent_external_id=parent,
                is_subtechnique=is_sub,
                name=name,
                description=f"{name} — sample MITRE Enterprise technique entry.",
                tactics=tactics,
                platforms=["Windows", "Linux", "macOS"],
                data_sources=["Process: Process Creation", "Network Traffic: Network Connection Creation"],
                detection=f"Detect {name} via EDR + network telemetry correlation.",
                url=f"https://attack.mitre.org/techniques/{ext_id.replace('.', '/')}/",
                sync_version="seed-2026-04",
            )
        )

    session.add(
        MitreSync(
            matrix="enterprise",
            source_url="https://attack.mitre.org/ (seed)",
            sync_version="seed-2026-04",
            tactics_count=len(_MITRE_TACTICS),
            techniques_count=len([t for t in _MITRE_TECHNIQUES if "." not in t[0]]),
            subtechniques_count=len([t for t in _MITRE_TECHNIQUES if "." in t[0]]),
            mitigations_count=0,
            deprecated_count=0,
            succeeded=True,
        )
    )
    logger.info(
        f"    ↳ {len(_MITRE_TACTICS)} tactics, {len(_MITRE_TECHNIQUES)} techniques"
    )


# --- Threat Actors --------------------------------------------------


_THREAT_ACTORS = [
    {
        "primary_alias": "LockBit 3.0",
        "aliases": ["LockBit Black", "LockBitSupp"],
        "description": (
            "Ransomware-as-a-Service operation; #1 ransomware crew by disclosed "
            "victim count in 2023-2025. Affiliate-driven, double-extortion model "
            "with public leak site. Currently re-branded post-NCA disruption."
        ),
        "forums_active": ["RAMP", "XSS"],
        "languages": ["ru", "en"],
        "known_ttps": ["T1486", "T1490", "T1078", "T1110.003", "T1567"],
        "risk_score": 0.92,
    },
    {
        "primary_alias": "FIN7",
        "aliases": ["Carbanak", "Carbon Spider", "ITG14"],
        "description": (
            "Financially-motivated threat group active since at least 2013. "
            "Targets retail, hospitality, restaurant chains via spear-phishing "
            "with weaponized docs. Operates Combi Security front company. "
            "Now overlaps with ransomware affiliate operations."
        ),
        "forums_active": ["Exploit", "RAMP"],
        "languages": ["ru", "en"],
        "known_ttps": ["T1566.001", "T1059.001", "T1003.001", "T1018"],
        "risk_score": 0.87,
    },
    {
        "primary_alias": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Strontium"],
        "description": (
            "Russia-attributed state-sponsored APT (GRU Unit 26165). Targets "
            "government, military, defense, NGOs. Notable for the 2016 DNC "
            "breach and pervasive credential phishing campaigns."
        ),
        "forums_active": [],
        "languages": ["ru"],
        "known_ttps": ["T1566.002", "T1078", "T1003", "T1071.001"],
        "risk_score": 0.94,
    },
    {
        "primary_alias": "Lazarus Group",
        "aliases": ["Hidden Cobra", "APT38", "Diamond Sleet"],
        "description": (
            "DPRK state-sponsored cluster. Targets banks (SWIFT heists), "
            "cryptocurrency exchanges (Ronin, Atomic Wallet), and defense. "
            "Funds the regime via crypto theft; 2022-2024 attributed losses "
            "exceed $3 billion."
        ),
        "forums_active": [],
        "languages": ["ko", "en"],
        "known_ttps": ["T1566.001", "T1059.003", "T1027", "T1041"],
        "risk_score": 0.95,
    },
    {
        "primary_alias": "ALPHV/BlackCat",
        "aliases": ["BlackCat", "Noberus"],
        "description": (
            "Ransomware-as-a-Service; first ransomware family written in Rust. "
            "Affiliate-recruited, double-extortion. Hit Change Healthcare in "
            "2024 ($22M ransom paid). Disrupted by FBI takedown Dec 2023; "
            "subsequently resurfaced."
        ),
        "forums_active": ["RAMP"],
        "languages": ["ru", "en"],
        "known_ttps": ["T1486", "T1490", "T1078", "T1567"],
        "risk_score": 0.89,
    },
    {
        "primary_alias": "Scattered Spider",
        "aliases": ["UNC3944", "Octo Tempest", "0ktapus"],
        "description": (
            "Native English-speaking, highly skilled social engineering crew. "
            "MGM/Caesars 2023, Twilio 2022. Combines voice phishing of help "
            "desks with rapid SIM swap and ransomware deployment via ALPHV "
            "affiliate channel."
        ),
        "forums_active": ["Telegram"],
        "languages": ["en"],
        "known_ttps": ["T1566", "T1078", "T1110.003", "T1486"],
        "risk_score": 0.91,
    },
    {
        "primary_alias": "Cl0p",
        "aliases": ["TA505 affiliate", "FIN11 nexus"],
        "description": (
            "Mass-exploitation ransomware crew. MOVEit Transfer (CVE-2023-34362) "
            "and GoAnywhere campaigns netted >2,500 victim orgs in 2023. "
            "Pivoting to data-extortion-only ('encrypt-less') in 2024."
        ),
        "forums_active": ["RAMP"],
        "languages": ["ru"],
        "known_ttps": ["T1190", "T1567", "T1041"],
        "risk_score": 0.88,
    },
    {
        "primary_alias": "APT41",
        "aliases": ["Winnti", "Barium", "Wicked Panda"],
        "description": (
            "China-attributed dual-use threat group: state-sponsored espionage "
            "by day, financially motivated game-publisher and crypto theft by "
            "night. Targets semiconductor IP and supply chains."
        ),
        "forums_active": [],
        "languages": ["zh", "en"],
        "known_ttps": ["T1190", "T1566.001", "T1027", "T1071"],
        "risk_score": 0.90,
    },
]


@section("threat actors (LockBit, FIN7, APT28, Lazarus, ALPHV, Scattered Spider, Cl0p, APT41)")
async def _seed_threat_actors(session: AsyncSession) -> dict[str, Any]:
    from src.models.intel import ActorSighting, ThreatActor
    from src.models.threat import Alert, Organization

    if await already_seeded(session, ThreatActor):
        logger.info("    ↳ threat actors already seeded; skipping")
        return {}

    actor_map: dict[str, ThreatActor] = {}
    for data in _THREAT_ACTORS:
        actor = ThreatActor(
            primary_alias=data["primary_alias"],
            aliases=data["aliases"],
            description=data["description"],
            forums_active=data["forums_active"],
            languages=data["languages"],
            pgp_fingerprints=[],
            known_ttps=data["known_ttps"],
            risk_score=data["risk_score"],
            first_seen=ago(days=rng.randint(800, 2400)),
            last_seen=ago(days=rng.randint(1, 14)),
            total_sightings=rng.randint(8, 90),
            profile_data={
                "first_observed": "external-feed",
                "associated_malware": [],
            },
        )
        session.add(actor)
        actor_map[data["primary_alias"]] = actor
    await session.flush()

    # Wire a few sightings to existing alerts so the actor profile pages
    # have something to display rather than an empty list.
    alerts = (
        await session.execute(select(Alert).limit(40))
    ).scalars().all()
    org_ids = list({a.organization_id for a in alerts})

    for actor in actor_map.values():
        for _ in range(rng.randint(2, 4)):
            target_alert = rng.choice(alerts) if alerts else None
            session.add(
                ActorSighting(
                    threat_actor_id=actor.id,
                    raw_intel_id=None,
                    alert_id=target_alert.id if target_alert else None,
                    source_platform=rng.choice(
                        ["XSS", "Exploit", "Telegram", "Tor leak site", "BreachForums"]
                    ),
                    alias_used=rng.choice(actor.aliases or [actor.primary_alias]),
                    context={"observed_at": ago(days=rng.randint(1, 60)).isoformat()},
                )
            )
    logger.info(f"    ↳ {len(actor_map)} actors + sightings linked to alerts")
    return actor_map


# --- IOCs (Indicators of Compromise) -------------------------------


_IOC_DOMAIN_NAMES = [
    "exfil-eu.lazarus-c2.io", "update.lockbit-3-0[.]life", "auth.fin7-staging[.]net",
    "api.alphv-ext-c2[.]xyz", "cdn-pull.scattered-spider[.]online", "panel.cl0p-uploader[.]top",
    "edge.apt41-pull[.]works", "auth.apt28-fancybear-relay[.]ru",
    "downloads.heliossemi-support[.]com", "cdn.meridianfg-update[.]com",
    "patient-portal-secure.novamed-health[.]net", "mfg-portal-login.com",
    "argusdemo-secure.bank", "argusdemo[.]help",
    "phish-meridianfg.support",
    "drive-novamed.share", "github-helios.dev", "okta-meridian.live",
    "vpn-novamed-emergency.com", "secure-mfg.help", "api-helios.zone",
]
_IOC_IPS = [
    "203.0.113.42", "198.51.100.7", "198.51.100.124", "192.0.2.55", "203.0.113.99",
    "185.220.101.45", "146.70.144.230", "5.45.207.88", "94.140.114.3", "162.247.74.27",
]
_IOC_HASHES_SHA256 = [fake_sha256(f"sample-malware-{i}") for i in range(12)]
_IOC_HASHES_MD5 = [fake_md5(f"sample-malware-md5-{i}") for i in range(8)]
_IOC_BTC = [
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    "1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "bc1q9h6yzvf9tj2cqpr2ehjx30s24c0s6cwx7yqzpq",
]
_IOC_CVES = [
    "CVE-2023-34362", "CVE-2024-1709", "CVE-2024-3400", "CVE-2024-21412",
    "CVE-2026-1001", "CVE-2024-47575", "CVE-2024-30088",
]


@section("IOCs (~50 across types) wired to threat actors")
async def _seed_iocs(session: AsyncSession) -> None:
    from src.models.intel import IOC, IOCType, ThreatActor

    if await already_seeded(session, IOC):
        logger.info("    ↳ IOCs already seeded; skipping")
        return

    actors = (await session.execute(select(ThreatActor))).scalars().all()
    actor_for = lambda i: actors[i % len(actors)] if actors else None

    rows: list[IOC] = []

    for i, dom in enumerate(_IOC_DOMAIN_NAMES):
        rows.append(
            IOC(
                ioc_type=IOCType.DOMAIN.value,
                value=dom.replace("[.]", "."),
                confidence=round(rng.uniform(0.55, 0.95), 2),
                first_seen=ago(days=rng.randint(7, 90)),
                last_seen=ago(hours=rng.randint(1, 72)),
                sighting_count=rng.randint(1, 25),
                tags=["c2", "phishing"] if i % 2 == 0 else ["typosquat"],
                context={"asn": f"AS{rng.randint(1000, 65000)}", "country": rng.choice(["RU", "CN", "KP", "UA", "US"])},
                threat_actor_id=actor_for(i).id if actor_for(i) else None,
            )
        )
    for i, ip in enumerate(_IOC_IPS):
        rows.append(
            IOC(
                ioc_type=IOCType.IPV4.value,
                value=ip,
                confidence=round(rng.uniform(0.5, 0.92), 2),
                first_seen=ago(days=rng.randint(3, 60)),
                last_seen=ago(hours=rng.randint(1, 48)),
                sighting_count=rng.randint(1, 18),
                tags=rng.choice([["scanner"], ["c2"], ["proxy", "tor_exit"]]),
                context={"asn": f"AS{rng.randint(1000, 65000)}"},
                threat_actor_id=actor_for(i).id if actor_for(i) else None,
            )
        )
    for i, h in enumerate(_IOC_HASHES_SHA256):
        rows.append(
            IOC(
                ioc_type=IOCType.SHA256.value,
                value=h,
                confidence=round(rng.uniform(0.7, 0.98), 2),
                first_seen=ago(days=rng.randint(1, 30)),
                last_seen=ago(hours=rng.randint(1, 24)),
                sighting_count=rng.randint(1, 12),
                tags=["malware"],
                context={"family": rng.choice(["IcedID", "QakBot", "Cobalt Strike", "BlackCat", "Mimikatz"])},
                threat_actor_id=actor_for(i).id if actor_for(i) else None,
            )
        )
    for i, h in enumerate(_IOC_HASHES_MD5):
        rows.append(
            IOC(
                ioc_type=IOCType.MD5.value,
                value=h,
                confidence=round(rng.uniform(0.5, 0.85), 2),
                first_seen=ago(days=rng.randint(1, 60)),
                last_seen=ago(days=rng.randint(0, 5)),
                sighting_count=rng.randint(1, 7),
                tags=["dropper"],
                threat_actor_id=actor_for(i).id if actor_for(i) else None,
            )
        )
    for i, addr in enumerate(_IOC_BTC):
        rows.append(
            IOC(
                ioc_type=IOCType.BTC_ADDRESS.value,
                value=addr,
                confidence=0.9,
                first_seen=ago(days=rng.randint(60, 400)),
                last_seen=ago(days=rng.randint(1, 30)),
                sighting_count=rng.randint(2, 50),
                tags=["ransomware-payment"],
                context={"chain": "bitcoin"},
                threat_actor_id=actor_for(i).id if actor_for(i) else None,
            )
        )
    for cve in _IOC_CVES:
        rows.append(
            IOC(
                ioc_type=IOCType.CVE.value,
                value=cve,
                confidence=0.99,
                first_seen=ago(days=rng.randint(30, 400)),
                last_seen=ago(days=rng.randint(0, 7)),
                sighting_count=rng.randint(5, 80),
                tags=["kev"] if rng.random() > 0.4 else ["pubsec"],
            )
        )

    session.add_all(rows)
    logger.info(f"    ↳ {len(rows)} IOCs seeded")


# --- TPRM (vendor scorecards + questionnaires) ---------------------


_TPRM_VENDORS = [
    {"name": "okta-saas-vendor.com", "industry": "Identity"},
    {"name": "sentry-monitoring-vendor.com", "industry": "Observability"},
    {"name": "stripe-payments-vendor.com", "industry": "Payments"},
    {"name": "slack-collab-vendor.com", "industry": "Collaboration"},
    {"name": "datadog-observability-vendor.com", "industry": "Observability"},
]


@section("TPRM vendor scorecards & questionnaires")
async def _seed_tprm(session: AsyncSession) -> None:
    from src.models.threat import Asset, Organization
    from src.models.tprm import (
        AnswerKind,
        QuestionnaireInstance,
        QuestionnaireKind,
        QuestionnaireState,
        QuestionnaireTemplate,
        VendorGrade,
        VendorOnboardingStage,
        VendorOnboardingWorkflow,
        VendorScorecard,
    )

    if await already_seeded(session, VendorScorecard):
        logger.info("    ↳ TPRM data already seeded; skipping")
        return

    org = (
        await session.execute(
            select(Organization).where(Organization.name == "Argus Demo Bank")
        )
    ).scalar_one_or_none()
    if org is None:
        # Fall back to first org if demo bank wasn't seeded
        org = (await session.execute(select(Organization))).scalar()
    if org is None:
        logger.info("    ↳ no orgs available; skipping TPRM")
        return

    # Standard questionnaire template (org-scoped + a system-wide one).
    template = QuestionnaireTemplate(
        organization_id=None,
        name="SIG Lite — Standard Information Gathering (Lite)",
        kind=QuestionnaireKind.SIG_LITE.value,
        description="Industry-standard third-party risk questionnaire.",
        questions=[
            {"id": "q01", "text": "Do you maintain a documented information security policy?", "kind": "yes_no", "weight": 5},
            {"id": "q02", "text": "Have you completed a SOC 2 Type II audit in the last 12 months?", "kind": "yes_no", "weight": 10},
            {"id": "q03", "text": "Do you encrypt data at rest using AES-256 or stronger?", "kind": "yes_no", "weight": 8},
            {"id": "q04", "text": "Do you encrypt data in transit using TLS 1.2 or higher?", "kind": "yes_no", "weight": 8},
            {"id": "q05", "text": "Do you require MFA for all production access?", "kind": "yes_no", "weight": 9},
            {"id": "q06", "text": "Do you have a documented incident response plan?", "kind": "yes_no", "weight": 7},
            {"id": "q07", "text": "Have you experienced a security incident in the last 24 months?", "kind": "yes_no", "weight": 5},
            {"id": "q08", "text": "Are penetration tests performed annually?", "kind": "yes_no", "weight": 6},
        ],
        is_active=True,
    )
    session.add(template)
    await session.flush()

    grade_options = [VendorGrade.A, VendorGrade.B, VendorGrade.C, VendorGrade.D]

    for i, vd in enumerate(_TPRM_VENDORS):
        vendor_asset = Asset(
            organization_id=org.id,
            asset_type="vendor",
            value=vd["name"],
            details={"industry": vd["industry"], "tier": rng.choice(["critical", "important", "standard"])},
            is_active=True,
        )
        session.add(vendor_asset)
        await session.flush()

        score = round(rng.uniform(55, 95), 1)
        grade = grade_options[min(int((100 - score) / 12), len(grade_options) - 1)]
        session.add(
            VendorScorecard(
                organization_id=org.id,
                vendor_asset_id=vendor_asset.id,
                score=score,
                grade=grade.value,
                is_current=True,
                pillar_scores={
                    "data_security": round(rng.uniform(40, 100), 1),
                    "incident_response": round(rng.uniform(40, 100), 1),
                    "access_control": round(rng.uniform(40, 100), 1),
                    "compliance": round(rng.uniform(40, 100), 1),
                },
                summary={
                    "highlights": ["SOC 2 Type II current", "MFA enforced"],
                    "gaps": ["Penetration test overdue"] if score < 80 else [],
                },
                computed_at=ago(days=rng.randint(0, 30)),
            )
        )

        # Questionnaire instance
        instance = QuestionnaireInstance(
            organization_id=org.id,
            template_id=template.id,
            vendor_asset_id=vendor_asset.id,
            state=rng.choice(
                [
                    QuestionnaireState.SENT.value,
                    QuestionnaireState.RECEIVED.value,
                    QuestionnaireState.REVIEWED.value,
                ]
            ),
            sent_at=ago(days=rng.randint(20, 60)),
            received_at=ago(days=rng.randint(5, 19)),
            due_at=ago(days=-rng.randint(0, 14)),
            score=score,
        )
        session.add(instance)

        session.add(
            VendorOnboardingWorkflow(
                organization_id=org.id,
                vendor_asset_id=vendor_asset.id,
                stage=rng.choice(
                    [
                        VendorOnboardingStage.QUESTIONNAIRE_RECEIVED.value,
                        VendorOnboardingStage.ANALYST_REVIEW.value,
                        VendorOnboardingStage.APPROVED.value,
                    ]
                ),
            )
        )
    logger.info(f"    ↳ 1 template, {len(_TPRM_VENDORS)} vendor scorecards + workflows")


# --- BIN registry --------------------------------------------------


_BINS = [
    # (prefix, scheme, card_type, issuer, country)
    ("400000", "visa", "credit", "Visa Test", "US"),
    ("411111", "visa", "credit", "Argus Demo Bank", "US"),
    ("424242", "visa", "credit", "Stripe Test", "US"),
    ("450875", "visa", "debit", "Wells Fargo", "US"),
    ("510510", "mastercard", "credit", "MasterCard Test", "US"),
    ("520000", "mastercard", "credit", "Citibank", "US"),
    ("530000", "mastercard", "debit", "Capital One", "US"),
    ("540000", "mastercard", "credit", "Chase", "US"),
    ("550000", "mastercard", "credit", "Bank of America", "US"),
    ("340000", "amex", "credit", "American Express Centurion", "US"),
    ("370000", "amex", "credit", "American Express Gold", "US"),
    ("601100", "discover", "credit", "Discover", "US"),
    ("352800", "jcb", "credit", "JCB", "JP"),
    ("300000", "diners", "credit", "Diners Club", "US"),
    ("424242", "visa", "credit", "Argus Demo Bank Premier", "US"),  # dup-prefix scoped to org
]


@section("BIN registry (Visa/MC/Amex/Discover/JCB/Diners)")
async def _seed_bin_registry(session: AsyncSession) -> None:
    from src.models.leakage import CardScheme, CardType, CreditCardBin

    if await already_seeded(session, CreditCardBin):
        logger.info("    ↳ BIN registry already seeded; skipping")
        return

    seen: set[tuple[str, str | None]] = set()
    for prefix, scheme, ctype, issuer, country in _BINS:
        # CreditCardBin model assumes (bin_prefix, organization_id) uniqueness;
        # treat duplicates as global fallback rows.
        key = (prefix, None)
        if key in seen:
            continue
        seen.add(key)
        session.add(
            CreditCardBin(
                bin_prefix=prefix,
                scheme=scheme,
                card_type=ctype,
                issuer=issuer,
                country_code=country,
                organization_id=None,
            )
        )
    logger.info(f"    ↳ {len(seen)} BIN ranges (global)")


# --- Brand logos (DB rows only — no actual image uploads) -----------


@section("brand logos (corpus reference rows)")
async def _seed_brand_logos(session: AsyncSession) -> None:
    from src.models.logo import BrandLogo
    from src.models.threat import Organization

    if await already_seeded(session, BrandLogo):
        logger.info("    ↳ brand logos already seeded; skipping")
        return

    orgs = (await session.execute(select(Organization))).scalars().all()
    if not orgs:
        return

    for org in orgs:
        for variant in ["primary", "monochrome", "social"]:
            session.add(
                BrandLogo(
                    organization_id=org.id,
                    label=f"{org.name} — {variant} logo",
                    description=f"Reference {variant} logo for {org.name}",
                    width=512,
                    height=512,
                    image_evidence_sha256=fake_sha256(f"{org.id}-{variant}"),
                    phash_hex="0" * 16,
                    dhash_hex="0" * 16,
                    ahash_hex="0" * 16,
                    color_histogram=[0.0] * 32,
                )
            )
    logger.info(f"    ↳ {len(orgs) * 3} logo corpus rows across orgs")


# --- Notification channels + a couple of deliveries ----------------


@section("notification channels (slack/email/webhook stubs)")
async def _seed_notifications(session: AsyncSession) -> None:
    from src.models.notifications import (
        ChannelKind,
        DeliveryStatus,
        EventKind,
        NotificationChannel,
        NotificationDelivery,
        NotificationRule,
        SeverityLevel,
    )
    from src.models.threat import Organization

    if await already_seeded(session, NotificationChannel):
        logger.info("    ↳ notification channels already seeded; skipping")
        return

    orgs = (await session.execute(select(Organization))).scalars().all()
    if not orgs:
        return

    for org in orgs:
        slack = NotificationChannel(
            organization_id=org.id,
            name="SOC #alerts (Slack)",
            kind=ChannelKind.SLACK.value,
            config={"webhook_url_redacted": True},
            secret_ciphertext="redacted-demo",
            enabled=True,
        )
        email = NotificationChannel(
            organization_id=org.id,
            name="On-call email",
            kind=ChannelKind.EMAIL.value,
            config={"recipients": ["soc@example.test"], "smtp_host": "mail.example.test"},
            secret_ciphertext=None,
            enabled=True,
        )
        session.add_all([slack, email])
        await session.flush()

        rule = NotificationRule(
            organization_id=org.id,
            name="Critical & High alerts → SOC channels",
            min_severity=SeverityLevel.HIGH.value,
            event_kinds=[EventKind.ALERT.value],
            channel_ids=[str(slack.id), str(email.id)],
            enabled=True,
        )
        session.add(rule)

        for i in range(3):
            session.add(
                NotificationDelivery(
                    organization_id=org.id,
                    channel_id=slack.id,
                    event_kind=EventKind.ALERT.value,
                    event_severity=rng.choice(
                        [SeverityLevel.HIGH.value, SeverityLevel.CRITICAL.value]
                    ),
                    event_payload={
                        "title": f"Demo alert delivery #{i+1}",
                        "summary": "Sample notification dispatched during seed.",
                    },
                    status=rng.choice(
                        [DeliveryStatus.SUCCEEDED.value, DeliveryStatus.FAILED.value]
                    ),
                    response_status=rng.choice([200, 502, 200]),
                    attempts=rng.randint(1, 3),
                    latency_ms=rng.randint(40, 800),
                    delivered_at=ago(hours=rng.randint(1, 96)),
                )
            )
    logger.info(f"    ↳ 2 channels × {len(orgs)} orgs + sample deliveries")


# --- Webhook endpoints --------------------------------------------


@section("webhook endpoints + sample deliveries")
async def _seed_webhooks(session: AsyncSession) -> None:
    from src.models.intel import WebhookDelivery, WebhookDeliveryStatus, WebhookEndpoint

    if await already_seeded(session, WebhookEndpoint):
        logger.info("    ↳ webhooks already seeded; skipping")
        return

    sirens = WebhookEndpoint(
        name="SIEM ingest — Splunk HEC (demo)",
        url="https://splunk.example.test/services/collector",
        endpoint_type="siem",
        secret="demo-hmac-secret",
        headers={"X-Splunk-Index": "argus_alerts"},
        enabled=True,
        min_severity="medium",
        organization_id=None,
    )
    soar = WebhookEndpoint(
        name="SOAR — Tines workflow",
        url="https://tines.example.test/webhook/argus-alerts",
        endpoint_type="generic",
        secret="demo-tines-secret",
        enabled=True,
        min_severity="high",
        organization_id=None,
    )
    session.add_all([sirens, soar])
    await session.flush()

    for ep in (sirens, soar):
        for i in range(3):
            session.add(
                WebhookDelivery(
                    endpoint_id=ep.id,
                    payload={"demo": True, "n": i},
                    status=rng.choice(
                        [
                            WebhookDeliveryStatus.DELIVERED.value,
                            WebhookDeliveryStatus.DELIVERED.value,
                            WebhookDeliveryStatus.FAILED.value,
                        ]
                    ),
                    status_code=rng.choice([200, 200, 503]),
                    attempt_count=rng.randint(1, 3),
                    delivered_at=ago(hours=rng.randint(1, 72)),
                )
            )
    logger.info("    ↳ 2 webhook endpoints, 6 deliveries")


# --- Integration configs (system-wide tool list) -------------------


@section("integration configs (Wazuh/Splunk/CrowdStrike stubs)")
async def _seed_integrations(session: AsyncSession) -> None:
    from src.models.intel import IntegrationConfig

    if await already_seeded(session, IntegrationConfig):
        logger.info("    ↳ integrations already seeded; skipping")
        return

    integrations = [
        ("wazuh", False, "https://wazuh.example.test", "unconfigured"),
        ("splunk_hec", True, "https://splunk.example.test", "healthy"),
        ("crowdstrike_falcon", False, "", "unconfigured"),
        ("microsoft_sentinel", False, "", "unconfigured"),
        ("misp", True, "https://misp.example.test", "degraded"),
        ("opencti", False, "", "unconfigured"),
    ]
    for name, enabled, url, health in integrations:
        session.add(
            IntegrationConfig(
                tool_name=name,
                enabled=enabled,
                api_url=url,
                api_key=None,
                health_status=health,
                last_sync_at=ago(hours=rng.randint(1, 48)) if enabled else None,
                last_error=None if health == "healthy" else "Demo seed: degraded - sample error" if health == "degraded" else None,
                sync_interval_seconds=3600,
            )
        )
    logger.info(f"    ↳ {len(integrations)} integration configs")


# --- Retention policies -------------------------------------------


@section("retention policies (global default + per-org)")
async def _seed_retention_policies(session: AsyncSession) -> None:
    from src.models.intel import RetentionPolicy
    from src.models.threat import Organization

    if await already_seeded(session, RetentionPolicy):
        logger.info("    ↳ retention policies already seeded; skipping")
        return

    session.add(
        RetentionPolicy(
            organization_id=None,
            raw_intel_days=90,
            alerts_days=365,
            audit_logs_days=730,
            iocs_days=365,
            redact_pii=True,
            auto_cleanup_enabled=True,
        )
    )
    orgs = (await session.execute(select(Organization))).scalars().all()
    for o in orgs[:2]:
        session.add(
            RetentionPolicy(
                organization_id=o.id,
                raw_intel_days=180,
                alerts_days=730,
                audit_logs_days=2555,
                iocs_days=730,
                redact_pii=True,
                auto_cleanup_enabled=True,
            )
        )
    logger.info("    ↳ global default + per-org overrides")


# --- News / Advisories --------------------------------------------


@section("news feeds + articles + advisories")
async def _seed_news_and_advisories(session: AsyncSession) -> None:
    from src.models.news import (
        Advisory,
        AdvisorySeverity,
        AdvisoryState,
        FeedKind,
        NewsArticle,
        NewsFeed,
    )
    from src.models.threat import Organization

    org = (
        await session.execute(
            select(Organization).where(Organization.name == "Argus Demo Bank")
        )
    ).scalar_one_or_none()
    if org is None:
        org = (await session.execute(select(Organization))).scalar()
    if org is None:
        return

    # Idempotency keys on (org_id, slug) for Advisory and (org_id, url) for
    # NewsFeed. Bail out if any of our advisories already exist; news feeds
    # are inserted defensively below.
    if await already_seeded(
        session, Advisory, where=Advisory.slug == "argus-2026-002"
    ):
        logger.info("    ↳ news/advisories already seeded; skipping")
        return

    # Avoid name/url collision with the CISA KEV feed seeded by
    # ``_seed_demo_bank`` (uniq constraint on (org_id, url)).
    candidate_feeds = [
        ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ("The Record by Recorded Future", "https://therecord.media/feed"),
        ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/"),
    ]
    feeds: list[NewsFeed] = []
    for name, url in candidate_feeds:
        existing = (
            await session.execute(
                select(NewsFeed).where(
                    NewsFeed.organization_id == org.id, NewsFeed.url == url
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            feeds.append(existing)
            continue
        feed = NewsFeed(
            organization_id=org.id,
            name=name,
            url=url,
            kind=FeedKind.RSS.value,
            enabled=True,
        )
        session.add(feed)
        feeds.append(feed)
    await session.flush()

    headlines = [
        ("LockBit affiliate breaches MSP, ~150 downstream orgs impacted", ["CVE-2024-1709"]),
        ("New MOVEit-style supply-chain campaign hits financial sector", ["CVE-2023-34362"]),
        ("APT41 weaponises EDA tooling to backdoor chip designers", []),
        ("CISA adds two more zero-days to KEV after active exploitation", ["CVE-2024-3400"]),
        ("Ransomware-as-a-service market consolidates around three brands", []),
        ("BIN-leak campaign on Telegram targets Latin American banks", []),
        ("Lazarus rotates infrastructure after ICANN takedown round", []),
        ("Scattered Spider pivots to insurance and healthcare verticals", []),
    ]
    for i, (title, cves) in enumerate(headlines):
        url = f"https://example.test/news/{i}-{title[:24].replace(' ', '-')}"
        session.add(
            NewsArticle(
                feed_id=feeds[i % len(feeds)].id,
                title=title,
                url=url,
                url_sha256=fake_sha256(url),
                summary=title + ". Sample article body for the demo.",
                cve_ids=cves,
                published_at=ago(hours=rng.randint(1, 200)),
                fetched_at=ago(hours=rng.randint(0, 6)),
            )
        )

    advisories = [
        ("argus-2026-002", "Patch CVE-2024-3400 across Palo Alto fleet", AdvisorySeverity.CRITICAL.value, ["CVE-2024-3400"]),
        ("argus-2026-003", "Rotate MOVEit credentials and enable audit", AdvisorySeverity.HIGH.value, ["CVE-2023-34362"]),
        ("argus-2026-004", "MFA enforcement reminder for vendor logins", AdvisorySeverity.MEDIUM.value, []),
        ("argus-2026-005", "Quarterly tabletop exercise — ransomware path", AdvisorySeverity.LOW.value, []),
    ]
    for slug, title, sev, cves in advisories:
        session.add(
            Advisory(
                organization_id=org.id,
                slug=slug,
                title=title,
                body_markdown=f"# {title}\n\nIssued by Argus Demo SOC. Action required.",
                severity=sev,
                state=AdvisoryState.PUBLISHED.value,
                cve_ids=cves,
                tags=["seed"],
                published_at=ago(days=rng.randint(0, 30)),
            )
        )
    logger.info(f"    ↳ {len(feeds)} feeds, {len(headlines)} articles, {len(advisories)} advisories")


# --- Reports -------------------------------------------------------


@section("sample reports (executive + technical)")
async def _seed_reports(session: AsyncSession) -> None:
    from src.models.threat import Organization, Report

    if await already_seeded(session, Report):
        logger.info("    ↳ reports already seeded; skipping")
        return

    orgs = (await session.execute(select(Organization))).scalars().all()
    if not orgs:
        return

    titles = [
        "Weekly Threat Briefing — Week 17",
        "Monthly Executive Risk Summary — March",
        "Brand Protection Quarterly — Q1 2026",
        "EASM Posture Snapshot",
    ]
    for org in orgs[:3]:
        for i, title in enumerate(titles):
            session.add(
                Report(
                    organization_id=org.id,
                    title=f"{title} — {org.name}",
                    date_from=ago(days=7 + i * 7),
                    date_to=ago(days=i * 7),
                    file_path=f"reports/{org.id}/{title.replace(' ', '_').replace('—', '-')}.pdf",
                    summary=(
                        f"Auto-generated demo report for {org.name}. "
                        "Sections: top alerts, new IOCs, recommended actions."
                    ),
                )
            )
    logger.info(f"    ↳ {len(titles)} reports × {min(3, len(orgs))} orgs")


# --- DMARC reports ------------------------------------------------


@section("DMARC RUA reports + per-row results")
async def _seed_dmarc(session: AsyncSession) -> None:
    from src.models.dmarc import (
        DmarcDispositionPolicy,
        DmarcReport,
        DmarcReportKind,
        DmarcReportRecord,
    )
    from src.models.threat import Organization

    if await already_seeded(session, DmarcReport):
        logger.info("    ↳ DMARC reports already seeded; skipping")
        return

    orgs = (await session.execute(select(Organization))).scalars().all()
    if not orgs:
        return

    for org in orgs:
        for domain in (org.domains or [])[:2]:
            for k in range(3):
                begin = ago(days=(k + 1) * 7)
                end = begin + timedelta(days=7)
                total = rng.randint(50, 5000)
                pass_n = int(total * rng.uniform(0.7, 0.99))
                fail_n = total - pass_n
                quar_n = int(fail_n * rng.uniform(0.4, 0.9))
                rej_n = fail_n - quar_n
                report = DmarcReport(
                    organization_id=org.id,
                    domain=domain,
                    kind=DmarcReportKind.AGGREGATE.value,
                    org_name=rng.choice(["google.com", "Yahoo!", "Microsoft Corporation"]),
                    report_id=f"seed-{org.id}-{domain}-{k}",
                    date_begin=begin,
                    date_end=end,
                    policy_p=DmarcDispositionPolicy.QUARANTINE.value,
                    policy_pct=100,
                    total_messages=total,
                    pass_count=pass_n,
                    fail_count=fail_n,
                    quarantine_count=quar_n,
                    reject_count=rej_n,
                )
                session.add(report)
                await session.flush()

                for r in range(rng.randint(2, 5)):
                    dkim_pass = rng.random() > 0.2
                    spf_pass = rng.random() > 0.3
                    aligned = dkim_pass or spf_pass
                    session.add(
                        DmarcReportRecord(
                            organization_id=org.id,
                            report_id=report.id,
                            domain=domain,
                            source_ip=f"203.0.113.{rng.randint(2, 254)}",
                            count=rng.randint(1, 200),
                            disposition=(
                                DmarcDispositionPolicy.NONE.value
                                if aligned
                                else DmarcDispositionPolicy.QUARANTINE.value
                            ),
                            dkim_result="pass" if dkim_pass else "fail",
                            spf_result="pass" if spf_pass else "fail",
                            dkim_aligned=dkim_pass,
                            spf_aligned=spf_pass,
                            envelope_from=rng.choice([domain, f"alias.{domain}", "spoof.test"]),
                            header_from=domain,
                        )
                    )
    logger.info("    ↳ DMARC aggregate reports + per-row records")


# --- Onboarding sessions ------------------------------------------


@section("onboarding sessions (in-progress + completed)")
async def _seed_onboarding(session: AsyncSession) -> None:
    from src.models.onboarding import OnboardingSession, OnboardingState
    from src.models.threat import Organization

    if await already_seeded(session, OnboardingSession):
        logger.info("    ↳ onboarding sessions already seeded; skipping")
        return

    orgs = (await session.execute(select(Organization))).scalars().all()
    if not orgs:
        return

    for org in orgs[:2]:
        session.add(
            OnboardingSession(
                organization_id=org.id,
                state=OnboardingState.COMPLETED.value,
                current_step=5,
                step_data={
                    "primary_domain": (org.domains or ["example.com"])[0],
                    "industry": org.industry,
                    "asset_count_estimate": rng.randint(20, 200),
                },
                completed_at=ago(days=rng.randint(7, 30)),
            )
        )
    if len(orgs) >= 3:
        session.add(
            OnboardingSession(
                organization_id=orgs[2].id,
                state=OnboardingState.DRAFT.value,
                current_step=3,
                step_data={
                    "primary_domain": (orgs[2].domains or ["pending.com"])[0],
                    "step": "asset_review",
                },
            )
        )
    logger.info("    ↳ 2 completed + 1 draft (mid-flow)")


# --- Audit-log backfill -------------------------------------------


@section("audit log backfill (login / settings / case events)")
async def _seed_audit_backfill(session: AsyncSession) -> None:
    from src.models.auth import AuditAction, AuditLog, User

    if await already_seeded(session, AuditLog, where=AuditLog.action == AuditAction.SETTINGS_UPDATE.value):
        logger.info("    ↳ audit backfill already present; skipping")
        return

    admin = (
        await session.execute(
            select(User).where(User.role == "admin").limit(1)
        )
    ).scalar()
    if admin is None:
        return

    for i in range(8):
        await audit_log(
            session,
            AuditAction.LOGIN,
            user=admin,
            resource_type="session",
            resource_id=str(deterministic_uuid("session", str(i))),
            details={"ip": f"10.0.0.{rng.randint(2, 254)}", "ua": "Mozilla/5.0 demo"},
        )
    settings_changes = [
        ("typosquat_similarity_threshold", 0.75, 0.85),
        ("alert_dedup_window_minutes", 60, 30),
        ("dlp_regex_timeout_ms", 500, 1000),
        ("retention_alerts_days", 365, 730),
    ]
    for key, before, after in settings_changes:
        await audit_log(
            session,
            AuditAction.SETTINGS_UPDATE,
            user=admin,
            resource_type="app_setting",
            resource_id=key,
            details={"key": key},
            before={"value": before},
            after={"value": after},
        )
    logger.info("    ↳ 8 LOGIN + 4 SETTINGS_UPDATE entries")


# --- Example agentic investigation -----------------------------------


@section("example investigation (completed run with full trace)")
async def _seed_example_investigation(session: AsyncSession) -> None:
    """Seed one COMPLETED Investigation against the highest-severity
    alert in the realistic dataset, plus a queued one against another
    severe alert so the Investigations tab demonstrates both states.
    """
    from src.models.investigations import Investigation, InvestigationStatus
    from src.models.threat import Alert

    if await already_seeded(session, Investigation):
        logger.info("    ↳ investigations already seeded; skipping")
        return

    # Scope to the system organisation so the seeded run is reachable
    # via the org-scoped /investigations API. ``get_system_org_id``
    # picks the lowest-created_at org — that's Argus Demo Bank in the
    # realistic phase ordering.
    from src.core.tenant import get_system_org_id

    org_id = await get_system_org_id(session)

    alerts = (
        await session.execute(
            select(Alert)
            .where(Alert.organization_id == org_id)
            .where(Alert.severity.in_(["critical", "high"]))
            .order_by(Alert.created_at.desc())
            .limit(2)
        )
    ).scalars().all()

    # If the system org has no usable alert (seed_full_demo doesn't
    # create alerts), synthesise a couple so the dashboard tab has
    # something to render. Same shape an LLM-triaged alert would
    # produce, just hand-written for reproducibility.
    if not alerts:
        from src.models.threat import Alert as _AlertModel
        from src.models.threat import AlertStatus, ThreatCategory, ThreatSeverity

        synth = [
            _AlertModel(
                organization_id=org_id,
                category=ThreatCategory.DARK_WEB_MENTION.value,
                severity=ThreatSeverity.CRITICAL.value,
                status=AlertStatus.NEW.value,
                title=(
                    "Argus Demo Bank wire-credentials offered for sale on "
                    "BreachForums (8.2K records)"
                ),
                summary=(
                    "Vendor 'darkvendor77' lists 8,217 employee credentials "
                    "from Argus Demo Bank for 1.5 BTC; sample row matches "
                    "an active SSO username. Posted four hours ago, 2.4k "
                    "views, 18 replies asking about banking services."
                ),
                confidence=0.91,
                matched_entities={
                    "organization name": "Argus Demo Bank",
                    "username sample": "matches active SSO directory",
                },
                recommended_actions=[
                    "Force credential rotation for the matched account",
                    "Open IR case and review recent SSO logins",
                ],
                agent_reasoning="Strong match on org name + SSO username sample.",
            ),
            _AlertModel(
                organization_id=org_id,
                category=ThreatCategory.RANSOMWARE_VICTIM.value,
                severity=ThreatSeverity.HIGH.value,
                status=AlertStatus.NEW.value,
                title=(
                    "LockBit blog references unnamed 'major US bank' "
                    "matching Demo Bank profile"
                ),
                summary=(
                    "LockBit 3.0 leak site countdown post about a 'major US "
                    "regional bank, ~$8B AUM, NY-headquartered' fits the "
                    "Demo Bank profile within five candidate institutions."
                ),
                confidence=0.74,
                matched_entities={"profile": "regional bank, ~$8B AUM, NY"},
                recommended_actions=[
                    "Begin defensive posture review",
                    "Validate backup integrity",
                ],
                agent_reasoning=(
                    "Profile-only match — corroborate before raising severity."
                ),
            ),
        ]
        for a in synth:
            session.add(a)
        await session.flush()
        alerts = synth
    if not alerts:
        logger.info("    ↳ no critical/high alerts to investigate; skipping")
        return

    # Build a realistic completed trace for the first one. The thoughts /
    # tool calls / results match what the agent would actually produce
    # when running against the seeded data — same actor names, IOCs,
    # alert wording.
    primary = alerts[0]
    completed = Investigation(
        organization_id=primary.organization_id,
        alert_id=primary.id,
        status=InvestigationStatus.COMPLETED.value,
        severity_assessment="critical",
        final_assessment=(
            f"This alert is corroborated by independent dark-web chatter and "
            f"a known threat actor's TTP fingerprint. The matched entity "
            f"appears in two related alerts in the last 14 days, suggesting "
            f"an active campaign rather than a one-off. Recommend immediate "
            f"escalation and the actions below."
        ),
        correlated_iocs=[
            "exfil-eu.lazarus-c2.io",
            "203.0.113.42",
            "CVE-2024-3400",
        ],
        correlated_actors=["LockBit 3.0", "Lazarus Group"],
        recommended_actions=[
            "Block the C2 domains at perimeter (DNS sinkhole + EDR rule).",
            "Patch CVE-2024-3400 across the Palo Alto fleet within 24h.",
            "Rotate credentials for any account that touched the affected subdomain.",
            "Open a CRITICAL case and assign to on-call IR analyst.",
        ],
        iterations=4,
        trace=[
            {
                "iteration": 1,
                "thought": (
                    "Start by pulling the full alert record so I can see "
                    "matched entities, raw intel excerpt, and confidence."
                ),
                "tool": "lookup_alert",
                "args": {"alert_id": str(primary.id)},
                "result": {
                    "id": str(primary.id),
                    "title": primary.title,
                    "severity": primary.severity,
                    "category": primary.category,
                    "confidence": primary.confidence,
                },
            },
            {
                "iteration": 2,
                "thought": (
                    "The matched entities reference a domain. Check if "
                    "we already track it as an IOC and which threat "
                    "actor (if any) owns it."
                ),
                "tool": "search_iocs",
                "args": {"query": "lazarus", "limit": 5},
                "result": [
                    {
                        "type": "domain",
                        "value": "exfil-eu.lazarus-c2.io",
                        "confidence": 0.92,
                        "threat_actor": "Lazarus Group",
                        "sighting_count": 17,
                    }
                ],
            },
            {
                "iteration": 3,
                "thought": (
                    "Lazarus Group is the prime suspect. Pull their full "
                    "profile and known TTPs to anchor the verdict."
                ),
                "tool": "lookup_threat_actor",
                "args": {"alias": "Lazarus Group"},
                "result": {
                    "primary_alias": "Lazarus Group",
                    "aliases": ["Hidden Cobra", "APT38"],
                    "known_ttps": ["T1566.001", "T1059.003", "T1027", "T1041"],
                    "risk_score": 0.95,
                    "total_sightings": 64,
                },
            },
            {
                "iteration": 4,
                "thought": (
                    "Check for related alerts in the last 14 days to "
                    "tell a one-off from a campaign before finalising."
                ),
                "tool": "related_alerts",
                "args": {
                    "organization_id": str(primary.organization_id),
                    "category": primary.category,
                    "lookback_days": 14,
                    "limit": 5,
                },
                "result": [
                    {
                        "id": str(primary.id),
                        "title": primary.title,
                        "severity": primary.severity,
                    }
                ],
            },
        ],
        model_id="claude-sonnet-4-6",
        duration_ms=8420,
        started_at=ago(minutes=12),
        finished_at=ago(minutes=11),
    )
    session.add(completed)

    if len(alerts) >= 2:
        queued = Investigation(
            organization_id=alerts[1].organization_id,
            alert_id=alerts[1].id,
            status=InvestigationStatus.QUEUED.value,
        )
        session.add(queued)

    logger.info(
        "    ↳ 1 completed investigation (4 steps) + 1 queued investigation"
    )


# --- Example Brand Defender action -----------------------------------


@section("example brand-defender action (completed → takedown_now)")
async def _seed_example_brand_action(session: AsyncSession) -> None:
    """Hand-crafted BrandAction so the Brand Defender dashboard has a
    convincing demo run on first boot. Uses the seeded SuspectDomain
    (``argusdemo-secure.bank``, similarity 0.91) as the target.
    """
    from src.models.brand import SuspectDomain
    from src.models.brand_actions import (
        BrandAction,
        BrandActionRecommendation,
        BrandActionStatus,
    )

    if await already_seeded(session, BrandAction):
        logger.info("    ↳ brand actions already seeded; skipping")
        return

    suspect = (
        await session.execute(
            select(SuspectDomain).order_by(SuspectDomain.similarity.desc()).limit(1)
        )
    ).scalar()
    if suspect is None:
        logger.info("    ↳ no SuspectDomain to defend; skipping")
        return

    completed = BrandAction(
        organization_id=suspect.organization_id,
        suspect_domain_id=suspect.id,
        status=BrandActionStatus.COMPLETED.value,
        recommendation=BrandActionRecommendation.TAKEDOWN_NOW.value,
        recommendation_reason=(
            "Live probe classified the page as phishing (cloned login form), "
            "logo perceptual-hash match against the brand corpus is 0.93, "
            "and the domain was registered five days ago. All three signals "
            "independently support a takedown; subsidiary allowlist excludes."
        ),
        confidence=0.94,
        risk_signals=[
            "logo>0.85",
            "fresh<7d",
            "live-probe:phishing",
            "tld:.bank",
        ],
        suggested_partner="netcraft",
        iterations=4,
        trace=[
            {
                "iteration": 1,
                "thought": (
                    "Pull the SuspectDomain row to see similarity, age "
                    "indicators and DNS records."
                ),
                "tool": "get_suspect_domain",
                "args": {"suspect_domain_id": str(suspect.id)},
                "result": {
                    "domain": suspect.domain,
                    "similarity": float(suspect.similarity),
                    "permutation_kind": suspect.permutation_kind,
                    "is_resolvable": suspect.is_resolvable,
                    "first_seen_at": suspect.first_seen_at.isoformat()
                    if suspect.first_seen_at
                    else None,
                    "source": suspect.source,
                },
            },
            {
                "iteration": 2,
                "thought": (
                    "Did the live probe land? If so what verdict did the "
                    "classifier produce?"
                ),
                "tool": "get_live_probe",
                "args": {"suspect_domain_id": str(suspect.id)},
                "result": {
                    "probe_run": True,
                    "fetched_at": ago(hours=4).isoformat(),
                    "http_status": 200,
                    "final_url": f"https://{suspect.domain}/login",
                    "title": "Argus Demo Bank — Sign in",
                    "verdict": "phishing",
                    "classifier_name": "argus-phish-cls-v3",
                },
            },
            {
                "iteration": 3,
                "thought": (
                    "Logo similarity is the third independent signal; "
                    "high pHash distance + low ahash distance suggests a "
                    "near-pixel-perfect rip."
                ),
                "tool": "get_logo_matches",
                "args": {"suspect_domain_id": str(suspect.id)},
                "result": {
                    "matched": True,
                    "similarity": 0.93,
                    "phash_distance": 4,
                    "dhash_distance": 6,
                    "ahash_distance": 3,
                    "verdict": "match",
                },
            },
            {
                "iteration": 4,
                "thought": (
                    "Confirm this isn't a registered subsidiary before "
                    "filing — false-positive on a sister brand would burn "
                    "trust with the partner."
                ),
                "tool": "check_subsidiary_allowlist",
                "args": {
                    "domain": suspect.domain,
                    "organization_id": str(suspect.organization_id),
                },
                "result": {"on_allowlist": False},
            },
        ],
        model_id="claude-sonnet-4-6",
        duration_ms=6280,
        started_at=ago(minutes=22),
        finished_at=ago(minutes=21),
    )
    session.add(completed)
    logger.info(
        "    ↳ 1 completed brand action (recommendation=takedown_now, 4 steps)"
    )


# --- Example Case Copilot run ----------------------------------------


@section("example case-copilot run (suggestions ready to apply)")
async def _seed_example_copilot_run(session: AsyncSession) -> None:
    """One completed CaseCopilotRun on the system org's case so the
    case detail page has a Copilot panel populated on first boot.
    """
    from src.models.case_copilot import CaseCopilotRun, CopilotStatus
    from src.models.cases import Case

    if await already_seeded(session, CaseCopilotRun):
        logger.info("    ↳ copilot runs already seeded; skipping")
        return

    from src.core.tenant import get_system_org_id

    org_id = await get_system_org_id(session)
    case = (
        await session.execute(
            select(Case)
            .where(Case.organization_id == org_id)
            .order_by(Case.created_at.desc())
            .limit(1)
        )
    ).scalar()
    if case is None:
        logger.info("    ↳ no system-org case to assist; skipping")
        return

    run = CaseCopilotRun(
        organization_id=org_id,
        case_id=case.id,
        status=CopilotStatus.COMPLETED.value,
        summary=(
            "Critical SSO regression with active exploitation indicators. "
            "Two related dark-web mentions in the past 14 days suggest "
            "this is part of an active campaign rather than opportunistic. "
            "Recommend the operations and incident response steps below."
        ),
        confidence=0.88,
        timeline_events=[
            {
                "at": ago(hours=14).isoformat(),
                "source": "raw_intel",
                "text": "BreachForums post offering sample SSO credentials",
            },
            {
                "at": ago(hours=8).isoformat(),
                "source": "alert",
                "text": "Triage agent flagged the credentials match an active SSO username",
            },
            {
                "at": ago(hours=2).isoformat(),
                "source": "finding",
                "text": "Linked to this case as primary finding",
            },
        ],
        suggested_mitre_ids=["T1078", "T1110.003", "T1190"],
        draft_next_steps=[
            "Force credential rotation for the matched SSO account.",
            "Pull SSO and IdP login telemetry for the past 14 days.",
            "Open a parallel comms thread with Identity & Access team.",
            "Confirm the leak source and notify Legal if customer PII is exposed.",
            "Schedule a post-incident review window for next week.",
        ],
        similar_case_ids=[],
        iterations=4,
        trace=[
            {
                "iteration": 1,
                "thought": "Pull the case to anchor on its severity, tags, and findings count.",
                "tool": "get_case",
                "args": {"case_id": str(case.id)},
                "result": {
                    "title": case.title,
                    "severity": case.severity,
                    "state": case.state,
                    "tags": case.tags or [],
                    "findings_count": 1,
                },
            },
            {
                "iteration": 2,
                "thought": "Read the seed alert for category + matched_entities — drives MITRE selection.",
                "tool": "get_seed_alert",
                "args": {"case_id": str(case.id)},
                "result": {"primary_alert": {"category": "dark_web_mention", "severity": "critical"}},
            },
            {
                "iteration": 3,
                "thought": "Look for past closed cases on this org to anchor the analyst.",
                "tool": "find_similar_past_cases",
                "args": {
                    "organization_id": str(org_id),
                    "severity": "critical",
                    "limit": 5,
                },
                "result": [],
            },
            {
                "iteration": 4,
                "thought": "Map the alert category to MITRE techniques worth attaching.",
                "tool": "suggest_mitre_techniques",
                "args": {"category": "dark_web_mention", "limit": 5},
                "result": [
                    {"external_id": "T1078", "name": "Valid Accounts"},
                    {"external_id": "T1110.003", "name": "Password Spraying"},
                    {"external_id": "T1190", "name": "Exploit Public-Facing Application"},
                ],
            },
        ],
        model_id="claude-sonnet-4-6",
        duration_ms=5910,
        started_at=ago(minutes=14),
        finished_at=ago(minutes=13),
    )
    session.add(run)
    logger.info("    ↳ 1 completed copilot run on the system-org case")


# --- Example Threat Hunter run ---------------------------------------


@section("example threat-hunt run (weekly cadence sample)")
async def _seed_example_threat_hunt(session: AsyncSession) -> None:
    """One completed ThreatHuntRun against the system org so the
    Threat Hunter dashboard tab has data on first boot.
    """
    from src.models.intel import ThreatActor
    from src.models.threat_hunts import HuntStatus, ThreatHuntRun

    if await already_seeded(session, ThreatHuntRun):
        logger.info("    ↳ threat hunt runs already seeded; skipping")
        return

    from src.core.tenant import get_system_org_id

    org_id = await get_system_org_id(session)
    actor = (
        await session.execute(
            select(ThreatActor)
            .where(ThreatActor.primary_alias == "LockBit 3.0")
            .limit(1)
        )
    ).scalar()
    if actor is None:
        actor = (await session.execute(select(ThreatActor).limit(1))).scalar()
    if actor is None:
        logger.info("    ↳ no threat actors to hunt; skipping")
        return

    run = ThreatHuntRun(
        organization_id=org_id,
        primary_actor_id=actor.id,
        primary_actor_alias=actor.primary_alias,
        status=HuntStatus.COMPLETED.value,
        summary=(
            f"Weekly hunt focused on {actor.primary_alias}: cross-checked their "
            f"known TTPs against our open exposures, recent alerts and tracked "
            f"IOCs. Two findings warrant SOC attention this week — see below."
        ),
        confidence=0.82,
        findings=[
            {
                "title": "Open RCE exposure aligns with LockBit's preferred entry vector",
                "description": (
                    "An open exposure on api.argusdemo.bank matches the "
                    "category LockBit affiliates exploited in three of the "
                    "last five attributed incidents (T1190 — exploit "
                    "public-facing application)."
                ),
                "relevance": 0.86,
                "mitre_ids": ["T1190"],
                "ioc_ids": [],
                "recommended_action": (
                    "Patch CVE-2026-1001 within 24h; restrict the SSO "
                    "endpoint to known ASNs until the fix lands."
                ),
            },
            {
                "title": "Credential-spray noise on the help-desk endpoint",
                "description": (
                    "Three alerts in the last 30 days match the "
                    "T1110.003 password-spray fingerprint LockBit "
                    "affiliates use to seed initial access."
                ),
                "relevance": 0.71,
                "mitre_ids": ["T1110.003", "T1078"],
                "ioc_ids": [],
                "recommended_action": (
                    "Enforce step-up MFA on the help-desk console; "
                    "review the past 30 days of unsuccessful login telemetry."
                ),
            },
        ],
        iterations=5,
        trace=[
            {
                "iteration": 1,
                "thought": "Pick the most active actor cluster to anchor this week's hunt.",
                "tool": "pick_active_actor",
                "args": {},
                "result": {
                    "primary_alias": actor.primary_alias,
                    "known_ttps": actor.known_ttps,
                    "risk_score": actor.risk_score,
                },
            },
            {
                "iteration": 2,
                "thought": "Look at IOCs we already track for this actor — do any overlap our intel?",
                "tool": "search_iocs_by_actor",
                "args": {"actor_id": str(actor.id), "limit": 10},
                "result": [{"type": "domain", "value": "exfil-eu.lazarus-c2.io"}],
            },
            {
                "iteration": 3,
                "thought": "T1190 exploitation is part of the actor's TTPs — do we have open RCE exposures?",
                "tool": "find_org_exposures",
                "args": {
                    "organization_id": str(org_id),
                    "min_severity": "high",
                    "limit": 5,
                },
                "result": [
                    {
                        "severity": "critical",
                        "category": "vulnerability",
                        "title": "RCE in legacy SSO endpoint (CVE-2026-1001)",
                    }
                ],
            },
            {
                "iteration": 4,
                "thought": "T1110.003 password spraying — any alerts in that bucket lately?",
                "tool": "find_org_alerts_for_category",
                "args": {
                    "organization_id": str(org_id),
                    "category": "underground_chatter",
                    "lookback_days": 30,
                    "limit": 10,
                },
                "result": [
                    {"title": "Spray attempts on help-desk console", "severity": "medium"}
                ],
            },
            {
                "iteration": 5,
                "thought": "Confirm the MITRE coordinates so the SOC has detection guidance handy.",
                "tool": "get_mitre_techniques_by_ids",
                "args": {"external_ids": ["T1190", "T1110.003", "T1078"]},
                "result": [
                    {"external_id": "T1190", "name": "Exploit Public-Facing Application"},
                    {"external_id": "T1110.003", "name": "Password Spraying"},
                    {"external_id": "T1078", "name": "Valid Accounts"},
                ],
            },
        ],
        model_id="claude-sonnet-4-6",
        duration_ms=11430,
        started_at=ago(hours=6),
        finished_at=ago(hours=6) + timedelta(seconds=11),
    )
    session.add(run)
    logger.info(
        "    ↳ 1 completed hunt run (2 findings, 5-step trace)"
    )


# ----------------------------------------------------------------------
# Reset support
# ----------------------------------------------------------------------


async def _wipe_demo_data(session: AsyncSession) -> None:
    """Wipe every data table for a clean re-seed.

    Many of Argus's FKs to ``organizations`` are RESTRICT (no CASCADE),
    and global fixture tables (IOCs, MITRE, retention) need to go too.
    Rather than enumerate every dependent table by hand, we ask the
    information_schema for the public-schema table list and TRUNCATE
    them all in one CASCADE. ``alembic_version`` is preserved so the
    schema-version invariant survives the wipe.
    """
    from sqlalchemy import text

    rows = (
        await session.execute(
            text(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = 'public' AND tablename != 'alembic_version'"
            )
        )
    ).all()
    if not rows:
        return
    table_list = ", ".join(f'"{r[0]}"' for r in rows)
    await session.execute(
        text(f"TRUNCATE TABLE {table_list} RESTART IDENTITY CASCADE")
    )
    logger.info(f"  · TRUNCATE … CASCADE on {len(rows)} tables (--reset)")
