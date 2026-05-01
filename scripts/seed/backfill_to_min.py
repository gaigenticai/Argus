"""Backfill every table that the realistic seed left under the demo
threshold (≥10 rows) with FK-correct, semantically realistic data.

The realistic seed was authored when several tables didn't yet exist
(P1 #1.3 compliance, P2 #2.12 D3FEND/OSCAL, P3 #3.4 feed subscriptions)
and a handful of older tables only got a few seed rows. For demo /
QA purposes the founder wants ≥10 rows in every table — this module
audits every table and tops it up where needed, idempotently.

Singleton-by-design tables are exempt:
  - alembic_version (one row per deployment)
  - global_threat_status (operator-managed singleton)

Everything else gets at least 10 realistic rows. FK relationships are
honored — every row points at real parent rows that already exist (or
are created here in topological order: orgs → users → cases/alerts →
everything else).

Idempotent: re-running is safe — each section counts existing rows and
only inserts the delta needed to reach the floor.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from scripts.seed._common import ago, deterministic_uuid, fake_sha256, logger, now, rng


_FLOOR = 10


# ── helpers ─────────────────────────────────────────────────────────


async def _count(session: AsyncSession, table: str) -> int:
    res = await session.execute(text(f"SELECT count(*) FROM {table}"))
    return int(res.scalar_one())


async def _need(session: AsyncSession, table: str, floor: int = _FLOOR) -> int:
    have = await _count(session, table)
    return max(floor - have, 0)


async def _first_org_id(session: AsyncSession) -> uuid.UUID:
    """The single 'system' org for single-tenant deployments — used as
    the default for any FK that requires an org."""
    res = await session.execute(text(
        "SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1"
    ))
    row = res.scalar_one_or_none()
    if row is None:
        raise RuntimeError("no organization rows; run realistic seed first")
    return row


async def _all_org_ids(session: AsyncSession) -> list[uuid.UUID]:
    res = await session.execute(text(
        "SELECT id FROM organizations ORDER BY created_at ASC"
    ))
    return [r[0] for r in res]


async def _all_user_ids(session: AsyncSession) -> list[uuid.UUID]:
    res = await session.execute(text(
        "SELECT id FROM users ORDER BY created_at ASC"
    ))
    return [r[0] for r in res]


async def _admin_user_id(session: AsyncSession) -> uuid.UUID | None:
    res = await session.execute(text(
        "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    ))
    return res.scalar_one_or_none()


# ── per-table backfill functions ────────────────────────────────────


async def _backfill_organizations(session: AsyncSession) -> int:
    need = await _need(session, "organizations")
    if not need:
        return 0
    samples = [
        ("Argus Demo Bank", "finance",
         ["argusdemobank.com"], ["argus", "demo bank"]),
        ("Spire Solutions", "consulting",
         ["spire-solutions.example"], ["spire"]),
        ("Mubadala Capital", "finance",
         ["mubadala-capital.example"], ["mubadala"]),
        ("Saudi Telecom Co.", "telecoms",
         ["stc.example"], ["stc"]),
        ("Aramco IT", "energy",
         ["aramco-it.example"], ["aramco"]),
        ("ADNOC Distribution", "energy",
         ["adnoc-distribution.example"], ["adnoc"]),
        ("Emirates Group", "transportation",
         ["emirates-group.example"], ["emirates"]),
        ("DEWA Smart Grid", "utilities",
         ["dewa-smart.example"], ["dewa"]),
        ("Qatar National Bank", "finance",
         ["qnb.example"], ["qnb"]),
        ("Kuwait Petroleum", "energy",
         ["kuwait-petroleum.example"], ["kpc"]),
        ("Bahrain Telecom", "telecoms",
         ["batelco.example"], ["batelco"]),
        ("Oman Air", "transportation",
         ["omanair.example"], ["oman air"]),
    ]
    inserted = 0
    for name, industry, domains, keywords in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM organizations WHERE name = :n"
        ), {"n": name})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO organizations (id, name, domains, keywords, industry,
                                        tech_stack, settings, created_at, updated_at)
            VALUES (:id, :name, :domains, :keywords, :industry,
                    :tech_stack, :settings, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "name": name, "domains": domains,
            "keywords": keywords, "industry": industry,
            "tech_stack": json.dumps({"cloud": "aws", "siem": "splunk"}),
            "settings": json.dumps({"locale": "en", "timezone": "Asia/Riyadh"}),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_users(session: AsyncSession) -> int:
    need = await _need(session, "users")
    if not need:
        return 0
    # Argon2 hash for "ArgusDemo123!" — frozen so seeded users can
    # actually log in for demos.
    pw_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$ZGVtby1zYWx0LWZyb3plbg"
        "$qX5sDtRbAfM2KcwvRHEwTVR7xZkNl0VAKXBwYRAj9w8"
    )
    samples = [
        ("admin@argus.demo", "admin", "Admin User", "admin"),
        ("analyst@argus.demo", "analyst", "Senior Analyst", "analyst"),
        ("alice.l1@argus.demo", "alice_l1", "Alice (L1 SOC)", "analyst"),
        ("bob.l2@argus.demo", "bob_l2", "Bob (L2 SOC)", "analyst"),
        ("carol.l3@argus.demo", "carol_l3", "Carol (L3 SOC)", "analyst"),
        ("dave.threat@argus.demo", "dave_threat",
         "Dave (Threat Intel)", "analyst"),
        ("eve.brand@argus.demo", "eve_brand",
         "Eve (Brand Defender)", "analyst"),
        ("frank.viewer@argus.demo", "frank_viewer",
         "Frank (CISO Viewer)", "viewer"),
        ("grace.dpo@argus.demo", "grace_dpo",
         "Grace (DPO Viewer)", "viewer"),
        ("henry.audit@argus.demo", "henry_audit",
         "Henry (Audit Viewer)", "viewer"),
        ("ivan.compliance@argus.demo", "ivan_compliance",
         "Ivan (Compliance)", "analyst"),
        ("julie.ir@argus.demo", "julie_ir",
         "Julie (Incident Response)", "analyst"),
    ]
    inserted = 0
    for email, username, display, role in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM users WHERE email = :e OR username = :u"
        ), {"e": email, "u": username})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO users (id, email, username, password_hash, display_name,
                                role, is_active, last_login_at,
                                created_at, updated_at)
            VALUES (:id, :email, :username, :pw, :display, :role, true,
                    :last_login, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "email": email, "username": username,
            "pw": pw_hash, "display": display, "role": role,
            "last_login": ago(hours=rng.randint(1, 72)),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_api_keys(session: AsyncSession) -> int:
    need = await _need(session, "api_keys")
    if not need:
        return 0
    user_ids = await _all_user_ids(session)
    if not user_ids:
        return 0
    inserted = 0
    for i in range(need):
        prefix = f"argus_{i:02d}"
        raw = secrets.token_hex(20)
        await session.execute(text("""
            INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix,
                                   is_active, last_used_at, expires_at,
                                   created_at, updated_at)
            VALUES (:id, :uid, :name, :hash, :prefix, true,
                    :last_used, :expires, :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "uid": user_ids[i % len(user_ids)],
            "name": f"Demo SDK key #{i+1}",
            "hash": hashlib.sha256(raw.encode()).hexdigest(),
            "prefix": prefix[:8],
            "last_used": ago(hours=rng.randint(1, 240)),
            "expires": now() + timedelta(days=365),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_news_feeds(session: AsyncSession) -> int:
    need = await _need(session, "news_feeds")
    if not need:
        return 0
    samples = [
        ("CISA Advisories", "https://www.cisa.gov/news.xml", "rss",
         ["advisory", "us-gov"]),
        ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
         "rss", ["advisory", "uk-gov"]),
        ("ENISA Insights", "https://www.enisa.europa.eu/news/rss",
         "rss", ["advisory", "eu"]),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/",
         "rss", ["news", "infosec"]),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews",
         "rss", ["news"]),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/",
         "rss", ["blog", "investigative"]),
        ("Saudi NCA Bulletins", "https://nca.gov.sa/feed.rss",
         "rss", ["advisory", "ksa-gov"]),
        ("UAE TDRA", "https://tdra.gov.ae/cyber-bulletins.xml",
         "rss", ["advisory", "uae-gov"]),
        ("Group-IB Blog", "https://group-ib.com/feed.xml",
         "rss", ["vendor", "intel"]),
        ("Mandiant Threat Intel", "https://www.mandiant.com/resources/blog/rss.xml",
         "rss", ["vendor", "intel"]),
        ("Recorded Future", "https://www.recordedfuture.com/feed",
         "rss", ["vendor", "intel"]),
        ("ThreatPost", "https://threatpost.com/feed/",
         "rss", ["news"]),
    ]
    inserted = 0
    for name, url, kind, tags in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM news_feeds WHERE url = :u AND organization_id IS NULL"
        ), {"u": url})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO news_feeds (id, organization_id, name, url, kind,
                                     enabled, last_fetched_at, last_status,
                                     tags, created_at, updated_at)
            VALUES (:id, NULL, :name, :url, :kind, true,
                    :last_fetch, 'ok', :tags, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "name": name, "url": url, "kind": kind,
            "last_fetch": ago(hours=rng.randint(1, 24)),
            "tags": tags, "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_news_articles(session: AsyncSession) -> int:
    need = await _need(session, "news_articles")
    if not need:
        return 0
    res = await session.execute(text(
        "SELECT id FROM news_feeds ORDER BY created_at ASC LIMIT 5"
    ))
    feed_ids = [r[0] for r in res]
    samples = [
        ("CISA: ALPHV/BlackCat ransomware update", "T1486"),
        ("Microsoft patches CVE-2026-21420 zero-day in Windows", "T1190"),
        ("LockBit affiliate hits Saudi healthcare provider", "T1059.001"),
        ("Iranian APT MuddyWater pivots to GCC banks", "T1071.001"),
        ("Ivanti VPN exploited in Saudi telco breach", "T1190"),
        ("Predatory Sparrow disrupts Iranian gas distribution", "T1485"),
        ("Cyber Av3ngers claims water-utility OT attack in UAE", "T1486"),
        ("Citrix Bleed re-emerges with new exploit chain", "T1190"),
        ("Telegram leak channel publishes 200k GCC bank cards", "T1078"),
        ("Mandiant flags new Iranian phishing kit targeting Aramco", "T1566.002"),
        ("Cisco IOS XE wave-2 exploitation underway", "T1133"),
        ("AnonGhost claims DDoS on Israeli MoD", "T1498"),
    ]
    inserted = 0
    for i, (title, tech) in enumerate(samples):
        if inserted >= need:
            break
        url = f"https://news.demo/argus/{deterministic_uuid('news', title).hex[:12]}"
        sha = hashlib.sha256(url.encode()).hexdigest()
        existing = await session.execute(text(
            "SELECT 1 FROM news_articles WHERE url_sha256 = :s"
        ), {"s": sha})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO news_articles (id, url_sha256, url, feed_id, title,
                                        summary, author, published_at, fetched_at,
                                        cve_ids, tags, raw, created_at, updated_at)
            VALUES (:id, :sha, :url, :feed, :title, :summary, :author,
                    :published, :fetched, :cves, :tags, :raw, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "sha": sha, "url": url,
            "feed": feed_ids[i % len(feed_ids)] if feed_ids else None,
            "title": title,
            "summary": f"{title}. Tracked under MITRE {tech}.",
            "author": "Argus Curator",
            "published": ago(days=rng.randint(0, 14)),
            "fetched": ago(days=rng.randint(0, 14)),
            "cves": [f"CVE-2026-{1000+i:04d}"],
            "tags": ["gcc", tech.split(".")[0]],
            "raw": json.dumps({"technique": tech}),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_advisories(session: AsyncSession) -> int:
    need = await _need(session, "advisories")
    if not need:
        return 0
    admin_id = await _admin_user_id(session)
    samples = [
        ("alphv-resurgence", "ALPHV resurgence — affiliate spinoffs detected",
         "high"),
        ("muddywater-gcc-pivot",
         "MuddyWater pivots to GCC bank phishing", "high"),
        ("citrix-bleed-2",
         "Citrix Bleed wave-2: rotate sessions immediately", "critical"),
        ("ivanti-vpn-zero-day",
         "Ivanti VPN zero-day actively exploited", "critical"),
        ("ms-march-patch-tuesday",
         "Microsoft March Patch Tuesday — 3 zero-days", "high"),
        ("cyber-avengers-uae-water",
         "Cyber Av3ngers claim UAE water utility OT attack", "high"),
        ("anonghost-il-ddos",
         "AnonGhost coordinated DDoS on .il targets", "medium"),
        ("predatory-sparrow-ir",
         "Predatory Sparrow disrupts Iranian gas grid", "info"),
        ("lockbit-affiliate-saudi-health",
         "LockBit affiliate breaches Saudi healthcare provider",
         "high"),
        ("telegram-200k-gcc-cards",
         "Telegram channel posts 200k GCC bank card dump", "critical"),
        ("opc-ua-cve-2026-1234",
         "OPC UA stack CVE-2026-1234 — OT-relevant patch", "medium"),
        ("vmware-esxi-rce",
         "VMware ESXi RCE in pre-auth path", "critical"),
    ]
    inserted = 0
    for slug, title, severity in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM advisories WHERE slug = :s "
            "AND organization_id IS NULL"
        ), {"s": slug})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO advisories (id, organization_id, slug, title,
                                     body_markdown, severity, state, tags,
                                     cve_ids, "references", published_at,
                                     author_user_id, created_at, updated_at)
            VALUES (:id, NULL, :slug, :title, :body,
                    CAST(:sev AS advisory_severity),
                    'published', :tags, :cves, :refs,
                    :published, :author, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "slug": slug, "title": title,
            "body": f"# {title}\n\nDetails curated from public reporting.",
            "sev": severity,
            "tags": ["argus-curated", "gcc"],
            "cves": [f"CVE-2026-{rng.randint(1000, 9999)}"],
            "refs": ["https://argus.demo/intel/" + slug],
            "published": ago(days=rng.randint(0, 30)),
            "author": admin_id,
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_vip_targets(session: AsyncSession) -> int:
    need = await _need(session, "vip_targets")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    samples = [
        ("Sara Al-Mansoori", "CEO"),
        ("Mohammed Al-Saud", "CFO"),
        ("Fatima Khan", "CISO"),
        ("Ahmad Bin Rashid", "COO"),
        ("Layla Hussein", "VP Risk"),
        ("Khalid Al-Otaibi", "Head of Treasury"),
        ("Noura Al-Hashemi", "Chief Compliance Officer"),
        ("Omar Yousef", "Head of Wholesale Banking"),
        ("Rania Saad", "Chief Data Officer"),
        ("Tarek El-Masri", "Head of Cyber Defence"),
        ("Yasmine Bouzid", "Head of Branch Network"),
        ("Ziad Hadid", "VP Investments"),
    ]
    inserted = 0
    for i, (name, title) in enumerate(samples):
        if inserted >= need:
            break
        org = org_ids[i % len(org_ids)]
        local = name.lower().replace(" ", ".").replace("-", "")
        await session.execute(text("""
            INSERT INTO vip_targets (id, organization_id, name, emails,
                                      usernames, phone_numbers, keywords,
                                      created_at, updated_at)
            VALUES (:id, :org, :name, :emails, :usernames, :phones,
                    :kw, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "org": org, "name": name,
            "emails": [f"{local}@argusdemobank.com"],
            "usernames": [local],
            "phones": [f"+966{rng.randint(500000000, 599999999)}"],
            "kw": [name.split()[0].lower(), title.lower()],
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_vip_profiles(session: AsyncSession) -> int:
    need = await _need(session, "vip_profiles")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    pool = [
        "Sara Al-Mansoori", "Mohammed Al-Saud", "Fatima Khan",
        "Ahmad Bin Rashid", "Layla Hussein", "Khalid Al-Otaibi",
        "Noura Al-Hashemi", "Omar Yousef", "Rania Saad",
        "Tarek El-Masri", "Yasmine Bouzid", "Ziad Hadid",
    ]
    inserted = 0
    for i, name in enumerate(pool):
        if inserted >= need:
            break
        org = org_ids[i % len(org_ids)]
        existing = await session.execute(text(
            "SELECT 1 FROM vip_profiles WHERE organization_id = :o "
            "AND full_name = :n"
        ), {"o": org, "n": name})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO vip_profiles (id, organization_id, full_name, title,
                                       aliases, bio_keywords,
                                       photo_evidence_sha256s, photo_phashes,
                                       created_at, updated_at)
            VALUES (:id, :org, :name, :title, :aliases, :kw,
                    :sha, :ph, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "org": org, "name": name,
            "title": "Senior Executive",
            "aliases": [name.split()[0]],
            "kw": [name.split()[0].lower()],
            "sha": [fake_sha256("vip-photo-" + name)],
            "ph": [hashlib.md5(name.encode()).hexdigest()[:16]],
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_actor_playbooks(session: AsyncSession) -> int:
    need = await _need(session, "actor_playbooks")
    if not need:
        return 0
    samples = [
        ("LockBit 3.0", ["lockbit", "abcd"], ["finance", "healthcare"],
         ["GCC", "EU"], ["T1486", "T1490", "T1078"], 9.5),
        ("ALPHV/BlackCat", ["BlackCat", "ALPHV"], ["finance", "manufacturing"],
         ["GLOBAL"], ["T1486", "T1059.001"], 9.0),
        ("Cl0p", ["TA505 ransomware"], ["finance", "retail"],
         ["GLOBAL"], ["T1190", "T1486"], 8.8),
        ("RansomHub", ["RansomHub-affiliate"], ["healthcare", "energy"],
         ["GCC", "US"], ["T1486", "T1071.001"], 8.5),
        ("Akira", ["Akira-affiliate"], ["legal", "finance"],
         ["EU", "US"], ["T1486", "T1003.001"], 8.0),
        ("MuddyWater", ["TA450", "Mango Sandstorm"],
         ["finance", "telecom", "government"],
         ["GCC", "TR"], ["T1059.001", "T1078"], 9.2),
        ("Cyber Av3ngers", ["IRGC-affiliate"], ["water", "energy"],
         ["IL", "GCC"], ["T1486"], 9.4),
        ("Predatory Sparrow", ["Gonjeshke Darande"], ["energy"],
         ["IR"], ["T1485"], 8.7),
        ("Moses Staff", ["Cobalt Sapling"], ["consulting"],
         ["IL", "GCC"], ["T1486", "T1078"], 8.3),
        ("AnonGhost", ["pro-Palestine"], ["all"],
         ["IL", "GCC"], ["T1498", "T1499"], 6.5),
        ("Yemeni Cyber Army", ["Houthi-aligned"], ["maritime", "telecom"],
         ["SA", "AE"], ["T1498"], 6.0),
        ("APT34", ["OilRig", "Helix Kitten"], ["energy", "telecom"],
         ["GCC"], ["T1190", "T1078"], 9.6),
    ]
    inserted = 0
    for alias, aliases, sectors, geos, ttps, score in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM actor_playbooks WHERE actor_alias = :a "
            "AND organization_id IS NULL"
        ), {"a": alias})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO actor_playbooks (id, organization_id, actor_alias,
                                          description, aliases,
                                          targeted_sectors, targeted_geos,
                                          attack_techniques, associated_malware,
                                          infra_iocs, "references",
                                          risk_score, created_at, updated_at)
            VALUES (:id, NULL, :alias, :desc, :aliases, :sectors, :geos,
                    :ttps, :malware, :iocs, :refs, :score, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "alias": alias,
            "desc": f"Curated profile for {alias}.",
            "aliases": aliases, "sectors": sectors, "geos": geos,
            "ttps": ttps,
            "malware": [alias.lower().replace(" ", "_")],
            "iocs": [],
            "refs": ["https://attack.mitre.org/groups/"],
            "score": score, "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_retention_policies(session: AsyncSession) -> int:
    need = await _need(session, "retention_policies")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    presets = [
        (90, 365, 730, 365), (60, 180, 365, 180), (180, 730, 1095, 730),
        (30, 90, 365, 90), (120, 365, 730, 365), (45, 270, 730, 270),
        (90, 365, 1095, 365), (180, 365, 1095, 365),
        (60, 365, 730, 365), (30, 180, 365, 180),
        (90, 730, 1825, 730), (45, 90, 365, 90),
    ]
    inserted = 0
    for i, (raw_d, alert_d, audit_d, ioc_d) in enumerate(presets):
        if inserted >= need:
            break
        await session.execute(text("""
            INSERT INTO retention_policies (id, raw_intel_days, alerts_days,
                                             audit_logs_days, iocs_days,
                                             redact_pii, auto_cleanup_enabled,
                                             created_at, updated_at)
            VALUES (:id, :raw, :alert, :audit, :ioc, true, true, :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "raw": raw_d, "alert": alert_d,
            "audit": audit_d, "ioc": ioc_d,
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_webhook_endpoints(session: AsyncSession) -> int:
    need = await _need(session, "webhook_endpoints")
    if not need:
        return 0
    samples = [
        ("Slack #soc", "https://hooks.slack.com/services/T0000/B1111/AAAA",
         "slack", "high"),
        ("Slack #ciso", "https://hooks.slack.com/services/T0000/B2222/BBBB",
         "slack", "critical"),
        ("Splunk HEC", "https://splunk.demo:8088/services/collector",
         "siem", "low"),
        ("Sentinel webhook",
         "https://sentinel-eus.azure.example/webhook",
         "siem", "medium"),
        ("XSOAR ingest", "https://xsoar.demo/instance/execute/argus",
         "soar", "medium"),
        ("Tines story trigger",
         "https://argus.tines.com/webhook/abc123/secret",
         "soar", "high"),
        ("PagerDuty events",
         "https://events.pagerduty.com/v2/enqueue", "paging", "critical"),
        ("Generic SIEM", "https://siem.demo/argus", "generic", "low"),
        ("Email gateway hook",
         "https://email-gw.demo/argus-events", "email", "medium"),
        ("ServiceNow ticket bridge",
         "https://servicenow.demo/api/now/table/incident",
         "ticketing", "high"),
        ("Jira ticket bridge",
         "https://argus.atlassian.net/rest/api/3/issue",
         "ticketing", "high"),
        ("Custom analytics",
         "https://analytics.demo/ingest/argus", "generic", "low"),
    ]
    inserted = 0
    for name, url, kind, sev in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM webhook_endpoints WHERE url = :u"
        ), {"u": url})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO webhook_endpoints (id, name, url, endpoint_type,
                                            enabled, min_severity,
                                            failure_count, created_at,
                                            updated_at)
            VALUES (:id, :name, :url, :kind, true, :sev, 0, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "name": name, "url": url, "kind": kind,
            "sev": sev, "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_security_ratings(session: AsyncSession) -> int:
    need = await _need(session, "security_ratings")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    grades = ["A+", "A", "B", "C", "D", "F"]
    inserted = 0
    for i in range(need):
        org = org_ids[i % len(org_ids)]
        score = round(rng.uniform(60, 95), 2)
        grade = grades[min(int((100 - score) / 7), len(grades) - 1)]
        await session.execute(text("""
            INSERT INTO security_ratings (id, organization_id, scope,
                                           rubric_version, score, grade,
                                           is_current, summary, computed_at,
                                           created_at, updated_at)
            VALUES (:id, :org, CAST('organization' AS rating_scope), 'v1', :score,
                    CAST(:grade AS rating_grade), :is_cur,
                    CAST(:summary AS jsonb),
                    :computed, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "org": org,
            "score": score, "grade": grade,
            "is_cur": (i < len(org_ids)),
            "summary": json.dumps({
                "factors": ["patching", "mfa", "logging"],
                "computed_by": "argus-rubric-v1",
            }),
            "computed": ago(days=rng.randint(0, 30)),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_questionnaire_templates(session: AsyncSession) -> int:
    need = await _need(session, "questionnaire_templates")
    if not need:
        return 0
    samples = [
        ("SIG Lite v3", "sig_lite"),
        ("SIG Core v3", "sig_core"),
        ("CAIQ v4 — CSP self-assessment", "caiq_v4"),
        ("NCA-ECC vendor self-attestation", "custom"),
        ("SAMA TPRM baseline", "custom"),
        ("ADHICS vendor questionnaire", "custom"),
        ("PCI DSS 4.0 supplier", "custom"),
        ("ISO 27001 supplier annex", "custom"),
        ("HIPAA BAA addendum", "custom"),
        ("GDPR Article 28 processor", "custom"),
        ("CIS Controls IG1 vendor", "custom"),
        ("NIST CSF 2.0 third-party", "custom"),
    ]
    inserted = 0
    for name, kind in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM questionnaire_templates WHERE name = :n"
        ), {"n": name})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO questionnaire_templates (id, organization_id, name, kind,
                                                  description, questions,
                                                  is_active, created_at, updated_at)
            VALUES (:id, NULL, :name, CAST(:kind AS questionnaire_kind), :desc,
                    CAST(:questions AS jsonb), true, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "name": name, "kind": kind,
            "desc": f"{name} demo template",
            "questions": json.dumps([
                {"id": "q1", "text": "Do you have an information-security policy?",
                 "kind": "yesno"},
                {"id": "q2", "text": "Last pentest date?",
                 "kind": "date"},
                {"id": "q3", "text": "Encryption at rest?",
                 "kind": "yesno"},
            ]),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_triage_runs(session: AsyncSession) -> int:
    need = await _need(session, "triage_runs")
    if not need:
        return 0
    triggers = ["manual", "scheduled", "post_feed"]
    inserted = 0
    for i in range(need):
        await session.execute(text("""
            INSERT INTO triage_runs (id, trigger, hours_window,
                                      entries_processed, iocs_created,
                                      alerts_generated, duration_seconds,
                                      status, created_at, updated_at)
            VALUES (:id, :trig, :win, :proc, :iocs, :alerts, :dur,
                    'completed', :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "trig": triggers[i % len(triggers)],
            "win": rng.choice([1, 4, 8, 24]),
            "proc": rng.randint(50, 500),
            "iocs": rng.randint(5, 60),
            "alerts": rng.randint(0, 20),
            "dur": round(rng.uniform(4, 60), 2),
            "ts": ago(hours=rng.randint(1, 720)),
        })
        inserted += 1
    return inserted


async def _backfill_triage_feedback(session: AsyncSession) -> int:
    need = await _need(session, "triage_feedback")
    if not need:
        return 0
    res = await session.execute(text(
        "SELECT id FROM alerts ORDER BY created_at DESC LIMIT :n"
    ), {"n": need + 5})
    alerts = [r[0] for r in res]
    user_ids = await _all_user_ids(session)
    if not alerts or not user_ids:
        return 0
    cats = ["phishing", "malware", "credential_leak", "brand_impersonation"]
    inserted = 0
    for i in range(min(need, len(alerts))):
        is_tp = (i % 3 != 0)
        await session.execute(text("""
            INSERT INTO triage_feedback (id, alert_id, analyst_id,
                                          original_category, original_severity,
                                          original_confidence, corrected_category,
                                          corrected_severity, is_true_positive,
                                          feedback_notes, created_at, updated_at)
            VALUES (:id, :alert, :user, :cat, :sev, :conf,
                    :corrected_cat, :corrected_sev, :tp, :notes, :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "alert": alerts[i],
            "user": user_ids[i % len(user_ids)],
            "cat": cats[i % len(cats)], "sev": "high",
            "conf": round(rng.uniform(0.55, 0.95), 2),
            "corrected_cat": None if is_tp else cats[(i + 1) % len(cats)],
            "corrected_sev": None if is_tp else "medium",
            "tp": is_tp,
            "notes": "Confirmed TP." if is_tp else "Re-classified after analyst review.",
            "ts": ago(hours=rng.randint(1, 240)),
        })
        inserted += 1
    return inserted


async def _backfill_vulnerability_scans(session: AsyncSession) -> int:
    need = await _need(session, "vulnerability_scans")
    if not need:
        return 0
    targets = [
        "*.argusdemobank.com", "api.argusdemobank.com",
        "vpn.argusdemobank.com", "mail.argusdemobank.com",
        "*.spire-solutions.example", "portal.aramco-it.example",
        "auth.adnoc-distribution.example", "*.qnb.example",
        "*.stc.example", "*.dewa-smart.example",
        "*.batelco.example", "*.kuwait-petroleum.example",
    ]
    scanners = ["nuclei", "subfinder+httpx+nuclei", "testssl"]
    inserted = 0
    for i in range(need):
        await session.execute(text("""
            INSERT INTO vulnerability_scans (id, target, scanner, status,
                                              findings_count, started_at,
                                              completed_at, created_at, updated_at)
            VALUES (:id, :tgt, :sc, 'completed', :fc, :start, :end, :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "tgt": targets[i % len(targets)],
            "sc": scanners[i % len(scanners)],
            "fc": rng.randint(0, 12),
            "start": ago(hours=rng.randint(2, 240)),
            "end": ago(hours=rng.randint(1, 239)),
            "ts": ago(hours=rng.randint(1, 240)),
        })
        inserted += 1
    return inserted


async def _backfill_live_probes(session: AsyncSession) -> int:
    need = await _need(session, "live_probes")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    domains = [
        "argusdemo-bank.com", "argusdemobаnk.com",
        "argus-demo-bank.online", "argus.demobank.support",
        "argusdemo-bank-secure.com", "argus-bank-login.com",
        "argusdemobank.recovery", "online-argusdemobank.com",
        "verify-argusdemobank.com", "secure-argusdemobank.net",
        "argusdemobank-help.com", "argusdemobank-portal.com",
    ]
    verdicts = ["phishing", "suspicious", "benign", "phishing", "suspicious"]
    inserted = 0
    for i, dom in enumerate(domains):
        if inserted >= need:
            break
        await session.execute(text("""
            INSERT INTO live_probes (id, organization_id, domain, fetched_at,
                                      verdict, classifier_name, confidence,
                                      signals, matched_brand_terms, legal_hold,
                                      created_at, updated_at)
            VALUES (:id, :org, :d, :fetched,
                    CAST(:verdict AS live_probe_verdict),
                    'argus_classifier_v2', :conf, :sig, :brand, false,
                    :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "org": org_ids[i % len(org_ids)],
            "d": dom,
            "fetched": ago(hours=rng.randint(1, 240)),
            "verdict": verdicts[i % len(verdicts)],
            "conf": round(rng.uniform(0.55, 0.95), 2),
            "sig": ["typosquat", "brand-keyword"]
                    if "argus" in dom else ["benign-tld"],
            "brand": ["argus", "argusdemobank"],
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_logo_matches(session: AsyncSession) -> int:
    need = await _need(session, "logo_matches")
    if not need:
        return 0
    res = await session.execute(text(
        "SELECT id, organization_id FROM brand_logos LIMIT 5"
    ))
    logos = [(r[0], r[1]) for r in res]
    if not logos:
        return 0
    res = await session.execute(text(
        "SELECT id FROM live_probes ORDER BY created_at DESC LIMIT :n"
    ), {"n": need + 2})
    probes = [r[0] for r in res]
    verdicts = ["likely_abuse", "possible_abuse", "no_match"]
    inserted = 0
    for i in range(need):
        logo_id, org_id = logos[i % len(logos)]
        ph_d = rng.randint(2, 30)
        verdict = (verdicts[0] if ph_d <= 6
                   else verdicts[1] if ph_d <= 14 else verdicts[2])
        await session.execute(text("""
            INSERT INTO logo_matches (id, organization_id, brand_logo_id,
                                       suspect_domain_id, live_probe_id,
                                       candidate_image_sha256, phash_distance,
                                       dhash_distance, ahash_distance,
                                       color_distance, similarity, verdict,
                                       matched_at, created_at, updated_at)
            VALUES (:id, :org, :logo, NULL, :probe, :sha, :phd, :dhd, :ahd,
                    :cd, :sim, CAST(:verdict AS logo_match_verdict), :matched,
                    :ts, :ts)
        """), {
            "id": uuid.uuid4(), "org": org_id, "logo": logo_id,
            "probe": probes[i % len(probes)] if probes else None,
            "sha": fake_sha256(f"logo-candidate-{i}"),
            "phd": ph_d, "dhd": rng.randint(2, 30),
            "ahd": rng.randint(2, 30),
            "cd": round(rng.uniform(0.05, 0.6), 3),
            "sim": round(1.0 - ph_d / 64.0, 3),
            "verdict": verdict,
            "matched": ago(hours=rng.randint(1, 240)),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_external_ticket_bindings(session: AsyncSession) -> int:
    need = await _need(session, "external_ticket_bindings")
    if not need:
        return 0
    res = await session.execute(text(
        "SELECT id, organization_id FROM cases ORDER BY created_at DESC LIMIT :n"
    ), {"n": need + 5})
    cases = [(r[0], r[1]) for r in res]
    if not cases:
        return 0
    systems = ["jira", "servicenow", "github", "linear"]
    inserted = 0
    for i in range(need):
        case_id, org_id = cases[i % len(cases)]
        sys_choice = systems[i % len(systems)]
        await session.execute(text("""
            INSERT INTO external_ticket_bindings (id, organization_id, case_id,
                                                   system, external_id,
                                                   created_at, updated_at)
            VALUES (:id, :org, :case, CAST(:sys AS ticket_system), :ext, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "org": org_id, "case": case_id,
            "sys": sys_choice,
            "ext": f"{sys_choice.upper()[:3]}-{1000 + i}",
            "ts": ago(days=rng.randint(0, 30)),
        })
        inserted += 1
    return inserted


async def _backfill_organization_agent_settings(session: AsyncSession) -> int:
    need = await _need(session, "organization_agent_settings")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    inserted = 0
    for org in org_ids:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM organization_agent_settings WHERE organization_id = :o"
        ), {"o": org})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO organization_agent_settings
                (id, organization_id, investigation_enabled, brand_defender_enabled,
                 case_copilot_enabled, threat_hunter_enabled,
                 chain_investigation_to_hunt, auto_promote_critical,
                 auto_takedown_high_confidence, created_at, updated_at)
            VALUES (gen_random_uuid(), :org, true, true, true, true,
                    true, false, false, now(), now())
        """), {"org": org})
        inserted += 1
    return inserted


async def _backfill_subsidiary_allowlist(session: AsyncSession) -> int:
    need = await _need(session, "subsidiary_allowlist")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    samples = [
        ("domain", "argusdemobank-investments.com"),
        ("domain", "argusdemobank-securities.com"),
        ("domain", "argusdemobank-takaful.com"),
        ("domain", "argusdemobank-research.com"),
        ("domain", "argusdemobank-cards.com"),
        ("domain", "argusdemobank-fintech.com"),
        ("domain", "argusdemobank-academy.com"),
        ("domain", "argusdemobank-real-estate.com"),
        ("brand", "ArgusInvest"),
        ("brand", "ArgusSecurities"),
        ("brand", "ArgusTakaful"),
        ("brand", "ArgusFintech"),
    ]
    inserted = 0
    for kind, value in samples:
        if inserted >= need:
            break
        org = org_ids[inserted % len(org_ids)]
        existing = await session.execute(text(
            "SELECT 1 FROM subsidiary_allowlist "
            "WHERE organization_id = :o AND value = :v"
        ), {"o": org, "v": value})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO subsidiary_allowlist (id, organization_id, kind, value,
                                               created_at, updated_at)
            VALUES (:id, :org, :kind, :v, now(), now())
        """), {
            "id": uuid.uuid4(), "org": org, "kind": kind, "v": value,
        })
        inserted += 1
    return inserted


async def _backfill_attack_technique_attachments(
    session: AsyncSession,
) -> int:
    need = await _need(session, "attack_technique_attachments")
    if not need:
        return 0
    res = await session.execute(text(
        "SELECT id, organization_id FROM alerts ORDER BY created_at DESC LIMIT :n"
    ), {"n": need + 5})
    alerts = [(r[0], r[1]) for r in res]
    if not alerts:
        return 0
    techs = ["T1190", "T1078", "T1566.001", "T1566.002", "T1486",
             "T1490", "T1071.001", "T1059.001", "T1003.001", "T1547.001",
             "T1110.003", "T1485"]
    inserted = 0
    for i in range(need):
        alert_id, org_id = alerts[i % len(alerts)]
        await session.execute(text("""
            INSERT INTO attack_technique_attachments
                (id, organization_id, entity_type, entity_id, matrix,
                 technique_external_id, confidence, source, created_at, updated_at)
            VALUES (:id, :org, 'alert', :entity, 'enterprise', :tech, :conf,
                    CAST('triage_agent' AS attack_attachment_source), :ts, :ts)
        """), {
            "id": uuid.uuid4(), "org": org_id, "entity": alert_id,
            "tech": techs[i % len(techs)],
            "conf": round(rng.uniform(0.55, 0.95), 2),
            "ts": ago(hours=rng.randint(1, 240)),
        })
        inserted += 1
    return inserted


async def _backfill_hardening_recommendations(session: AsyncSession) -> int:
    need = await _need(session, "hardening_recommendations")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    samples = [
        ("Disable legacy SMBv1 protocol",
         "Block SMBv1 across the estate; downgrade attacks rely on it.",
         "high", ["CIS-9.1"], ["D3-NTA"], ["PR.AC-3"]),
        ("Enforce MFA on all VPN gateways",
         "Apply phishing-resistant MFA on every remote-access path.",
         "critical", ["CIS-6.5"], ["D3-MFA"], ["PR.AC-1"]),
        ("Patch Citrix Bleed CVE-2023-4966",
         "Rotate sessions after patching; older sessions remain vulnerable.",
         "critical", ["CIS-7.4"], ["D3-IPC"], ["DE.CM-8"]),
        ("Reject TLS 1.0 / 1.1",
         "Disable obsolete TLS versions on all customer-facing endpoints.",
         "medium", ["CIS-3.10"], ["D3-CH"], ["PR.DS-2"]),
        ("Rate-limit auth endpoints",
         "Protect login + password-reset against credential-stuffing.",
         "high", ["CIS-6.5"], ["D3-AL"], ["PR.AC-7"]),
        ("Rotate exposed AWS keys",
         "GitHub leakage findings name two keys still active in IAM.",
         "critical", ["CIS-3.11"], ["D3-CR"], ["PR.AC-1"]),
        ("Enable DMARC reject policy",
         "Currently p=quarantine; flip to p=reject after 30 days at quarantine.",
         "medium", ["CIS-9.7"], ["D3-DR"], ["PR.PT-3"]),
        ("Block port 22/3389 from internet",
         "EASM finds SSH/RDP exposed on three subsidiary IPs.",
         "high", ["CIS-12.1"], ["D3-NTA"], ["PR.AC-5"]),
        ("Enroll laptops in EDR",
         "12 laptops still report 'no EDR agent' in CrowdStrike Falcon.",
         "high", ["CIS-13.1"], ["D3-PA"], ["DE.CM-4"]),
        ("Enable WAF in front of online-banking app",
         "Add CloudFront / Cloudflare WAF managed-ruleset.",
         "medium", ["CIS-13.10"], ["D3-NTA"], ["PR.PT-1"]),
        ("Turn on S3 bucket public-access block",
         "Org-level guardrail prevents accidental public buckets.",
         "high", ["CIS-3.3"], ["D3-AC"], ["PR.AC-3"]),
        ("Restrict service accounts to least-privilege",
         "Two service accounts have AdministratorAccess; downscope.",
         "high", ["CIS-5.4"], ["D3-AC"], ["PR.AC-4"]),
    ]
    inserted = 0
    for title, summary, prio, cis, d3, csf in samples:
        if inserted >= need:
            break
        await session.execute(text("""
            INSERT INTO hardening_recommendations
                (id, organization_id, exposure_finding_id, title, summary,
                 cis_control_ids, d3fend_techniques, nist_csf_subcats,
                 priority, status, created_at, updated_at)
            VALUES (:id, :org, NULL, :title, :summary, :cis, :d3, :csf,
                    :prio, CAST('open' AS hardening_status), :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "org": org_ids[inserted % len(org_ids)],
            "title": title, "summary": summary,
            "cis": cis, "d3": d3, "csf": csf, "prio": prio,
            "ts": ago(days=rng.randint(0, 30)),
        })
        inserted += 1
    return inserted


# ── Compliance evidence + exports + mitre mitigations + feed subs ──


async def _backfill_compliance_evidence(session: AsyncSession) -> int:
    need = await _need(session, "compliance_evidence")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    res = await session.execute(text("""
        SELECT cc.id, cc.framework_id
          FROM compliance_controls cc
         ORDER BY random()
         LIMIT :n
    """), {"n": need})
    controls = [(r[0], r[1]) for r in res]
    if not controls:
        return 0
    res = await session.execute(text(
        "SELECT id FROM alerts ORDER BY created_at DESC LIMIT :n"
    ), {"n": need})
    alerts = [r[0] for r in res]
    inserted = 0
    for i in range(need):
        ctrl_id, fw_id = controls[i % len(controls)]
        await session.execute(text("""
            INSERT INTO compliance_evidence
                (id, organization_id, framework_id, control_id, source_kind,
                 source_id, captured_at, summary_en, summary_ar,
                 details, status, created_at, updated_at)
            VALUES (:id, :org, :fw, :ctrl, 'alert', :src, :captured,
                    :en, :ar, :details, 'active', :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "org": org_ids[i % len(org_ids)],
            "fw": fw_id, "ctrl": ctrl_id,
            "src": alerts[i % len(alerts)] if alerts else uuid.uuid4(),
            "captured": ago(days=rng.randint(0, 60)),
            "en": "Alert triaged + mitigated within SLA.",
            "ar": "تمت معالجة التنبيه ضمن اتفاقية مستوى الخدمة.",
            "details": json.dumps({"sla_hit": True, "ttr_minutes": rng.randint(5, 120)}),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_compliance_exports(session: AsyncSession) -> int:
    need = await _need(session, "compliance_exports")
    if not need:
        return 0
    org_ids = await _all_org_ids(session)
    res = await session.execute(text(
        "SELECT id FROM compliance_frameworks ORDER BY name_en LIMIT 4"
    ))
    fws = [r[0] for r in res]
    if not fws:
        return 0
    user_id = await _admin_user_id(session)
    modes = ["en", "ar", "bilingual"]
    inserted = 0
    for i in range(need):
        period_to = ago(days=rng.randint(0, 60))
        period_from = period_to - timedelta(days=90)
        await session.execute(text("""
            INSERT INTO compliance_exports
                (id, organization_id, framework_id, requested_by_user_id,
                 language_mode, format, period_from, period_to,
                 status, created_at, completed_at)
            VALUES (:id, :org, :fw, :user, :mode, 'pdf',
                    :pfrom, :pto, 'completed', :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "org": org_ids[i % len(org_ids)],
            "fw": fws[i % len(fws)],
            "user": user_id,
            "mode": modes[i % len(modes)],
            "pfrom": period_from, "pto": period_to,
            "ts": period_to,
        })
        inserted += 1
    return inserted


async def _backfill_mitre_mitigations(session: AsyncSession) -> int:
    need = await _need(session, "mitre_mitigations")
    if not need:
        return 0
    samples = [
        ("M1015", "Active Directory Configuration"),
        ("M1017", "User Training"),
        ("M1018", "User Account Management"),
        ("M1026", "Privileged Account Management"),
        ("M1027", "Password Policies"),
        ("M1030", "Network Segmentation"),
        ("M1031", "Network Intrusion Prevention"),
        ("M1032", "Multi-factor Authentication"),
        ("M1036", "Account Use Policies"),
        ("M1037", "Filter Network Traffic"),
        ("M1038", "Execution Prevention"),
        ("M1041", "Encrypt Sensitive Information"),
        ("M1042", "Disable or Remove Feature or Program"),
        ("M1043", "Credential Access Protection"),
        ("M1049", "Antivirus/Antimalware"),
        ("M1050", "Exploit Protection"),
    ]
    inserted = 0
    for ext_id, name in samples:
        if inserted >= need:
            break
        existing = await session.execute(text(
            "SELECT 1 FROM mitre_mitigations WHERE matrix='enterprise' "
            "AND external_id = :e"
        ), {"e": ext_id})
        if existing.scalar_one_or_none() is not None:
            continue
        await session.execute(text("""
            INSERT INTO mitre_mitigations
                (id, matrix, external_id, name, description, url,
                 sync_version, raw, created_at, updated_at)
            VALUES (:id, 'enterprise', :ext, :name, :desc, :url,
                    'argus-curated-1', :raw, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "ext": ext_id, "name": name,
            "desc": f"MITRE ATT&CK Enterprise mitigation {ext_id}: {name}.",
            "url": f"https://attack.mitre.org/mitigations/{ext_id}/",
            "raw": json.dumps({"source": "argus-curated"}),
            "ts": now(),
        })
        inserted += 1
    return inserted


async def _backfill_mitre_syncs(session: AsyncSession) -> int:
    need = await _need(session, "mitre_syncs")
    if not need:
        return 0
    inserted = 0
    user_id = await _admin_user_id(session)
    for i in range(need):
        await session.execute(text("""
            INSERT INTO mitre_syncs
                (id, matrix, source_url, sync_version, tactics_count,
                 techniques_count, subtechniques_count, mitigations_count,
                 deprecated_count, succeeded, error_message,
                 triggered_by_user_id, created_at, updated_at)
            VALUES (:id, 'enterprise',
                    'https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json',
                    :ver, 14, 200, 400, 42, 5, true, NULL, :u, :ts, :ts)
        """), {
            "id": uuid.uuid4(),
            "ver": f"v15.{i}-curated",
            "u": user_id,
            "ts": ago(days=i * 7),
        })
        inserted += 1
    return inserted


async def _backfill_feed_subscriptions(session: AsyncSession) -> int:
    need = await _need(session, "feed_subscriptions")
    if not need:
        return 0
    user_ids = await _all_user_ids(session)
    org = await _first_org_id(session)
    if not user_ids:
        return 0
    samples = [
        ("Critical phishing → SOC #soc",
         {"severity": ["critical", "high"], "category": ["phishing"]},
         [{"type": "webhook",
           "url": "https://hooks.slack.com/services/T0/B0/AAAA"}]),
        ("Credential leak → CISO",
         {"category": ["credential_leak"]},
         [{"type": "email", "address": "ciso@argus.demo"}]),
        ("Brand impersonation alerts",
         {"category": ["brand_impersonation"]},
         [{"type": "slack",
           "url": "https://hooks.slack.com/services/T0/B1/BBBB"}]),
        ("Iran-nexus actor sightings",
         {"tags_any": ["iran", "muddywater", "apt34"]},
         [{"type": "email", "address": "threatintel@argus.demo"}]),
        ("Ransomware leak posts",
         {"tags_any": ["lockbit", "alphv", "akira", "cl0p"]},
         [{"type": "webhook",
           "url": "https://soc.demo/argus-ransomware"}]),
        ("High-confidence DLP",
         {"category": ["data_leak"], "min_confidence": 0.7},
         [{"type": "email", "address": "dpo@argus.demo"}]),
        ("CVE patches in tech stack",
         {"title_regex": r"CVE-2026-\d+"},
         [{"type": "email", "address": "patch@argus.demo"}]),
        ("Mobile app abuse",
         {"category": ["mobile_app_abuse"]},
         [{"type": "slack",
           "url": "https://hooks.slack.com/services/T0/B2/CCCC"}]),
        ("Card BIN leakage",
         {"category": ["card_leakage"]},
         [{"type": "webhook",
           "url": "https://fraud.demo/argus"}]),
        ("Telegram leak posts",
         {"tags_any": ["telegram", "leak"]},
         [{"type": "email", "address": "oc-soc@argus.demo"}]),
        ("Critical only — exec digest",
         {"severity": ["critical"]},
         [{"type": "email", "address": "exec-digest@argus.demo"}]),
        ("KSA / SAMA-relevant alerts",
         {"tags_any": ["ksa", "sama", "saudi"]},
         [{"type": "webhook",
           "url": "https://compliance.demo/argus"}]),
    ]
    inserted = 0
    for i, (name, filt, channels) in enumerate(samples):
        if inserted >= need:
            break
        user_id = user_ids[i % len(user_ids)]
        await session.execute(text("""
            INSERT INTO feed_subscriptions
                (id, user_id, organization_id, name, description,
                 filter, channels, active, last_dispatched_at, last_error,
                 created_at, updated_at)
            VALUES (:id, :uid, :org, :name, :desc,
                    CAST(:filt AS jsonb),
                    CAST(:ch AS jsonb), true, :last, NULL, :ts, :ts)
        """), {
            "id": uuid.uuid4(), "uid": user_id, "org": org,
            "name": name, "desc": f"Demo subscription: {name}",
            "filt": json.dumps(filt),
            "ch": json.dumps(channels),
            "last": ago(hours=rng.randint(1, 240))
                     if i % 3 != 0 else None,
            "ts": now(),
        })
        inserted += 1
    return inserted


# ── Top-level dispatcher ───────────────────────────────────────────


_TASKS = [
    ("organizations", _backfill_organizations),
    ("users", _backfill_users),
    ("api_keys", _backfill_api_keys),
    ("organization_agent_settings", _backfill_organization_agent_settings),
    ("subsidiary_allowlist", _backfill_subsidiary_allowlist),
    ("vip_targets", _backfill_vip_targets),
    ("vip_profiles", _backfill_vip_profiles),
    ("retention_policies", _backfill_retention_policies),
    ("webhook_endpoints", _backfill_webhook_endpoints),
    ("security_ratings", _backfill_security_ratings),
    ("questionnaire_templates", _backfill_questionnaire_templates),
    ("triage_runs", _backfill_triage_runs),
    ("triage_feedback", _backfill_triage_feedback),
    ("vulnerability_scans", _backfill_vulnerability_scans),
    ("live_probes", _backfill_live_probes),
    ("logo_matches", _backfill_logo_matches),
    ("external_ticket_bindings", _backfill_external_ticket_bindings),
    ("attack_technique_attachments", _backfill_attack_technique_attachments),
    ("hardening_recommendations", _backfill_hardening_recommendations),
    ("actor_playbooks", _backfill_actor_playbooks),
    ("news_feeds", _backfill_news_feeds),
    ("news_articles", _backfill_news_articles),
    ("advisories", _backfill_advisories),
    ("mitre_mitigations", _backfill_mitre_mitigations),
    ("mitre_syncs", _backfill_mitre_syncs),
    ("compliance_evidence", _backfill_compliance_evidence),
    ("compliance_exports", _backfill_compliance_exports),
    ("feed_subscriptions", _backfill_feed_subscriptions),
]


async def run_backfill(session_factory: async_sessionmaker[AsyncSession]) -> dict[str, int]:
    """Run every backfill section. Returns a {table → rows_inserted} map."""
    out: dict[str, int] = {}
    async with session_factory() as session:
        for name, fn in _TASKS:
            try:
                inserted = await fn(session)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[backfill] %s skipped: %s: %s",
                    name, type(exc).__name__, exc,
                )
                inserted = 0
            out[name] = inserted
            if inserted:
                logger.info("[backfill] %s +%d", name, inserted)
            await session.commit()
    return out
