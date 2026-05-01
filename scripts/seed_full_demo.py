"""Argus full-stack demo seed (Audit H1).

One script that lights up every phase end-to-end. Runs against a
freshly-migrated DB and produces realistic-looking fixtures for the
dashboard / sales walkthrough:

- Bootstrap admin + analyst user
- Demo organisation + brand terms + assets across every type
- A handful of EASM discovery jobs in mixed states
- Exposure findings at every severity
- Suspect domains + live-probe findings
- Impersonation + fraud findings
- Card-leakage finding
- DLP policy + finding
- Security rating, vendor scorecard
- Cases + SLA policy + breach event
- Takedown ticket
- News feed + advisory

Usage::

    source scripts/test-env.sh   # or your prod-equivalent .env
    python -m scripts.seed_full_demo

The script is **idempotent**: re-running it on an already-seeded DB
short-circuits if the demo org already exists. Pass `--reset` to drop
the demo org and re-seed clean.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import cast

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import hash_password
from src.models.auth import User, UserRole
from src.models.brand import (
    BrandTerm, BrandTermKind, SuspectDomain, SuspectDomainSource, SuspectDomainState,
)
from src.models.cases import Case, CaseFinding, CaseSeverity, CaseState
from src.models.easm import DiscoveryFinding, FindingState
from src.models.exposures import (
    ExposureCategory, ExposureFinding, ExposureSeverity, ExposureSource, ExposureState,
)
from src.models.fraud import FraudFinding, FraudKind, FraudState
from src.models.leakage import (
    CardLeakageFinding, CardType, DlpFinding, DlpPolicy, LeakageState,
)
from src.models.news import (
    Advisory, AdvisorySeverity, AdvisoryState, FeedKind, NewsArticle, NewsFeed,
)
from src.models.onboarding import DiscoveryJob, DiscoveryJobKind, DiscoveryJobStatus
from src.models.ratings import RatingScope, SecurityRating
from src.models.sla import SlaPolicy, SlaSeverity, SlaBreachEvent
from src.models.social import (
    ImpersonationFinding, ImpersonationKind, ImpersonationState, SocialPlatform,
    VipProfile,
)
from src.models.takedown import (
    TakedownPartner, TakedownState, TakedownTargetKind, TakedownTicket,
)
from src.models.threat import Asset, Organization
from src.storage import database as _db


DEMO_ORG_NAME = "Argus Demo Bank"


def _refuse_in_production() -> None:
    """Adversarial audit D-4 — make it impossible to run this seed
    against a production database by accident.

    The script ships with literal demo passwords; the only safe place
    to apply it is a dev / sales-demo install. Both gates must be
    affirmative:

      * ``ARGUS_SEED_MODE`` is one of ``demo``/``realistic``/``stress``.
      * Either ``ARGUS_DEBUG=true`` or ``ARGUS_ENVIRONMENT != production``.
    """
    import os as _os

    seed_mode = (_os.environ.get("ARGUS_SEED_MODE") or "").strip().lower()
    env = (_os.environ.get("ARGUS_ENVIRONMENT") or "").strip().lower()
    debug = (_os.environ.get("ARGUS_DEBUG") or "").strip().lower() in ("1", "true", "yes")

    if seed_mode not in {"demo", "realistic", "stress"}:
        sys.stderr.write(
            "scripts/seed_full_demo.py refuses to run unless "
            "ARGUS_SEED_MODE is one of {demo, realistic, stress}.\n"
        )
        sys.exit(2)
    if env == "production" and not debug:
        sys.stderr.write(
            "scripts/seed_full_demo.py refuses to run when "
            "ARGUS_ENVIRONMENT=production. Set ARGUS_DEBUG=true on a "
            "non-prod database to override (DO NOT do this on prod).\n"
        )
        sys.exit(2)


async def _wipe_demo_org(session: AsyncSession) -> None:
    res = await session.execute(
        select(Organization).where(Organization.name == DEMO_ORG_NAME)
    )
    org = res.scalar_one_or_none()
    if org is None:
        return
    await session.execute(delete(Organization).where(Organization.id == org.id))
    await session.commit()
    print(f"  ↳ wiped existing org {org.id}")


async def _seed(session: AsyncSession) -> Organization:
    existing = (
        await session.execute(
            select(Organization).where(Organization.name == DEMO_ORG_NAME)
        )
    ).scalar_one_or_none()
    if existing is not None:
        print(f"  ↳ org already exists ({existing.id}); skipping")
        return existing

    now = datetime.now(timezone.utc)
    org = Organization(
        name=DEMO_ORG_NAME,
        domains=["argusdemo.bank", "argusdemo.cloud"],
        keywords=["argusdemo", "argus-bank"],
        industry="finance",
    )
    session.add(org)
    await session.flush()

    # --- users -------------------------------------------------------
    # Audit D-4 — generate fresh random passwords every seed run so the
    # repository never ships working credentials. Print once to stdout
    # so the demo operator can capture them.
    import secrets as _secrets

    admin_pwd = _secrets.token_urlsafe(18)
    analyst_pwd = _secrets.token_urlsafe(18)
    if not (await session.execute(select(User).where(User.email == "demo-admin@argus.test"))).scalar_one_or_none():
        session.add(User(
            email="demo-admin@argus.test",
            username="demo-admin",
            password_hash=hash_password(admin_pwd),
            display_name="Demo Admin",
            role=UserRole.ADMIN.value,
            is_active=True,
        ))
        session.add(User(
            email="demo-analyst@argus.test",
            username="demo-analyst",
            password_hash=hash_password(analyst_pwd),
            display_name="Demo Analyst",
            role=UserRole.ANALYST.value,
            is_active=True,
        ))
        print("============================================================")
        print("DEMO USERS (random passwords — copy now, shown only once):")
        print(f"  admin:    demo-admin@argus.test  /  {admin_pwd}")
        print(f"  analyst:  demo-analyst@argus.test  /  {analyst_pwd}")
        print("============================================================")

    # --- brand terms -------------------------------------------------
    session.add_all([
        BrandTerm(organization_id=org.id, kind=BrandTermKind.NAME.value, value="argusdemo"),
        BrandTerm(organization_id=org.id, kind=BrandTermKind.NAME.value, value="argus-bank"),
        BrandTerm(organization_id=org.id, kind=BrandTermKind.APEX_DOMAIN.value, value="argusdemo.bank"),
    ])

    # --- assets ------------------------------------------------------
    apex = Asset(
        organization_id=org.id, asset_type="domain", value="argusdemo.bank",
        details={"primary": True}, criticality="crown_jewel",
    )
    api = Asset(
        organization_id=org.id, asset_type="subdomain", value="api.argusdemo.bank",
        criticality="high",
    )
    session.add_all([apex, api])
    await session.flush()

    # --- EASM discovery jobs (mixed states) --------------------------
    session.add_all([
        DiscoveryJob(
            organization_id=org.id, asset_id=apex.id,
            kind=DiscoveryJobKind.SUBDOMAIN_ENUM.value, target="argusdemo.bank",
            status=DiscoveryJobStatus.SUCCEEDED.value,
            started_at=now - timedelta(hours=2), finished_at=now - timedelta(hours=1),
            result_summary={"new_findings": 3, "raw_count": 12},
        ),
        DiscoveryJob(
            organization_id=org.id, asset_id=api.id,
            kind=DiscoveryJobKind.HTTPX_PROBE.value, target="api.argusdemo.bank",
            status=DiscoveryJobStatus.QUEUED.value,
        ),
    ])
    session.add(DiscoveryFinding(
        organization_id=org.id, parent_asset_id=apex.id,
        asset_type="subdomain", value="staging.argusdemo.bank",
        confidence=0.9, discovered_via="subfinder",
        state=FindingState.NEW.value,
    ))

    # --- exposures across severities ---------------------------------
    for i, (sev, cat, title) in enumerate([
        (ExposureSeverity.CRITICAL, ExposureCategory.VULNERABILITY, "RCE in legacy SSO endpoint (CVE-2026-1001)"),
        (ExposureSeverity.HIGH, ExposureCategory.WEAK_CRYPTO, "TLS 1.0 enabled on api.argusdemo.bank"),
        (ExposureSeverity.MEDIUM, ExposureCategory.MISCONFIGURATION, "Server header leaks nginx version"),
        (ExposureSeverity.LOW, ExposureCategory.VERSION_DISCLOSURE, "X-Powered-By disclosed"),
        (ExposureSeverity.INFO, ExposureCategory.OTHER, "robots.txt references /admin"),
    ]):
        session.add(ExposureFinding(
            organization_id=org.id, asset_id=api.id,
            severity=sev.value, category=cat.value, state=ExposureState.OPEN.value,
            source=ExposureSource.NUCLEI.value, rule_id=f"demo-rule-{i}",
            title=title, target=f"https://api.argusdemo.bank/x{i}",
            matched_at=now - timedelta(days=i),
            last_seen_at=now,
            occurrence_count=1 + i,
        ))

    # --- brand: suspect domains + live probe -------------------------
    session.add(SuspectDomain(
        organization_id=org.id,
        domain="argusdemo-secure.bank",
        matched_term_value="argusdemo",
        similarity=0.91, permutation_kind="addition",
        is_resolvable=True, a_records=["203.0.113.42"],
        first_seen_at=now - timedelta(days=2), last_seen_at=now,
        state=SuspectDomainState.OPEN.value,
        source=SuspectDomainSource.DNSTWIST.value,
    ))

    # --- social impersonation + fraud --------------------------------
    vip = VipProfile(
        organization_id=org.id, full_name="Jane Doe", title="CFO, Argus Demo Bank",
        aliases=["Jane D."], bio_keywords=["CFO", "Argus Demo Bank"],
    )
    session.add(vip)
    await session.flush()
    session.add(ImpersonationFinding(
        organization_id=org.id, vip_profile_id=vip.id,
        kind=ImpersonationKind.EXECUTIVE.value, platform=SocialPlatform.TWITTER.value,
        candidate_handle="@janeargusbank", candidate_display_name="Jane Doe (CFO)",
        candidate_url="https://twitter.com/janeargusbank",
        name_similarity=0.95, handle_similarity=0.78, bio_similarity=0.6,
        photo_similarity=0.92, aggregate_score=0.86,
        signals=["name", "photo"], state=ImpersonationState.CONFIRMED.value,
        detected_at=now - timedelta(hours=6),
    ))
    session.add(FraudFinding(
        organization_id=org.id, kind=FraudKind.CRYPTO_GIVEAWAY.value,
        channel="telegram", target_identifier="@argusdemo_offers",
        title="Fake giveaway impersonating Argus Demo Bank",
        excerpt="Claim your $1,000 reward by submitting your card to ...",
        matched_brand_terms=["argusdemo"], score=0.88,
        state=FraudState.OPEN.value, detected_at=now,
    ))

    # --- card leakage + DLP ------------------------------------------
    session.add(CardLeakageFinding(
        organization_id=org.id,
        pan_first6="411111", pan_last4="4242",
        pan_sha256="0" * 64, card_type=CardType.CREDIT.value,
        scheme="visa",
        source_url="https://pastebin.example/leak/abc",
        source_kind="paste", excerpt="…leaked dump from breach …",
        state=LeakageState.OPEN.value, detected_at=now,
    ))
    policy = DlpPolicy(
        organization_id=org.id, name="Internal API key pattern",
        kind="regex",
        pattern=r"argusdemo_[A-Za-z0-9]{32}",
        severity="high",
    )
    session.add(policy)
    await session.flush()
    session.add(DlpFinding(
        organization_id=org.id, policy_id=policy.id,
        policy_name=policy.name, severity="high",
        matched_excerpts=["argusdemo_DEADBEEFDEADBEEFDEADBEEFDEADBEEF"],
        source_url="https://github.example/repo/blob/main/.env",
        state=LeakageState.OPEN.value, detected_at=now,
    ))

    # --- security rating + vendor scorecard --------------------------
    session.add(SecurityRating(
        organization_id=org.id, scope=RatingScope.ORGANIZATION.value,
        rubric_version="v1",
        score=72.5, grade="B", is_current=True,
        summary={"pillars": {"exposures": 65, "hygiene": 80, "governance": 78}},
        computed_at=now,
    ))

    # --- SLA policy + breach + case ---------------------------------
    session.add(SlaPolicy(
        organization_id=org.id,
        severity=SlaSeverity.CRITICAL.value,
        first_response_minutes=30, remediation_minutes=240,
    ))
    case = Case(
        organization_id=org.id,
        title="CVE-2026-1001 active exploitation in production",
        summary="Critical SSO endpoint flaw being exploited; rotate keys + patch.",
        severity=CaseSeverity.CRITICAL.value, state=CaseState.IN_PROGRESS.value,
        primary_asset_id=api.id, tags=["sso", "exploit"],
    )
    session.add(case)
    await session.flush()
    session.add(SlaBreachEvent(
        organization_id=org.id, case_id=case.id,
        kind="first_response", severity=SlaSeverity.CRITICAL.value,
        threshold_minutes=30,
        detected_at=now - timedelta(minutes=15),
    ))

    # --- takedown ----------------------------------------------------
    session.add(TakedownTicket(
        organization_id=org.id,
        target_identifier="argusdemo-secure.bank",
        target_kind=TakedownTargetKind.SUSPECT_DOMAIN.value,
        partner=TakedownPartner.NETCRAFT.value,
        state=TakedownState.SUBMITTED.value,
        submitted_at=now - timedelta(hours=4),
    ))

    # --- news + advisory --------------------------------------------
    feed = NewsFeed(
        organization_id=org.id,
        name="CISA KEV", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog/feed",
        kind=FeedKind.RSS.value, enabled=True,
    )
    session.add(feed)
    await session.flush()
    import hashlib as _hashlib
    article_url = "https://www.cisa.gov/news/argus-cve-2026-1001"
    session.add(NewsArticle(
        feed_id=feed.id,
        title="CISA adds CVE-2026-1001 to KEV catalog",
        url=article_url,
        url_sha256=_hashlib.sha256(article_url.encode("utf-8")).hexdigest(),
        summary="Argus Demo Bank SSO RCE actively exploited.",
        cve_ids=["CVE-2026-1001"],
        published_at=now - timedelta(hours=8),
        fetched_at=now,
    ))
    session.add(Advisory(
        organization_id=org.id, slug="argus-2026-001",
        title="Internal advisory: critical SSO regression",
        body_markdown="# Summary\n\nKey rotation required by EOD.\n",
        severity=AdvisorySeverity.HIGH.value, state=AdvisoryState.PUBLISHED.value,
        cve_ids=["CVE-2026-1001"], tags=["sso"],
        published_at=now,
    ))

    await session.commit()
    print(f"  ↳ seeded org {org.id}")
    return org


async def main(reset: bool) -> int:
    await _db.init_db()
    if _db.async_session_factory is None:
        print("init_db did not populate session factory", file=sys.stderr)
        return 1
    async with _db.async_session_factory() as session:
        if reset:
            print("=== Wiping demo org ===")
            await _wipe_demo_org(session)
        print("=== Seeding demo data ===")
        await _seed(session)
    print("=== Done ===")
    return 0


if __name__ == "__main__":
    _refuse_in_production()
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true",
                        help="wipe the demo org before seeding")
    args = parser.parse_args()
    sys.exit(asyncio.run(main(args.reset)))
