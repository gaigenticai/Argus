"""Augment Demo Bank with realistic alert volume.

The dashboard's KPI tiles pull from the system org (Demo Bank). The
realistic seed only creates 2 alerts there, so the dashboard reads
``2 / 1 / 2 / 0`` which reads as "no traffic" to a CIO. This module
adds ~25 additional alerts spread across all severities and statuses
(including a healthy resolved/closed bucket) so the tiles look like a
real production install.

Idempotent: short-circuits if Demo Bank already has 12+ alerts.

Two entry points:

  * ``augment_demo_bank_alerts(session)`` — call from another seed
    script (used by ``scripts.seed.realistic``).
  * ``python -m scripts._augment_demo_bank_alerts`` — standalone
    runner that opens its own session.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


def _refuse_in_production() -> None:
    seed_mode = (os.environ.get("ARGUS_SEED_MODE") or "").strip().lower()
    env = (os.environ.get("ARGUS_ENVIRONMENT") or "").strip().lower()
    debug = (os.environ.get("ARGUS_DEBUG") or "").strip().lower() in ("1", "true", "yes")
    if seed_mode not in {"demo", "realistic", "stress"}:
        sys.stderr.write("Refusing — set ARGUS_SEED_MODE.\n")
        sys.exit(2)
    if env == "production" and not debug:
        sys.stderr.write("Refusing — production env without ARGUS_DEBUG.\n")
        sys.exit(2)


_DEMO_BANK_NAME = "Argus Demo Bank"

# Mix tuned so the dashboard looks alive:
#   2 critical (immediate), 6 high, 9 medium, 6 low, 2 info
#   8 new, 5 triaged, 3 investigating, 4 confirmed,
#   8 resolved, 3 false_positive
ALERT_TEMPLATES = [
    # ── CRITICAL — actively-being-handled work ────────────────────────────
    ("critical", "investigating", "credential_leak",
     "Privileged ops mailbox auth tokens dumped on RAMP",
     "Vendor 'rampseller_prime' lists 1,184 OAuth tokens scoped to ops@argusdemo.bank including approved sender list and break-glass admin sessions. Sample row matches active Microsoft 365 token issued 2026-04-29.",
     0.94),
    ("critical", "confirmed", "ransomware_victim",
     "BlackCat ALPHV affiliate countdown — payment portal IOCs match Demo Bank",
     "Negotiation portal at dread.onion/blackcat lists a victim profile with $11.4B AUM, US east-coast HQ, Avaya CCaaS, and Workday HR — exact infrastructure fingerprint for Demo Bank.",
     0.91),

    # ── HIGH — split across triage stages ─────────────────────────────────
    ("high", "new", "phishing",
     "Lookalike domain argusdemo-loginsupport[.]bank registered 11h ago",
     "WhoisDS first-seen + DNStwist Levenshtein 1 from argusdemo.bank. Cloudflare-fronted, valid Let's Encrypt cert, Punycode variant of 'support'.",
     0.88),
    ("high", "triaged", "stealer_log",
     "Redline stealer log batch — 23 entries on argusdemo.bank corp domain",
     "Russian Market post offers 23 endpoint logs with active Outlook + corporate VPN tokens; sample preview shows active session for [redacted]@argusdemo.bank dated 2026-04-30 17:12 UTC.",
     0.86),
    ("high", "investigating", "brand_abuse",
     "Brand-impersonating Telegram channel @argusdemo_loans — 4.8K subs",
     "Channel impersonates Demo Bank's retail arm, pushes fake loan-pre-approval form harvesting SSN + DL via Google Forms. 187 net-new subs in 24h; admin handle on AlphaBay v2.",
     0.82),
    ("high", "resolved", "data_breach",
     "Aged ICICI/Demo-Bank 2024 breach record re-listed",
     "BreachForums 'data_phoenix' reposted the November 2024 dataset (acknowledged & disclosed). Treated as historical exposure; advised customers re-rotated post-original-incident.",
     0.71),
    ("high", "false_positive", "exploit",
     "0day broker advertises 'unauthenticated RCE' affecting 'major US east-coast bank'",
     "Cross-checked seller's prior CVE attributions against Demo Bank patch register. Description maps to a competitor's tech stack (Java + Liferay). Fingerprint confirmed mismatch.",
     0.42),
    ("high", "resolved", "doxxing",
     "Director-of-Treasury home address posted on doxbin",
     "Took down via Cloudflare abuse + direct doxbin operator. Replacement post seeded; Argus alerted physical-security retainer; family relocated 6 weeks pre-incident under retention policy. Closed.",
     0.95),

    # ── MEDIUM — ambient noise + active work ──────────────────────────────
    ("medium", "new", "dark_web_mention",
     "Demo Bank cited as 'mid-tier prey' in BreachForums recon thread",
     "Thread '$10B AUM East-Coast targets' lists Demo Bank #4 alongside three competitors. No active TTPs, just opportunistic reconnaissance discussion.",
     0.66),
    ("medium", "new", "underground_chatter",
     "XSS.is debate over Demo Bank's Plaid integration scope",
     "Russian-language thread speculates on Plaid + MX Aggregation token caching. Largely informational; Plaid responded directly on the platform.",
     0.58),
    ("medium", "triaged", "impersonation",
     "Fake LinkedIn recruiter targeting Demo Bank engineering staff",
     "Profile 'Hannah K. — Talent at Argus Demo Bank' identified in 14 outreach messages to senior engineers. Reverse-image hit: profile photo from Unsplash. Reported to LinkedIn.",
     0.74),
    ("medium", "triaged", "phishing",
     "SMS phishing wave — Demo Bank fraud-team caller-ID spoofing",
     "1,247 reports via /report-phish in last 6h. Numbers spoofed from internal fraud-line +1-800-DEMO-BNK; landing page on Cloudflare workers pulled within 90 min via partner.",
     0.79),
    ("medium", "investigating", "insider_threat",
     "Outbound scp from privileged dev workstation to personal Gmail Drive",
     "DLP triggered on 6.2 GB transfer over 4h; engineer claims SOC2 evidence backup. Assigned to insider-risk team for interview + chain-of-custody review.",
     0.68),
    ("medium", "confirmed", "access_sale",
     "AlphaBay v2 listing claims 'Citrix admin to mid-size US bank'",
     "Seller offers RDP + 14-day rotation. Demo Bank's Citrix is sunset since 2025-Q1 — listing likely targets a different victim, but marker created in case of revival.",
     0.61),
    ("medium", "resolved", "dark_web_mention",
     "Demo Bank careers page enumerated on RAMP for spear-phishing target list",
     "Bulk LinkedIn-scraped employee directory posted with department mapping. Coordinated with HR + LinkedIn legal; 71% of records redacted within 14d. Closed.",
     0.69),
    ("medium", "resolved", "phishing",
     "Brand-suffix typosquat argusdemo-secure[.]net suspended",
     "Live-probe captured cloned login portal; takedown filed via Netcraft on 2026-04-22, registrar suspended within 38h. Evidence vault: 6 screenshots, 3 HTML snapshots.",
     0.91),
    ("medium", "false_positive", "dark_web_mention",
     "Forum mention of 'Argus' resolves to Argus security.research, not Demo Bank",
     "Cross-org disambiguation: matched against subsidiary allowlist + brand-context classifier. 'Argus' here refers to the open-source TLS scanner. Closed.",
     0.31),

    # ── LOW — long-tail observability ─────────────────────────────────────
    ("low", "new", "underground_chatter",
     "Generic 'list of US fintechs' shared with Demo Bank named",
     "Aggregate listing of 312 firms by AUM. No active targeting; logged for trend analysis.",
     0.44),
    ("low", "triaged", "brand_abuse",
     "Twitter/X parody account @ArgusDemoBank_Reviews",
     "Satirical account, 2.1K followers. Reviewed under platform parody policy — not actionable. Monitoring quarterly.",
     0.39),
    ("low", "resolved", "phishing",
     "Phish kit advertising 'Bank of Argus' — defensive registration suggested",
     "Generic kit lists 50+ banks including misspelt Demo Bank brand. Marketing pre-registered the variants; no live infra observed. Closed.",
     0.51),
    ("low", "resolved", "underground_chatter",
     "Demo Bank's 2024 ESG report quoted on a finance-research Discord",
     "Public document; mentioned in a research peer-review channel. No exposure or threat. Closed for context.",
     0.27),
    ("low", "false_positive", "dark_web_mention",
     "Tor forum thread 'arguments demolish bank' — false brand-keyword hit",
     "NLP tokenizer split 'argument' + 'demo' + 'bank' as Demo Bank brand. Tuned suppression rule added to triage agent. Closed.",
     0.18),
    ("low", "resolved", "credential_leak",
     "Email-only leak — 4 employees on a 5-yr-old LinkedIn breach",
     "All four already in HIBP; no current credential exposure. Helpdesk reset historical password reuse across 2 accounts. Closed.",
     0.62),

    # ── INFO — health + signal-quality ──────────────────────────────────
    ("info", "resolved", "underground_chatter",
     "Quarterly threat-actor sweep — no new mentions",
     "Sweep across 47 monitored channels for '$11B AUM bank east-coast' returned zero matches for the quarter. Auto-generated baseline event.",
     0.95),
    ("info", "resolved", "dark_web_mention",
     "Test alert — Demo Bank bait keyword fired by canary post",
     "Internal red-team posted bait to a private testbed; verified end-to-end pipeline + dashboard latency at 7m12s. Closed.",
     0.99),
]


async def augment_demo_bank_alerts(session: AsyncSession) -> int:
    """Insert the realistic alert mix into Argus Demo Bank.

    Returns the number of alerts inserted. Re-running on a populated
    Demo Bank is a no-op (returns 0).
    """
    from src.models.threat import Alert, Organization

    org = (await session.execute(
        select(Organization).where(Organization.name == _DEMO_BANK_NAME)
    )).scalar_one_or_none()
    if not org:
        return 0
    existing = (await session.execute(
        select(func.count(Alert.id)).where(Alert.organization_id == org.id)
    )).scalar_one() or 0
    if existing >= 12:
        return 0

    # Deterministic seed so the timeline spread is reproducible across
    # fresh installs.
    rng = random.Random(0xA8DE0BA8)
    added = 0
    now = datetime.now(timezone.utc)
    for sev, status, category, title, summary, conf in ALERT_TEMPLATES:
        existing_title = (await session.execute(
            select(Alert.id).where(
                Alert.organization_id == org.id, Alert.title == title
            )
        )).scalar_one_or_none()
        if existing_title:
            continue
        offset_h = rng.randint(2, 720)  # 2h to 30d ago
        a = Alert(
            organization_id=org.id,
            category=category,
            severity=sev,
            status=status,
            title=title,
            summary=summary,
            confidence=conf,
            matched_entities={"brand": "Argus Demo Bank"},
            recommended_actions=[
                "Triage and assign to SOC L2",
                "Capture evidence to vault before takedown",
                "Cross-reference with active investigations",
            ],
            agent_reasoning=(
                f"Auto-classified by triage agent v2; matched on brand_terms + "
                f"tech_stack heuristics with confidence {conf:.2f}."
            ),
            analyst_notes=(
                "Closed — verified resolved per IR runbook." if status == "resolved"
                else "Suppressed — analyst confirmed false-positive after enrichment." if status == "false_positive"
                else "Active workstream; tracked in case workspace."
            ) if status in {"resolved", "false_positive"} else None,
            details={"triage_version": "2.1", "model": "claude-sonnet-4-6", "provider": "bridge"},
        )
        a.created_at = now - timedelta(hours=offset_h)
        session.add(a)
        added += 1
    await session.flush()
    return added


async def _main():
    from src.storage import database as _db

    await _db.init_db()
    if _db.async_session_factory is None:
        print("init_db failed", file=sys.stderr)
        sys.exit(1)
    async with _db.async_session_factory() as session:
        added = await augment_demo_bank_alerts(session)
        await session.commit()
        print(f"Added {added} alerts to Demo Bank.")


if __name__ == "__main__":
    _refuse_in_production()
    asyncio.run(_main())
