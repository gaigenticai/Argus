"""Harvester smoketest — confirm Marsad's free public-source
integrations actually surface signal for a given target organisation.

Pairs with ``scripts.seed.load_real_target`` (which loads e.g.
Emirates NBD as a verified eval target). After loading, run this:

    .venv/bin/python -m scripts.eval.harvester_smoketest --org "Emirates NBD"

For each integration, the script:
  1. Invokes the harvester's actual production entrypoint against the
     org's domains / brand terms.
  2. Captures: API reachable? rows returned? rows persisted? duration?
  3. Reports per-source status:
        OK    — surfaced N items (the integration works)
        EMPTY — reachable but 0 items (signal may genuinely not
                exist for this org, OR matcher is broken — needs
                eyeball)
        SKIP  — needs configuration we don't have (HIBP needs an
                email list; Telegram needs channel handles)
        ERROR — auth/rate-limit/crash. Fix this before demoing.

This is a *product validation* tool, not a parallel verifier. We use
the same code paths the live workers do, so a clean run here means the
dashboard will populate when the schedulers tick. A failure here
points at a real product bug, not a missing capability.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

# Register every model on Base.metadata before we touch the DB.
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

from src.models.brand import BrandTerm, BrandTermKind
from src.models.threat import Organization
from src.storage import database as _db
from src.storage.database import init_db


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING,  # quiet by default; we print our own report
    stream=sys.stdout,
)
logger = logging.getLogger("eval.harvester_smoketest")
logger.setLevel(logging.INFO)


# Status legend rendered in the report.
STATUS_OK = "OK"
STATUS_EMPTY = "EMPTY"
STATUS_SKIP = "SKIP"
STATUS_ERROR = "ERROR"

# ANSI colours so the terminal report is scannable. We degrade
# gracefully when stdout isn't a TTY (CI logs).
_TTY = sys.stdout.isatty()
def _c(text: str, color: str) -> str:
    if not _TTY:
        return text
    codes = {"green": "32", "yellow": "33", "red": "31", "grey": "90", "bold": "1"}
    return f"\x1b[{codes[color]}m{text}\x1b[0m"


@dataclass
class CheckResult:
    name: str
    status: str  # OK / EMPTY / SKIP / ERROR
    count: int = 0
    duration_ms: int = 0
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


# ---------- Helpers --------------------------------------------------------


@dataclass
class TargetContext:
    org: Organization
    domains: list[str]
    brand_term_names: list[str]
    breach_emails: list[str]
    telegram_channels: list[str]


async def _load_org(
    factory: async_sessionmaker[AsyncSession], name: str
) -> TargetContext:
    """Resolve the target org and pull every seed the smoketest needs."""
    async with factory() as db:
        org = (
            await db.execute(select(Organization).where(Organization.name == name))
        ).scalar_one_or_none()
        if org is None:
            raise SystemExit(
                f"Organisation {name!r} not found. Run scripts.seed.load_real_target first."
            )
        terms = (
            await db.execute(
                select(BrandTerm).where(
                    BrandTerm.organization_id == org.id,
                    BrandTerm.is_active.is_(True),
                )
            )
        ).scalars().all()
        settings = org.settings or {}
        domains = list(org.domains or [])
        name_terms = [
            t.value for t in terms if t.kind == BrandTermKind.NAME.value
        ]
        # Per-org seeds for HIBP + Telegram. Fall back to derive-from-
        # domains so smoketest still has something to test even on
        # legacy orgs that pre-date the load_real_target helper.
        breach_emails = list(settings.get("breach_check_emails") or [])
        if not breach_emails and domains:
            for d in domains:
                for lp in ("info", "support", "careers", "security"):
                    breach_emails.append(f"{lp}@{d}")
        telegram_channels = list(settings.get("telegram_monitor_channels") or [])
        if not telegram_channels:
            try:
                from src.integrations.telegram_collector.channels import (
                    list_active_channels,
                )
                telegram_channels = [
                    c.handle for c in list_active_channels()
                    if c.region_focus and "GCC" in (
                        r.upper() for r in c.region_focus
                    )
                ]
            except Exception:  # noqa: BLE001
                telegram_channels = []
        return TargetContext(
            org=org,
            domains=domains,
            brand_term_names=name_terms,
            breach_emails=breach_emails,
            telegram_channels=telegram_channels,
        )


async def _timed(coro) -> tuple[Any, int]:
    """Run a coroutine and return (result, elapsed_ms)."""
    t = time.monotonic()
    try:
        result = await coro
    finally:
        elapsed = int((time.monotonic() - t) * 1000)
    return result, elapsed


# ---------- Per-integration checks ----------------------------------------


async def check_ct_logs(brand_terms: list[str], domains: list[str]) -> CheckResult:
    """crt.sh (Certificate Transparency) — public, no auth."""
    name = "CT logs (crt.sh)"
    if not brand_terms and not domains:
        return CheckResult(name, STATUS_SKIP, detail="no brand terms or domains")
    try:
        from src.feeds.certstream_feed import CertStreamFeed

        keywords = tuple(brand_terms or domains)
        feed = CertStreamFeed(keywords=keywords)
        t0 = time.monotonic()
        entries = []
        # CertStreamFeed.poll yields FeedEntry objects — collect them.
        async for entry in feed.poll():
            entries.append(entry)
            if len(entries) >= 200:  # cap; crt.sh can be huge
                break
        elapsed = int((time.monotonic() - t0) * 1000)
        if entries:
            sample_val = entries[0].value
            return CheckResult(
                name, STATUS_OK, count=len(entries), duration_ms=elapsed,
                detail=f"e.g. {sample_val}",
            )
        return CheckResult(
            name, STATUS_EMPTY, duration_ms=elapsed,
            detail="0 cert hits — unusual for a known brand; check the keyword list",
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, STATUS_ERROR, detail=f"{type(e).__name__}: {e}")


async def check_phishing_feeds(
    factory: async_sessionmaker[AsyncSession], org_id: uuid.UUID
) -> CheckResult:
    """PhishTank + OpenPhish + URLhaus — public feeds, ingested through
    the production matcher so any hits also persist as suspect domains."""
    name = "Phishing feeds (PhishTank + OpenPhish + URLhaus)"
    try:
        from src.intel.phishing_feeds import (
            fetch_all_feeds,
            ingest_for_organization,
        )

        feeds, fetch_ms = await _timed(fetch_all_feeds())
        total_fetched = sum(len(v) for v in feeds.values())
        if total_fetched == 0:
            return CheckResult(
                name, STATUS_ERROR, duration_ms=fetch_ms,
                detail="all 3 feeds returned 0 entries — network or upstream outage",
            )
        async with factory() as db:
            reports, ingest_ms = await _timed(
                ingest_for_organization(db, org_id, feeds=feeds)
            )
            await db.commit()
        elapsed = fetch_ms + ingest_ms
        per_feed = {r.feed: r.matches_org_count for r in reports}
        total_matches = sum(per_feed.values())
        suspects_created = sum(r.suspects_created for r in reports)
        if total_matches > 0:
            return CheckResult(
                name, STATUS_OK, count=total_matches, duration_ms=elapsed,
                detail=f"{suspects_created} new suspect domain rows persisted",
                extra={"per_feed_matches": per_feed,
                       "fetched": {k: len(v) for k, v in feeds.items()}},
            )
        return CheckResult(
            name, STATUS_EMPTY, duration_ms=elapsed,
            detail=(
                f"fetched {total_fetched} phishing URLs but 0 matched the org's "
                "brand terms — may be true negative, or matcher tuning gap"
            ),
            extra={"fetched": {k: len(v) for k, v in feeds.items()}},
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, STATUS_ERROR, detail=f"{type(e).__name__}: {e}")


async def check_dnstwist(
    factory: async_sessionmaker[AsyncSession], org_id: uuid.UUID
) -> CheckResult:
    """dnstwist + DNS resolution — pure-python lookalike domain
    detection. Fully self-contained, no external API."""
    name = "Lookalike domains (dnstwist)"
    try:
        from src.brand.scanner import scan_organization

        async with factory() as db:
            report, elapsed = await _timed(scan_organization(db, org_id))
            await db.commit()
        return CheckResult(
            name,
            STATUS_OK if report.candidates_resolved > 0 else STATUS_EMPTY,
            count=report.suspects_created + report.suspects_seen_again,
            duration_ms=elapsed,
            detail=(
                f"{report.terms_scanned} terms → "
                f"{report.permutations_generated} permutations → "
                f"{report.candidates_resolved} resolved → "
                f"{report.suspects_created} new"
            ),
            extra={
                "terms_scanned": report.terms_scanned,
                "permutations_generated": report.permutations_generated,
                "candidates_resolved": report.candidates_resolved,
                "suspects_created": report.suspects_created,
                "suspects_seen_again": report.suspects_seen_again,
                "resolver_errors": report.resolver_errors,
            },
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, STATUS_ERROR, detail=f"{type(e).__name__}: {e}")


async def check_dns_dmarc(domains: list[str]) -> CheckResult:
    """DNS / SPF / DMARC posture via dnspython — no external API."""
    name = "DNS / SPF / DMARC"
    if not domains:
        return CheckResult(name, STATUS_SKIP, detail="org has no domains")
    try:
        from src.easm.runners import DnsRefreshRunner

        runner = DnsRefreshRunner()
        per_domain: dict[str, dict] = {}
        t0 = time.monotonic()
        for d in domains:
            out = await runner.run(d)
            if not out.succeeded:
                per_domain[d] = {"error": out.error_message}
                continue
            row = out.items[0] if out.items else {}
            per_domain[d] = {
                "a": len(row.get("a", [])),
                "mx": len(row.get("mx", [])),
                "ns": len(row.get("ns", [])),
                "spf": bool(row.get("spf")),
                "dmarc": bool(row.get("dmarc")),
            }
        elapsed = int((time.monotonic() - t0) * 1000)
        success = sum(1 for v in per_domain.values() if "error" not in v)
        if success == 0:
            return CheckResult(
                name, STATUS_ERROR, duration_ms=elapsed,
                detail=f"0 of {len(domains)} domains resolved",
                extra=per_domain,
            )
        return CheckResult(
            name, STATUS_OK, count=success, duration_ms=elapsed,
            detail=f"{success} of {len(domains)} domains resolved",
            extra=per_domain,
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, STATUS_ERROR, detail=f"{type(e).__name__}: {e}")


async def check_urlscan(domains: list[str]) -> CheckResult:
    """urlscan.io historical search. Free tier: 100 lookups/day."""
    name = "urlscan.io (historical scans)"
    if not domains:
        return CheckResult(name, STATUS_SKIP, detail="org has no domains")
    try:
        from src.enrichment.urlscan import search_recent, is_configured

        if not is_configured():
            return CheckResult(
                name, STATUS_SKIP,
                detail="ARGUS_URLSCAN_API_KEY not set (free signup at urlscan.io)",
            )
        per_domain: dict[str, int] = {}
        total = 0
        t0 = time.monotonic()
        for d in domains:
            r = await search_recent(d, limit=10)
            if r.success:
                hits = len(r.data.get("results", [])) if r.data else 0
                per_domain[d] = hits
                total += hits
            else:
                per_domain[d] = -1
        elapsed = int((time.monotonic() - t0) * 1000)
        if total == 0:
            return CheckResult(
                name, STATUS_EMPTY, duration_ms=elapsed,
                detail="0 historical scans found across all domains",
                extra=per_domain,
            )
        return CheckResult(
            name, STATUS_OK, count=total, duration_ms=elapsed,
            detail=f"{total} scans across {len(domains)} domains",
            extra=per_domain,
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, STATUS_ERROR, detail=f"{type(e).__name__}: {e}")


async def check_hibp(emails: list[str], *, max_lookups: int = 12) -> CheckResult:
    """HIBP — query each role-based email. Cap lookups so we don't
    burn an Enterprise key on a smoketest run; 12 covers 3 domains x
    4 role accounts which is plenty for a yes/no on 'integration works'."""
    name = "HIBP (Have I Been Pwned)"
    if not os.environ.get("ARGUS_HIBP_API_KEY"):
        return CheckResult(
            name, STATUS_SKIP,
            detail=(
                "ARGUS_HIBP_API_KEY not set (Enterprise tier required, "
                "$3.95/mo at haveibeenpwned.com/api)"
            ),
        )
    if not emails:
        return CheckResult(
            name, STATUS_SKIP,
            detail="no breach_check_emails seeded on org settings",
        )
    try:
        from src.integrations.breach.hibp import HibpProvider

        provider = HibpProvider()
        emails_to_check = emails[:max_lookups]
        per_email: dict[str, int | str] = {}
        total_breaches = 0
        emails_with_hits = 0
        errored = 0
        t0 = time.monotonic()
        for email in emails_to_check:
            r = await provider.search_email(email)
            if r.success:
                hits = len(r.hits)
                per_email[email] = hits
                if hits > 0:
                    emails_with_hits += 1
                    total_breaches += hits
            else:
                per_email[email] = f"err: {r.error or r.note or 'unknown'}"
                errored += 1
        elapsed = int((time.monotonic() - t0) * 1000)
        if errored == len(emails_to_check):
            return CheckResult(
                name, STATUS_ERROR, duration_ms=elapsed,
                detail=f"all {errored} HIBP lookups failed — check API key + rate limits",
                extra=per_email,
            )
        if emails_with_hits == 0:
            return CheckResult(
                name, STATUS_EMPTY, duration_ms=elapsed,
                detail=f"checked {len(emails_to_check)} role emails, 0 breaches found",
                extra=per_email,
            )
        return CheckResult(
            name, STATUS_OK, count=total_breaches, duration_ms=elapsed,
            detail=(
                f"{emails_with_hits} of {len(emails_to_check)} emails "
                f"in breach corpus — {total_breaches} total breach records"
            ),
            extra=per_email,
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, STATUS_ERROR, detail=f"{type(e).__name__}: {e}")


async def check_telegram(
    channels: list[str], brand_term_names: list[str], *, max_channels: int = 6
) -> CheckResult:
    """Scrape public Telegram channels via t.me/s/ web preview (no
    API key). For the smoketest we cap channels and stop early to keep
    runtime bounded; production worker iterates the full list per tick."""
    name = "Telegram public channels"
    if not channels:
        return CheckResult(
            name, STATUS_SKIP,
            detail=(
                "no telegram_monitor_channels seeded — "
                "check src/integrations/telegram_collector/channels.py "
                "or set Organization.settings.telegram_monitor_channels"
            ),
        )
    try:
        from src.crawlers.telegram_crawler import TelegramCrawler

        targets = channels[:max_channels]
        crawler = TelegramCrawler(channels=targets)
        t0 = time.monotonic()
        message_count = 0
        per_channel: dict[str, int] = {ch: 0 for ch in targets}
        brand_mentions = 0
        # Lowercase brand terms once for case-insensitive substring match.
        bt_lower = [b.lower() for b in brand_term_names]
        async for result in crawler.crawl():
            message_count += 1
            # Crawler's source_url is the message URL; channel handle
            # is encoded in the path. Cheap parse:
            url = result.source_url or ""
            for ch in targets:
                if f"/{ch}/" in url or url.endswith(f"/{ch}"):
                    per_channel[ch] += 1
                    break
            content = (result.content or "").lower()
            if any(bt in content for bt in bt_lower):
                brand_mentions += 1
            if message_count >= 200:  # cap; full pass is for the worker
                break
        elapsed = int((time.monotonic() - t0) * 1000)
        if message_count == 0:
            return CheckResult(
                name, STATUS_ERROR, duration_ms=elapsed,
                detail=(
                    f"0 messages parsed across {len(targets)} channels — "
                    "all channels unreachable, defunct, or t.me/s/ format changed"
                ),
                extra=per_channel,
            )
        # OK if we pulled messages; brand mentions are bonus signal.
        detail = (
            f"{message_count} messages across {len(targets)} channels"
        )
        if brand_mentions > 0:
            detail += f" — {brand_mentions} mention org brand terms"
        return CheckResult(
            name,
            STATUS_OK,
            count=message_count,
            duration_ms=elapsed,
            detail=detail,
            extra={"per_channel": per_channel, "brand_mentions": brand_mentions},
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, STATUS_ERROR, detail=f"{type(e).__name__}: {e}")


async def check_dark_web_crawlers() -> CheckResult:
    """Tor / I2P / Lokinet / forum / ransomware / stealer crawlers all
    need both a SOCKS proxy and a configured search-term/forum list.
    We don't try to invoke them in the smoketest because a misconfigured
    proxy hangs forever — manual smoketest territory."""
    name = "Dark-web crawlers (Tor / I2P / forum / ransomware / stealer / Matrix)"
    return CheckResult(
        name, STATUS_SKIP,
        detail=(
            "needs SOCKS proxy + per-crawler seed config. Verify wiring "
            "from `/feeds` page in the dashboard or `src/feeds/scheduler.py`"
        ),
    )


# ---------- Report --------------------------------------------------------


def _status_color(status: str) -> str:
    return {
        STATUS_OK: "green",
        STATUS_EMPTY: "yellow",
        STATUS_SKIP: "grey",
        STATUS_ERROR: "red",
    }[status]


def _print_report(org_name: str, results: list[CheckResult]) -> None:
    bar = "─" * 78
    print()
    print(_c(bar, "grey"))
    print(_c(f"  HARVESTER SMOKETEST — {org_name}", "bold"))
    print(_c(bar, "grey"))
    print()
    header = f"  {'STATUS':<7}  {'INTEGRATION':<46}  {'COUNT':>7}  {'TIME':>6}"
    print(_c(header, "bold"))
    print(_c("  " + "-" * 76, "grey"))
    by_status: dict[str, int] = {}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        status_text = _c(f"{r.status:<7}", _status_color(r.status))
        count_text = f"{r.count:>7}" if r.count else f"{'—':>7}"
        time_text = f"{r.duration_ms:>5}ms" if r.duration_ms else f"{'—':>6}"
        print(f"  {status_text}  {r.name[:46]:<46}  {count_text}  {time_text}")
        if r.detail:
            print(_c(f"           ↳ {r.detail}", "grey"))
    print()
    print(_c("  Summary:", "bold"), end=" ")
    summary_bits = []
    for s in (STATUS_OK, STATUS_EMPTY, STATUS_SKIP, STATUS_ERROR):
        if s in by_status:
            summary_bits.append(_c(f"{by_status[s]} {s.lower()}", _status_color(s)))
    print(", ".join(summary_bits))
    print()
    if STATUS_ERROR in by_status:
        print(_c("  ERRORs are real product bugs — fix before demoing.", "red"))
    if STATUS_EMPTY in by_status:
        print(_c(
            "  EMPTYs need eyeball — could be true negatives OR matcher gaps. "
            "Cross-check by hand for ENBD-class targets.",
            "yellow",
        ))
    if STATUS_SKIP in by_status:
        print(_c(
            "  SKIPs are config gaps — set the named env var or seed config to enable.",
            "grey",
        ))
    print()


# ---------- Entrypoint ----------------------------------------------------


async def main_async(args: argparse.Namespace) -> int:
    if _db.async_session_factory is None:
        await init_db()
    factory: async_sessionmaker[AsyncSession] = _db.async_session_factory  # type: ignore[assignment]

    ctx = await _load_org(factory, args.org)
    logger.info(
        "Target: %s — %d domains, %d brand-name terms, "
        "%d breach-check emails, %d telegram channels",
        ctx.org.name,
        len(ctx.domains),
        len(ctx.brand_term_names),
        len(ctx.breach_emails),
        len(ctx.telegram_channels),
    )

    results: list[CheckResult] = []
    # Run checks sequentially so the report ordering is stable + so we
    # don't hammer crt.sh with parallel keyword fan-outs.
    results.append(await check_ct_logs(ctx.brand_term_names, ctx.domains))
    results.append(await check_phishing_feeds(factory, ctx.org.id))
    results.append(await check_dnstwist(factory, ctx.org.id))
    results.append(await check_dns_dmarc(ctx.domains))
    results.append(await check_urlscan(ctx.domains))
    results.append(await check_hibp(ctx.breach_emails))
    results.append(await check_telegram(ctx.telegram_channels, ctx.brand_term_names))
    results.append(await check_dark_web_crawlers())

    _print_report(ctx.org.name, results)
    # Non-zero exit when something's actually broken, so this can be a
    # CI gate later. EMPTY/SKIP don't fail the run.
    has_error = any(r.status == STATUS_ERROR for r in results)
    return 1 if has_error else 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Smoketest Marsad's free public-source harvesters against a target org.",
    )
    p.add_argument(
        "--org", default="Emirates NBD",
        help="Organisation name to test against (must already exist in DB).",
    )
    args = p.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
