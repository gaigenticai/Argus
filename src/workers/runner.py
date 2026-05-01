"""Background worker loop — see ``src.workers`` package docstring."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import Awaitable, Callable

from sqlalchemy import select

from src.core.metrics import easm_jobs_processed_total, sla_evaluations_total
from src.easm.worker import tick as easm_tick
from src.models.brand import BrandTerm
from src.models.threat import Organization
from src.sla.engine import evaluate_organization
from src.storage import database as _db


_logger = logging.getLogger("argus.worker")


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


EASM_INTERVAL = _int_env("ARGUS_WORKER_EASM_INTERVAL", 5)
EASM_BATCH = _int_env("ARGUS_WORKER_EASM_BATCH", 10)
SLA_INTERVAL = _int_env("ARGUS_WORKER_SLA_INTERVAL", 300)
INVESTIGATION_INTERVAL = _int_env("ARGUS_WORKER_INVESTIGATION_INTERVAL", 15)
INVESTIGATION_BATCH = _int_env("ARGUS_WORKER_INVESTIGATION_BATCH", 3)
BRAND_DEFENDER_INTERVAL = _int_env("ARGUS_WORKER_BRAND_DEFENDER_INTERVAL", 20)
BRAND_DEFENDER_BATCH = _int_env("ARGUS_WORKER_BRAND_DEFENDER_BATCH", 3)
CASE_COPILOT_INTERVAL = _int_env("ARGUS_WORKER_CASE_COPILOT_INTERVAL", 20)
CASE_COPILOT_BATCH = _int_env("ARGUS_WORKER_CASE_COPILOT_BATCH", 3)
# Threat Hunter is the only scheduler-triggered agent. Every tick it
# kicks off a fresh hunt against the system org. Default cadence is
# weekly; the worker also drains any queued ad-hoc runs.
THREAT_HUNT_INTERVAL = _int_env("ARGUS_WORKER_THREAT_HUNT_INTERVAL", 604800)
THREAT_HUNT_BATCH = _int_env("ARGUS_WORKER_THREAT_HUNT_BATCH", 1)
# Audit B3 — CertStream daemon is opt-in. Off by default so dev/test
# environments don't open an outbound WebSocket. Set
# ``ARGUS_WORKER_CERTSTREAM_ENABLED=1`` in production to start it.
CERTSTREAM_ENABLED = os.environ.get("ARGUS_WORKER_CERTSTREAM_ENABLED") == "1"
# Audit B3 — mobile-app store scan cadence. 0 disables. Default 6h
# because the stores throttle aggressive callers; running every 6h is
# enough to catch new rogue uploads without provoking IP bans.
MOBILE_APPS_INTERVAL = _int_env("ARGUS_WORKER_MOBILE_APPS_INTERVAL", 21600)
# Audit B3 — Telegram channel monitor cadence. 0 disables. Default
# 30 min — public channel preview is cheap to fetch and scams move
# fast. Tightening below 5 min risks t.me rate-limiting our IP.
TELEGRAM_INTERVAL = _int_env("ARGUS_WORKER_TELEGRAM_INTERVAL", 1800)
# Audit B3 — phishing-feed sync cadence. 0 disables. Default 1h —
# OpenPhish + PhishTank publish updates every few minutes; URLhaus
# every 5 min. 1h is the sweet spot between freshness and
# politeness to free upstream services.
PHISHING_FEEDS_INTERVAL = _int_env("ARGUS_WORKER_PHISHING_FEEDS_INTERVAL", 3600)
# Audit B3 — Instagram monitor cadence. 0 disables. Default 1h —
# instaloader's anonymous rate limit is roughly one profile every
# 30s; 1h gives us headroom even at 50 monitored handles per org.
INSTAGRAM_INTERVAL = _int_env("ARGUS_WORKER_INSTAGRAM_INTERVAL", 3600)
# Audit B3 — TikTok monitor cadence. 0 disables. Default 0 because
# the TikTokApi loader requires Playwright + Chromium installed in
# the runtime image; production deploys that want TikTok must
# (a) set this > 0 and (b) bake `playwright install chromium` into
# their image build (documented in DEPLOYMENT.md).
TIKTOK_INTERVAL = _int_env("ARGUS_WORKER_TIKTOK_INTERVAL", 0)
# Audit B3 — Twitter/X monitor cadence. 0 disables. Default 0
# because Scweet requires authenticated session files to be present
# at ARGUS_TWITTER_SESSION_DIR; deploys without them must keep this
# disabled (the loader fails closed, but skipping scheduling
# entirely is cleaner).
TWITTER_INTERVAL = _int_env("ARGUS_WORKER_TWITTER_INTERVAL", 0)
# Audit B3 — LinkedIn monitor cadence. 0 disables (default). Real-
# world deploys MUST set this to ≥ 6h (21600) to avoid LinkedIn
# anti-abuse triggers, regardless of how few handles are configured.
LINKEDIN_INTERVAL = _int_env("ARGUS_WORKER_LINKEDIN_INTERVAL", 0)
# Audit E14 — NVD / EPSS / KEV daily sync. Default 24h cadence; the
# upstream feeds are published once per day so faster polling wastes
# bandwidth without yielding fresher data. Disable by setting the
# interval to 0.
INTEL_INTERVAL = _int_env("ARGUS_WORKER_INTEL_INTERVAL", 86400)
NVD_FEED_URL = os.environ.get(
    "ARGUS_WORKER_NVD_URL",
    # NVD v1.1 JSON feeds were retired Dec 2023. Using the v2.0 REST API.
    # Paginated; sync_nvd() handles pages automatically.
    # Override with a local mirror URL for air-gapped deployments.
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
)
EPSS_FEED_URL = os.environ.get(
    "ARGUS_WORKER_EPSS_URL",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
)
KEV_FEED_URL = os.environ.get(
    "ARGUS_WORKER_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)


async def _run_loop(
    name: str,
    interval: int,
    body: Callable[[], Awaitable[None]],
    stop: asyncio.Event,
) -> None:
    """Run ``body`` every ``interval`` seconds until ``stop`` is set.

    Exceptions are logged with full traceback but never break the loop —
    the worker is expected to keep ticking through transient failures.
    """
    _logger.info("loop[%s] starting (interval=%ss)", name, interval)
    while not stop.is_set():
        try:
            await body()
        except Exception:  # noqa: BLE001
            _logger.exception("loop[%s] iteration failed", name)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    _logger.info("loop[%s] stopped", name)


# Audit F4 — heartbeat file. Each successful tick on any loop touches
# this path with the current epoch seconds. The compose / k8s
# healthcheck reads it and treats "not updated in N seconds" as
# unhealthy, which lets orchestrators restart a stuck worker.
HEARTBEAT_PATH = os.environ.get("ARGUS_WORKER_HEARTBEAT", "/tmp/argus-worker.heartbeat")


def _write_heartbeat() -> None:
    import time as _time
    try:
        with open(HEARTBEAT_PATH, "w") as f:
            f.write(str(int(_time.time())))
    except Exception:  # noqa: BLE001 — heartbeat is best-effort
        pass


async def _easm_tick_once() -> None:
    if _db.async_session_factory is None:
        return
    _write_heartbeat()
    async with _db.async_session_factory() as session:
        results = await easm_tick(session, max_jobs=EASM_BATCH)
        if results:
            _logger.info(
                "easm tick: %d job(s) executed (%d ok, %d failed)",
                len(results),
                sum(1 for r in results if r.get("succeeded")),
                sum(1 for r in results if not r.get("succeeded")),
            )
            for r in results:
                easm_jobs_processed_total.labels(
                    kind=r.get("kind") or "unknown",
                    outcome="succeeded" if r.get("succeeded") else "failed",
                ).inc()


async def _investigation_tick_once() -> None:
    """Drain queued Investigation rows.

    The agentic loop is slow (multi-second per alert), so we cap each
    tick at ``INVESTIGATION_BATCH`` rows to keep the worker responsive
    on other loops. Every run gets its own session so a flushed verdict
    doesn't sit in memory longer than necessary.
    """
    if _db.async_session_factory is None:
        return
    _write_heartbeat()

    from src.models.investigations import Investigation, InvestigationStatus
    from src.agents.investigation_agent import run_and_persist

    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(Investigation)
                .where(Investigation.status == InvestigationStatus.QUEUED.value)
                .order_by(Investigation.created_at.asc())
                .limit(INVESTIGATION_BATCH)
            )
        ).scalars().all()
        if not rows:
            return
        _logger.info("investigation tick: %d row(s) to drain", len(rows))

    for r in rows:
        # One session per run so SQLAlchemy doesn't hold the trace dict
        # across runs and we get a clean transaction boundary.
        async with _db.async_session_factory() as session:
            try:
                await run_and_persist(
                    session,
                    alert_id=r.alert_id,
                    organization_id=r.organization_id,
                    investigation_id=r.id,
                )
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "[investigate] worker run failed for id=%s", r.id
                )


async def _brand_defender_tick_once() -> None:
    """Drain queued BrandAction rows.

    Same shape as ``_investigation_tick_once`` — separate session per
    run so the trace dict doesn't pile up in memory across iterations.
    """
    if _db.async_session_factory is None:
        return
    _write_heartbeat()

    from src.models.brand_actions import BrandAction, BrandActionStatus
    from src.agents.brand_defender_agent import run_and_persist as _bd_run

    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(BrandAction)
                .where(BrandAction.status == BrandActionStatus.QUEUED.value)
                .order_by(BrandAction.created_at.asc())
                .limit(BRAND_DEFENDER_BATCH)
            )
        ).scalars().all()
        if not rows:
            return
        _logger.info(
            "brand-defender tick: %d row(s) to drain", len(rows)
        )

    for r in rows:
        async with _db.async_session_factory() as session:
            try:
                await _bd_run(
                    session,
                    suspect_domain_id=r.suspect_domain_id,
                    organization_id=r.organization_id,
                    action_id=r.id,
                )
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "[brand-defender] worker run failed for id=%s", r.id
                )


async def _case_copilot_tick_once() -> None:
    """Drain queued CaseCopilotRun rows. Same shape as the other
    agentic ticks."""
    if _db.async_session_factory is None:
        return
    _write_heartbeat()

    from src.models.case_copilot import CaseCopilotRun, CopilotStatus
    from src.agents.case_copilot_agent import run_and_persist as _cc_run

    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(CaseCopilotRun)
                .where(CaseCopilotRun.status == CopilotStatus.QUEUED.value)
                .order_by(CaseCopilotRun.created_at.asc())
                .limit(CASE_COPILOT_BATCH)
            )
        ).scalars().all()
        if not rows:
            return
        _logger.info(
            "case-copilot tick: %d row(s) to drain", len(rows)
        )

    for r in rows:
        async with _db.async_session_factory() as session:
            try:
                await _cc_run(
                    session,
                    case_id=r.case_id,
                    organization_id=r.organization_id,
                    run_id=r.id,
                )
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "[case-copilot] worker run failed for id=%s", r.id
                )


async def _threat_hunt_tick_once() -> None:
    """Drain queued ThreatHuntRun rows AND kick off a scheduled hunt
    if no run has happened in the last interval.

    The hunt is intentionally long-running — we cap at one in-flight
    per tick so two parallel hunts never compete for the same actor
    cluster.
    """
    if _db.async_session_factory is None:
        return
    _write_heartbeat()

    from datetime import datetime, timezone

    from src.core.tenant import get_system_org_id
    from src.models.threat_hunts import HuntStatus, ThreatHuntRun
    from src.agents.threat_hunter_agent import run_and_persist as _hunt_run

    # Drain any queued ad-hoc rows first.
    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(ThreatHuntRun)
                .where(ThreatHuntRun.status == HuntStatus.QUEUED.value)
                .order_by(ThreatHuntRun.created_at.asc())
                .limit(THREAT_HUNT_BATCH)
            )
        ).scalars().all()

    for r in rows:
        async with _db.async_session_factory() as session:
            try:
                await _hunt_run(
                    session,
                    organization_id=r.organization_id,
                    run_id=r.id,
                )
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "[threat-hunter] queued run failed for id=%s", r.id
                )

    # Scheduled cadence: if no completed run in the last interval,
    # queue one. The interval is honoured by ``_run_loop`` so we only
    # need a quick "anything recently?" check here.
    async with _db.async_session_factory() as session:
        try:
            org_id = await get_system_org_id(session)
        except Exception:  # noqa: BLE001
            return
        recent = (
            await session.execute(
                select(ThreatHuntRun)
                .where(ThreatHuntRun.organization_id == org_id)
                .where(
                    ThreatHuntRun.status.in_(
                        [
                            HuntStatus.QUEUED.value,
                            HuntStatus.RUNNING.value,
                            HuntStatus.COMPLETED.value,
                        ]
                    )
                )
                .order_by(ThreatHuntRun.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if recent is not None:
            age = datetime.now(timezone.utc) - recent.created_at
            if age.total_seconds() < THREAT_HUNT_INTERVAL:
                return
        run = ThreatHuntRun(
            organization_id=org_id,
            status=HuntStatus.QUEUED.value,
        )
        session.add(run)
        await session.commit()
        _logger.info("[threat-hunter] auto-scheduled hunt %s", run.id)


async def _intel_tick_once() -> None:
    """Audit E14 — daily NVD + EPSS + KEV refresh. Each call is
    idempotent at the row level (the underlying syncs upsert by CVE
    id), so a missed tick simply runs at the next interval."""
    if _db.async_session_factory is None:
        return
    from src.intel.nvd_epss import sync_epss, sync_kev, sync_nvd

    from src.core import feed_health as _feed_health
    from src.models.admin import FeedHealthStatus

    feeds = (
        ("nvd", NVD_FEED_URL, sync_nvd),
        ("epss", EPSS_FEED_URL, sync_epss),
        ("kev", KEV_FEED_URL, sync_kev),
    )
    for label, url, fn in feeds:
        feed_name = f"intel.{label}"
        if not url:
            async with _db.async_session_factory() as session:
                await _feed_health.mark_disabled(
                    session,
                    feed_name=feed_name,
                    detail=f"ARGUS_WORKER_{label.upper()}_URL is unset",
                )
                await session.commit()
            continue
        async with _db.async_session_factory() as session:
            import time as _time

            t0 = _time.monotonic()
            try:
                report = await fn(session, source=url)
                await session.commit()
                duration_ms = int((_time.monotonic() - t0) * 1000)
                if report.succeeded:
                    await _feed_health.mark_ok(
                        session,
                        feed_name=feed_name,
                        rows_ingested=report.rows_ingested,
                        duration_ms=duration_ms,
                        detail=(
                            f"updated={report.rows_updated}"
                            if hasattr(report, "rows_updated") else None
                        ),
                    )
                else:
                    await _feed_health.mark_failure(
                        session,
                        feed_name=feed_name,
                        error=getattr(report, "error", "sync reported failure"),
                        duration_ms=duration_ms,
                        classify=FeedHealthStatus.PARSE_ERROR.value,
                    )
                await session.commit()
                _logger.info(
                    "intel %s sync: ingested=%d updated=%d ok=%s",
                    label, report.rows_ingested, report.rows_updated,
                    report.succeeded,
                )
            except Exception as exc:  # noqa: BLE001
                await session.rollback()
                duration_ms = int((_time.monotonic() - t0) * 1000)
                async with _db.async_session_factory() as health_session:
                    await _feed_health.mark_failure(
                        health_session,
                        feed_name=feed_name,
                        error=exc,
                        duration_ms=duration_ms,
                    )
                    await health_session.commit()
                _logger.exception("intel %s sync failed", label)


async def _mobile_apps_tick_once() -> None:
    """Audit B3 — scan Google Play + iTunes for rogue apps that match
    each org's brand-NAME terms. Per-org failures are isolated; the
    tick is best-effort and never raises out."""
    if _db.async_session_factory is None:
        return
    from src.social.mobile_apps import scan_organization as scan_mobile_apps

    async with _db.async_session_factory() as session:
        org_ids = (
            await session.execute(
                select(BrandTerm.organization_id)
                .where(BrandTerm.is_active == True)  # noqa: E712
                .where(BrandTerm.kind == "name")
                .distinct()
            )
        ).scalars().all()

    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await scan_mobile_apps(session, org_id)
                await session.commit()
                if report.suspects_created or report.suspects_seen_again:
                    _logger.info(
                        "mobile_apps scan org=%s terms=%d candidates=%d "
                        "new=%d seen-again=%d official=%d errors=%d",
                        org_id,
                        report.terms_scanned,
                        report.candidates_seen,
                        report.suspects_created,
                        report.suspects_seen_again,
                        report.skipped_official,
                        len(report.errors),
                    )
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception(
                    "mobile_apps scan failed for org %s", org_id
                )


async def _linkedin_tick_once() -> None:
    """Audit B3 — LinkedIn Company-page monitor.

    Off by default; requires operator credentials. Bails after 3
    consecutive empty fetches in case credentials are wrong / blocked
    so we don't burn the per-company delay budget on a doomed run.
    """
    if _db.async_session_factory is None:
        return
    from src.social.linkedin_monitor import scan_organization as scan_li

    async with _db.async_session_factory() as session:
        org_rows = (
            await session.execute(select(Organization))
        ).scalars().all()
        org_ids = [
            o.id for o in org_rows
            if (o.settings or {}).get("linkedin_monitor_handles")
        ]

    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await scan_li(session, org_id)
                await session.commit()
                if report.fail_closed:
                    _logger.warning(
                        "linkedin scan org=%s fail-closed (likely missing "
                        "ARGUS_LINKEDIN_USERNAME/PASSWORD)",
                        org_id,
                    )
                if report.fraud_findings_created or report.impersonations_created:
                    _logger.info(
                        "linkedin scan org=%s handles=%d fraud=%d impers=%d",
                        org_id,
                        report.handles_scanned,
                        report.fraud_findings_created,
                        report.impersonations_created,
                    )
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception("linkedin scan failed for org %s", org_id)


async def _twitter_tick_once() -> None:
    """Audit B3 — Twitter/X account monitor (Scweet-based).

    Fails closed when ARGUS_TWITTER_SESSION_DIR isn't populated; the
    loader logs WARNING for the first handle and returns None for
    every subsequent handle in the same tick.
    """
    if _db.async_session_factory is None:
        return
    from src.social.twitter_monitor import scan_organization as scan_tw

    async with _db.async_session_factory() as session:
        org_rows = (
            await session.execute(select(Organization))
        ).scalars().all()
        org_ids = [
            o.id for o in org_rows
            if (o.settings or {}).get("twitter_monitor_handles")
        ]

    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await scan_tw(session, org_id)
                await session.commit()
                if report.fraud_findings_created or report.impersonations_created:
                    _logger.info(
                        "twitter scan org=%s handles=%d fraud=%d impers=%d errors=%d",
                        org_id,
                        report.handles_scanned,
                        report.fraud_findings_created,
                        report.impersonations_created,
                        len(report.errors),
                    )
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception("twitter scan failed for org %s", org_id)


async def _tiktok_tick_once() -> None:
    """Audit B3 — public TikTok account monitor.

    Spawns a Playwright browser per call (TikTokApi requirement); the
    interval defaults to 0 (disabled) because most deploys won't have
    chromium installed.
    """
    if _db.async_session_factory is None:
        return
    from src.social.tiktok_monitor import scan_organization as scan_tt

    async with _db.async_session_factory() as session:
        org_rows = (
            await session.execute(select(Organization))
        ).scalars().all()
        org_ids = [
            o.id for o in org_rows
            if (o.settings or {}).get("tiktok_monitor_handles")
        ]

    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await scan_tt(session, org_id)
                await session.commit()
                if report.fraud_findings_created or report.impersonations_created:
                    _logger.info(
                        "tiktok scan org=%s handles=%d fraud=%d impers=%d errors=%d",
                        org_id,
                        report.handles_scanned,
                        report.fraud_findings_created,
                        report.impersonations_created,
                        len(report.errors),
                    )
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception("tiktok scan failed for org %s", org_id)


async def _instagram_tick_once() -> None:
    """Audit B3 — public Instagram profile monitor."""
    if _db.async_session_factory is None:
        return
    from src.social.instagram_monitor import scan_organization as scan_ig

    async with _db.async_session_factory() as session:
        org_rows = (
            await session.execute(select(Organization))
        ).scalars().all()
        org_ids = [
            o.id for o in org_rows
            if (o.settings or {}).get("instagram_monitor_handles")
        ]

    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await scan_ig(session, org_id)
                await session.commit()
                if report.fraud_findings_created or report.impersonations_created:
                    _logger.info(
                        "instagram scan org=%s handles=%d fraud=%d impers=%d errors=%d",
                        org_id,
                        report.handles_scanned,
                        report.fraud_findings_created,
                        report.impersonations_created,
                        len(report.errors),
                    )
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception("instagram scan failed for org %s", org_id)


async def _phishing_feeds_tick_once() -> None:
    """Audit B3 — Netcraft replacement.

    Pull every wired public phishing feed once per tick; share the
    payload across all orgs (they would otherwise burn the same bytes
    N times). Each org's brand terms are matched against the feed
    domains and matches land as ``SuspectDomain`` rows tagged with
    the upstream feed.
    """
    if _db.async_session_factory is None:
        return
    from src.intel.phishing_feeds import (
        fetch_all_feeds,
        ingest_for_organization,
        orgs_with_active_brand_terms,
    )

    feeds = await fetch_all_feeds()
    total_entries = sum(len(v) for v in feeds.values())
    _logger.info(
        "phishing_feeds: fetched %d entries across %d feed(s)",
        total_entries, len(feeds),
    )

    async with _db.async_session_factory() as session:
        org_ids = await orgs_with_active_brand_terms(session)

    total_created = 0
    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                reports = await ingest_for_organization(
                    session, org_id, feeds=feeds
                )
                await session.commit()
                created_here = sum(r.suspects_created for r in reports)
                if created_here:
                    _logger.info(
                        "phishing_feeds org=%s created=%d (%s)",
                        org_id,
                        created_here,
                        ", ".join(
                            f"{r.feed}={r.suspects_created}"
                            for r in reports
                            if r.suspects_created
                        ),
                    )
                total_created += created_here
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception(
                    "phishing_feeds ingest failed for org %s", org_id
                )

    if total_created:
        _logger.info(
            "phishing_feeds tick complete: %d new suspects across %d org(s)",
            total_created, len(org_ids),
        )


async def _telegram_tick_once() -> None:
    """Audit B3 — scan public Telegram channels configured per-org for
    fraud + impersonation against the brand. Per-org failures are
    isolated; the tick is best-effort and never raises out."""
    if _db.async_session_factory is None:
        return
    from src.social.telegram_monitor import scan_organization as scan_tg

    async with _db.async_session_factory() as session:
        # Only orgs with at least one monitored channel configured.
        # Settings is JSONB; the inexpensive path is to filter in
        # Python after a project-wide select.
        org_rows = (
            await session.execute(select(Organization))
        ).scalars().all()
        org_ids = [
            o.id for o in org_rows
            if (o.settings or {}).get("telegram_monitor_channels")
        ]

    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await scan_tg(session, org_id)
                await session.commit()
                if report.fraud_findings_created or report.impersonations_created:
                    _logger.info(
                        "telegram scan org=%s channels=%d msgs=%d fraud=%d "
                        "impers=%d errors=%d",
                        org_id,
                        report.channels_scanned,
                        report.messages_seen,
                        report.fraud_findings_created,
                        report.impersonations_created,
                        len(report.errors),
                    )
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception(
                    "telegram scan failed for org %s", org_id
                )


async def _sla_tick_once() -> None:
    if _db.async_session_factory is None:
        return
    async with _db.async_session_factory() as session:
        org_ids = (
            await session.execute(select(Organization.id))
        ).scalars().all()
        for org_id in org_ids:
            try:
                await evaluate_organization(session, org_id)
                await session.commit()
                sla_evaluations_total.labels(outcome="succeeded").inc()
            except Exception:  # noqa: BLE001
                await session.rollback()
                sla_evaluations_total.labels(outcome="failed").inc()
                _logger.exception("sla evaluate failed for org %s", org_id)


async def _requeue_stale_running_jobs() -> int:
    """Audit C12 — on boot, mark any DiscoveryJob stuck in ``running``
    back to ``queued`` so the next tick can re-claim it.

    A job ends up here when the previous worker process was killed
    mid-execution (Railway redeploy, OOM kill, k8s pod eviction). The
    atomic ``claim_one()`` guarantees no two workers touch the same row,
    so it's safe to flip ``running`` back to ``queued`` at startup.

    Returns the number of rows requeued.
    """
    if _db.async_session_factory is None:
        return 0
    from sqlalchemy import text as _text

    async with _db.async_session_factory() as session:
        result = await session.execute(
            _text(
                """
                UPDATE discovery_jobs
                SET status = 'queued',
                    started_at = NULL,
                    updated_at = NOW()
                WHERE status = 'running'
                RETURNING id
                """
            )
        )
        rows = result.fetchall()
        await session.commit()
        if rows:
            _logger.info(
                "requeued %d stale running discovery_job(s) on boot", len(rows)
            )
        return len(rows)


async def run() -> None:
    await _db.init_db()
    await _requeue_stale_running_jobs()
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Non-Unix signal support; fall back to default behaviour.
            pass

    _logger.info(
        "argus worker online — easm every %ss, sla every %ss, intel every %ss",
        EASM_INTERVAL, SLA_INTERVAL, INTEL_INTERVAL,
    )
    loops = [
        _run_loop("easm", EASM_INTERVAL, _easm_tick_once, stop),
        _run_loop("sla", SLA_INTERVAL, _sla_tick_once, stop),
        _run_loop(
            "investigation",
            INVESTIGATION_INTERVAL,
            _investigation_tick_once,
            stop,
        ),
        _run_loop(
            "brand_defender",
            BRAND_DEFENDER_INTERVAL,
            _brand_defender_tick_once,
            stop,
        ),
        _run_loop(
            "case_copilot",
            CASE_COPILOT_INTERVAL,
            _case_copilot_tick_once,
            stop,
        ),
        # Threat Hunter ticks every 4h to drain queued runs; the
        # auto-schedule logic inside the tick body honours
        # THREAT_HUNT_INTERVAL for cadence (weekly default).
        _run_loop(
            "threat_hunt",
            min(THREAT_HUNT_INTERVAL, 14400),  # cap polling at 4h
            _threat_hunt_tick_once,
            stop,
        ),
    ]
    if INTEL_INTERVAL > 0:
        loops.append(_run_loop("intel", INTEL_INTERVAL, _intel_tick_once, stop))
    if MOBILE_APPS_INTERVAL > 0:
        loops.append(
            _run_loop(
                "mobile_apps", MOBILE_APPS_INTERVAL, _mobile_apps_tick_once, stop
            )
        )
    if TELEGRAM_INTERVAL > 0:
        loops.append(
            _run_loop(
                "telegram", TELEGRAM_INTERVAL, _telegram_tick_once, stop
            )
        )
    if PHISHING_FEEDS_INTERVAL > 0:
        loops.append(
            _run_loop(
                "phishing_feeds",
                PHISHING_FEEDS_INTERVAL,
                _phishing_feeds_tick_once,
                stop,
            )
        )
    if INSTAGRAM_INTERVAL > 0:
        loops.append(
            _run_loop(
                "instagram", INSTAGRAM_INTERVAL, _instagram_tick_once, stop
            )
        )
    if TIKTOK_INTERVAL > 0:
        loops.append(
            _run_loop(
                "tiktok", TIKTOK_INTERVAL, _tiktok_tick_once, stop
            )
        )
    if TWITTER_INTERVAL > 0:
        loops.append(
            _run_loop(
                "twitter", TWITTER_INTERVAL, _twitter_tick_once, stop
            )
        )
    if LINKEDIN_INTERVAL > 0:
        loops.append(
            _run_loop(
                "linkedin", LINKEDIN_INTERVAL, _linkedin_tick_once, stop
            )
        )
    if CERTSTREAM_ENABLED:
        from src.workers import certstream_daemon
        _logger.info("certstream daemon enabled")
        loops.append(certstream_daemon.run(stop))
    try:
        await asyncio.gather(*loops)
    finally:
        await _db.close_db()


def main() -> None:
    from src.core.logging import configure_logging

    configure_logging()
    asyncio.run(run())


if __name__ == "__main__":
    main()
