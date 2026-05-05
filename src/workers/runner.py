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
# Re-probe scheduler — checks every 5 min by default, drains 25 due
# suspects per tick. Cheap (the scheduler is mostly DB reads + HTTP
# fetches), and the 7d/30d cadence makes most ticks a no-op.
REPROBE_INTERVAL = _int_env("ARGUS_WORKER_REPROBE_INTERVAL", 300)
REPROBE_BATCH = _int_env("ARGUS_WORKER_REPROBE_BATCH", 25)
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
# Governance — retention scheduler. Daily by default. Setting 0 disables
# the loop (config-only mode). Cleanup honours legal-hold and is a no-op
# when ``auto_cleanup_enabled = false`` on the policy.
RETENTION_INTERVAL = _int_env("ARGUS_WORKER_RETENTION_INTERVAL", 86400)
# Governance — agent-task dispatcher. Frequent (every 10s) because most
# agent tasks finish in <30s and the queue is hot during business hours.
# Each tick drains up to AGENT_DISPATCH_BATCH tasks.
AGENT_DISPATCH_INTERVAL = _int_env("ARGUS_WORKER_AGENT_DISPATCH_INTERVAL", 10)
AGENT_DISPATCH_BATCH = _int_env("ARGUS_WORKER_AGENT_DISPATCH_BATCH", 8)
# Governance — DMARC IMAP mailbox poll for RUA/RUF reports. Hourly is
# the right cadence — receivers send aggregate reports daily.
DMARC_MAILBOX_INTERVAL = _int_env("ARGUS_WORKER_DMARC_MAILBOX_INTERVAL", 3600)
# Governance — DMARC RUF spike scanner. Sweeps ``dmarc_forensic_reports``
# hourly and enqueues ``dmarc_spoof_campaign_detect`` for any source IP
# that crossed the spike threshold.
DMARC_SPIKE_SCAN_INTERVAL = _int_env(
    "ARGUS_WORKER_DMARC_SPIKE_SCAN_INTERVAL", 3600
)
# Governance — Pastebin archive scrape (DLP/card detection feed).
PASTEBIN_INTERVAL = _int_env("ARGUS_WORKER_PASTEBIN_INTERVAL", 3600)
# Governance — HIBP correlator runs against new DLP findings.
HIBP_CORRELATOR_INTERVAL = _int_env("ARGUS_WORKER_HIBP_CORRELATOR_INTERVAL", 1800)
# Governance — daily exec briefing (DLP + leakage). 0 disables.
LEAKAGE_BRIEFING_INTERVAL = _int_env(
    "ARGUS_WORKER_LEAKAGE_BRIEFING_INTERVAL", 86400
)
# Governance — weekly retention-policy conflict scan.
RETENTION_CONFLICT_INTERVAL = _int_env(
    "ARGUS_WORKER_RETENTION_CONFLICT_INTERVAL", 86400 * 7
)
# Self-healing maintenance loops. ``REFRESH_RANSOMWARE_INTERVAL`` keeps
# the dark-web target list current (groups rotate URLs every 2-3 weeks);
# ``PRUNE_TELEGRAM_INTERVAL`` marks Telegram channels whose public
# preview has been disabled. 0 disables either loop; defaults are
# conservative because the upstream APIs / endpoints are public.
RANSOMWARE_REFRESH_INTERVAL = _int_env(
    "ARGUS_WORKER_RANSOMWARE_REFRESH_INTERVAL", 86400  # daily
)
# Typosquat daily sweep — for each org, generate look-alike permutations
# of its primary domains and resolve them via DNS / WHOIS / TLS to flag
# new lookalike registrations as suspect_domains rows. Default daily;
# 0 disables. The orchestrator (src/onboarding/intel_setup.py) kicks
# off an immediate scan on org create, so this loop is purely the
# recurring backstop.
TYPOSQUAT_SCAN_INTERVAL = _int_env(
    "ARGUS_WORKER_TYPOSQUAT_SCAN_INTERVAL", 86400  # daily
)
TELEGRAM_PRUNE_INTERVAL = _int_env(
    "ARGUS_WORKER_TELEGRAM_PRUNE_INTERVAL", 604800  # weekly
)
# Scheduled EASM Nuclei sweep — periodic vulnerability scan over each
# org's known assets. Default 6h tick balances coverage vs cost; one
# sweep visits ARGUS_NUCLEI_EASM_TARGETS_PER_TICK assets per org
# (default 20). 0 disables the loop entirely.
NUCLEI_EASM_INTERVAL = _int_env(
    "ARGUS_WORKER_NUCLEI_EASM_INTERVAL", 21600  # 6h
)
# Suricata eve.json tail — tight default tick (60s) so NSM alerts feel
# near-real-time. The worker is a no-op when ARGUS_SURICATA_EVE_PATH
# is unset, so leaving this on by default costs nothing.
SURICATA_TAIL_INTERVAL = _int_env(
    "ARGUS_WORKER_SURICATA_TAIL_INTERVAL", 60
)
# Prowler cloud audit — weekly tick by default. The worker is a no-op
# when no cloud creds are detected (AWS_*, AZURE_*, GOOGLE_*, KUBECONFIG),
# so leaving this on by default costs nothing for non-cloud deploys.
PROWLER_AUDIT_INTERVAL = _int_env(
    "ARGUS_WORKER_PROWLER_AUDIT_INTERVAL", 604800  # weekly
)
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

    A small randomised startup jitter (0-3s) is applied before the
    first tick. Without it, every loop fires its body simultaneously
    on container boot, sending a thundering herd of ``getaddrinfo`` +
    ``connect`` syscalls through the asyncio default executor's
    bounded thread pool. On a fresh container with many loops (we
    have ~12) the pool gets saturated, individual ``getaddrinfo``
    coroutines get cancelled by their outer timeouts, and every loop
    starts its life with a TimeoutError before backing off. The
    jitter spreads the herd across a 3-second window so the resolver
    + connection-pool warm-up runs cleanly.
    """
    import random as _random
    _logger.info("loop[%s] starting (interval=%ss)", name, interval)
    # Small jitter so we don't thunder at boot. Capped at 3s — even
    # the longest-interval loops feel this only at startup and then
    # settle into their normal cadence.
    jitter = _random.uniform(0.0, min(3.0, float(interval) / 2))
    try:
        await asyncio.wait_for(stop.wait(), timeout=jitter)
    except asyncio.TimeoutError:
        pass
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


async def _reprobe_tick_once() -> None:
    """Drain the live-probe re-scheduler queue (T80).

    Per-tick batch is bounded by REPROBE_BATCH; the cadence inside
    ``compute_reprobe_queue`` ensures the same suspect isn't probed
    more than once a week unless its verdict was suspicious /
    unreachable.
    """
    if _db.async_session_factory is None:
        return
    _write_heartbeat()

    from src.brand.reprobe_scheduler import reprobe_tick

    async with _db.async_session_factory() as session:
        try:
            n = await reprobe_tick(session, batch_size=REPROBE_BATCH)
            if n:
                _logger.info("reprobe tick: probed %d suspect(s)", n)
        except Exception:  # noqa: BLE001
            _logger.exception("[reprobe] tick crashed")


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


async def _ransomware_refresh_tick_once() -> None:
    """Self-healing: keep the ransomware leak-site target list
    current. Wraps the maintenance job so the worker tick stays
    consistent with the rest of the loops."""
    if _db.async_session_factory is None:
        return
    _write_heartbeat()
    from src.workers.maintenance import refresh_ransomware_targets
    await refresh_ransomware_targets.tick_once()


async def _typosquat_scan_tick_once() -> None:
    """Recurring brand typosquat sweep across every org's domains.

    For each Organization row, runs ``src.brand.scanner.scan_organization``
    which permutes the primary domains, resolves candidates, and writes
    SuspectDomain rows that the brand-protection dashboard renders. The
    orchestrator (``src/onboarding/intel_setup.py``) handles the
    immediate first scan on org create; this loop is the recurring
    backstop so newly-registered look-alike domains get caught daily.

    Failures on a single org never break the loop — each org's scan is
    isolated in its own try/except.
    """
    if _db.async_session_factory is None:
        return
    _write_heartbeat()
    from src.brand.scanner import scan_organization
    from src.models.threat import Organization
    async with _db.async_session_factory() as session:
        rows = (await session.execute(select(Organization))).scalars().all()
        for org in rows:
            if not org.domains:
                continue
            try:
                await scan_organization(session, organization_id=org.id)
                await session.commit()
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "[typosquat] scan failed for org %s — continuing",
                    org.id,
                )
                await session.rollback()


async def _telegram_prune_tick_once() -> None:
    """Self-healing: prune Telegram channels whose public preview has
    been disabled (banned / private / restricted / rebranded)."""
    if _db.async_session_factory is None:
        return
    _write_heartbeat()
    from src.workers.maintenance import prune_dead_telegram_channels
    await prune_dead_telegram_channels.tick_once()


async def _nuclei_easm_tick_once() -> None:
    """Scheduled EASM Nuclei sweep over each org's monitored assets.
    Persists exposure_findings rows visible at /exposures."""
    if _db.async_session_factory is None:
        return
    _write_heartbeat()
    from src.workers.maintenance import nuclei_easm
    await nuclei_easm.tick_once()


async def _suricata_tail_tick_once() -> None:
    """Tail Suricata eve.json on configured path; persist alerts."""
    if _db.async_session_factory is None:
        return
    _write_heartbeat()
    from src.workers.maintenance import suricata_tail
    await suricata_tail.tick_once()


async def _prowler_audit_tick_once() -> None:
    """Run Prowler against every configured cloud; persist failed
    findings as ExposureFindings on /exposures."""
    if _db.async_session_factory is None:
        return
    _write_heartbeat()
    from src.workers.maintenance import prowler_audit
    await prowler_audit.tick_once()


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
    from src.core import feed_health as _feed_health
    from src.core import integration_keys as _integration_keys

    def _has_integration_key(name: str, *, env_fallback: str) -> bool:
        return _integration_keys.is_configured(name, env_fallback=env_fallback)

    feeds = await fetch_all_feeds()
    total_entries = sum(len(v) for v in feeds.values())
    _logger.info(
        "phishing_feeds: fetched %d entries across %d feed(s)",
        total_entries, len(feeds),
    )

    # Surface per-feed health so /admin → Feed Health shows operators
    # WHICH feed is broken instead of an aggregate that hides
    # per-source failures. PhishTank in particular fails closed without
    # a registered API key — the dashboard needs to point at the right
    # remediation (Settings → Integrations → PhishTank) rather than
    # leave the operator guessing.
    async with _db.async_session_factory() as session:
        for feed_name, entries in feeds.items():
            row_count = len(entries)
            if row_count > 0:
                await _feed_health.mark_ok(
                    session,
                    feed_name=f"phishing_feed.{feed_name}",
                    rows_ingested=row_count,
                    detail=f"upstream returned {row_count} entries",
                )
            elif feed_name == "phishtank" and not _has_integration_key(
                "phishtank", env_fallback="ARGUS_PHISHTANK_API_KEY",
            ):
                # Most common mode: PhishTank has tightened to require
                # a registered application key. Free to obtain;
                # remediation lives in Settings → Integrations.
                await _feed_health.mark_failure(
                    session,
                    feed_name=f"phishing_feed.{feed_name}",
                    error=(
                        "PhishTank now requires a registered application "
                        "key for unauthenticated fetches (HTTP 403). "
                        "Set ARGUS_PHISHTANK_API_KEY via Settings → "
                        "Integrations → PhishTank."
                    ),
                    classify="auth_error",
                )
            else:
                await _feed_health.mark_failure(
                    session,
                    feed_name=f"phishing_feed.{feed_name}",
                    error=(
                        f"upstream returned 0 entries — feed may be down "
                        f"or its public endpoint moved (check worker logs)"
                    ),
                    classify="network_error",
                )
        await session.commit()

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
    isolated; the tick is best-effort and never raises out.

    Writes a ``social.telegram`` FeedHealth row so the Service
    Inventory + per-page SourcesStrip can surface this as a real
    integration instead of an opaque ``unknown``."""
    if _db.async_session_factory is None:
        return
    from src.social.telegram_monitor import scan_organization as scan_tg
    from src.core import feed_health as _feed_health
    import time as _time

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

    if not org_ids:
        async with _db.async_session_factory() as session:
            await _feed_health.mark_unconfigured(
                session,
                feed_name="social.telegram",
                detail=(
                    "No org has settings.telegram_monitor_channels set. "
                    "Configure via Settings → Monitoring."
                ),
            )
            await session.commit()
        return

    started = _time.monotonic()
    total_channels = 0
    total_messages = 0
    total_fraud = 0
    total_impers = 0
    total_errors = 0

    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await scan_tg(session, org_id)
                await session.commit()
                total_channels += report.channels_scanned
                total_messages += report.messages_seen
                total_fraud += report.fraud_findings_created
                total_impers += report.impersonations_created
                total_errors += len(report.errors)
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
                total_errors += 1
                _logger.exception(
                    "telegram scan failed for org %s", org_id
                )

    duration_ms = int((_time.monotonic() - started) * 1000)
    async with _db.async_session_factory() as session:
        if total_messages > 0 or total_errors == 0:
            await _feed_health.mark_ok(
                session,
                feed_name="social.telegram",
                rows_ingested=total_fraud + total_impers,
                duration_ms=duration_ms,
                detail=(
                    f"orgs={len(org_ids)} channels={total_channels} "
                    f"msgs={total_messages} fraud={total_fraud} "
                    f"impers={total_impers} errors={total_errors}"
                ),
            )
        else:
            await _feed_health.mark_failure(
                session,
                feed_name="social.telegram",
                error=(
                    f"all {total_errors} per-org scans failed; "
                    f"channels={total_channels}, messages=0"
                ),
                duration_ms=duration_ms,
            )
        await session.commit()


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


# ---------------------------------------- Governance ticks (Phase 0)


async def _retention_cleanup_tick_once() -> None:
    """Daily retention enforcement.

    Walks every policy with ``auto_cleanup_enabled = true``, calls the
    same ``run_cleanup`` engine the manual ``POST /retention/cleanup``
    endpoint uses, and emits one structured row per run for
    observability. Honours legal-hold automatically (the engine already
    filters held rows out of every DELETE clause).
    """
    if _db.async_session_factory is None:
        return
    from src.api.routes.retention import run_cleanup
    from src.models.intel import RetentionPolicy

    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(RetentionPolicy).where(
                    RetentionPolicy.auto_cleanup_enabled.is_(True)
                )
            )
        ).scalars().all()
        for policy in rows:
            try:
                await run_cleanup(session, policy)
                _logger.info(
                    "retention.cleanup ok org=%s policy=%s",
                    policy.organization_id, policy.id,
                )
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception(
                    "retention.cleanup failed for policy %s", policy.id
                )


async def _agent_dispatch_tick_once() -> None:
    """Drain up to AGENT_DISPATCH_BATCH queued agent tasks per tick."""
    if _db.async_session_factory is None:
        return
    from src.llm.agent_queue import process_one
    # Force registration of all governance handlers on first tick.
    try:
        from src.agents import governance_handlers  # noqa: F401
    except Exception:  # noqa: BLE001
        _logger.exception("governance_handlers import failed")
        return

    drained = 0
    for _ in range(AGENT_DISPATCH_BATCH):
        async with _db.async_session_factory() as session:
            try:
                if not await process_one(session):
                    break
                drained += 1
            except Exception:  # noqa: BLE001
                await session.rollback()
                _logger.exception("agent dispatcher tick errored")
                break
    if drained:
        _logger.info("agent_dispatch drained=%d", drained)


async def _dmarc_mailbox_tick_once() -> None:
    """Poll every enabled DMARC IMAP mailbox for new reports."""
    if _db.async_session_factory is None:
        return
    try:
        from src.dmarc.mailbox_worker import poll_all_mailboxes
    except Exception:  # noqa: BLE001
        _logger.exception("dmarc mailbox worker import failed")
        return
    async with _db.async_session_factory() as session:
        try:
            await poll_all_mailboxes(session)
        except Exception:  # noqa: BLE001
            await session.rollback()
            _logger.exception("dmarc mailbox tick failed")


async def _dmarc_spike_scan_tick_once() -> None:
    """Group last-hour RUF rows by source IP / from-domain and enqueue
    a ``dmarc_spoof_campaign_detect`` agent for anything that looks
    like an attack. Thresholds: 500+ records on one IP, OR 50+ rows
    sharing the same Header-From in one hour.
    """
    if _db.async_session_factory is None:
        return
    try:
        from datetime import datetime as _dt
        from datetime import timedelta as _td
        from datetime import timezone as _tz
        from sqlalchemy import and_ as _and, func as _func, select as _select

        from src.llm.agent_queue import enqueue as _enqueue
        from src.models.dmarc_forensic import DmarcForensicReport as _DRF
    except Exception:  # noqa: BLE001
        _logger.exception("dmarc spike scan import failed")
        return

    cutoff = _dt.now(_tz.utc) - _td(hours=1)
    async with _db.async_session_factory() as session:
        try:
            ip_q = (
                _select(
                    _DRF.organization_id,
                    _DRF.domain,
                    _DRF.source_ip,
                    _func.count(_DRF.id).label("cnt"),
                )
                .where(_and(_DRF.received_at >= cutoff, _DRF.source_ip.is_not(None)))
                .group_by(_DRF.organization_id, _DRF.domain, _DRF.source_ip)
                .having(_func.count(_DRF.id) >= 500)
            )
            from_q = (
                _select(
                    _DRF.organization_id,
                    _DRF.domain,
                    _DRF.original_mail_from,
                    _func.count(_DRF.id).label("cnt"),
                )
                .where(
                    _and(
                        _DRF.received_at >= cutoff,
                        _DRF.original_mail_from.is_not(None),
                    )
                )
                .group_by(_DRF.organization_id, _DRF.domain, _DRF.original_mail_from)
                .having(_func.count(_DRF.id) >= 50)
            )
            for org_id, domain, src_ip, cnt in (await session.execute(ip_q)).all():
                await _enqueue(
                    session,
                    kind="dmarc_spoof_campaign_detect",
                    payload={
                        "organization_id": str(org_id),
                        "domain": domain,
                        "source_ip": src_ip,
                        "count": int(cnt),
                        "trigger": "ip_spike",
                    },
                    organization_id=org_id,
                    dedup_key=f"spoof:{org_id}:{src_ip}:{cutoff.strftime('%Y%m%d%H')}",
                    priority=4,
                )
            for org_id, domain, mfrom, cnt in (await session.execute(from_q)).all():
                await _enqueue(
                    session,
                    kind="dmarc_spoof_campaign_detect",
                    payload={
                        "organization_id": str(org_id),
                        "domain": domain,
                        "source_ip": mfrom,
                        "count": int(cnt),
                        "trigger": "from_spike",
                    },
                    organization_id=org_id,
                    dedup_key=f"spoof:{org_id}:{mfrom}:{cutoff.strftime('%Y%m%d%H')}",
                    priority=4,
                )
        except Exception:  # noqa: BLE001
            await session.rollback()
            _logger.exception("dmarc spike scan tick failed")


async def _pastebin_monitor_tick_once() -> None:
    if _db.async_session_factory is None:
        return
    try:
        from src.workers.maintenance.pastebin_monitor import poll_once
    except Exception:  # noqa: BLE001
        _logger.exception("pastebin monitor import failed")
        return
    async with _db.async_session_factory() as session:
        try:
            await poll_once(session)
        except Exception:  # noqa: BLE001
            await session.rollback()
            _logger.exception("pastebin monitor tick failed")


async def _hibp_correlator_tick_once() -> None:
    if _db.async_session_factory is None:
        return
    try:
        from src.workers.maintenance.hibp_correlator import correlate_pending
    except Exception:  # noqa: BLE001
        _logger.exception("hibp correlator import failed")
        return
    async with _db.async_session_factory() as session:
        try:
            await correlate_pending(session)
        except Exception:  # noqa: BLE001
            await session.rollback()
            _logger.exception("hibp correlator tick failed")


async def _leakage_briefing_tick_once() -> None:
    if _db.async_session_factory is None:
        return
    try:
        from src.workers.maintenance.leakage_briefing import enqueue_daily_briefings
    except Exception:  # noqa: BLE001
        _logger.exception("leakage briefing import failed")
        return
    async with _db.async_session_factory() as session:
        try:
            await enqueue_daily_briefings(session)
        except Exception:  # noqa: BLE001
            await session.rollback()
            _logger.exception("leakage briefing tick failed")
    # Piggy-back the on-call digest enqueue onto this same daily tick —
    # adding a fresh tick would mean another scheduler row per env. The
    # handler is the wake-up brief for whichever user(s) we point at.
    await _notification_oncall_digest_tick_once()


async def _notification_oncall_digest_tick_once() -> None:
    """Daily 08:00 user-local on-call digest. We just enqueue one
    ``notification_oncall_digest`` agent task per active admin per
    organization; the agent handler does the heavy lifting."""
    if _db.async_session_factory is None:
        return
    try:
        from src.llm.agent_queue import enqueue
        from src.models.auth import User
        from src.models.threat import Organization
    except Exception:  # noqa: BLE001
        _logger.exception("oncall digest import failed")
        return
    from datetime import datetime, timezone
    from sqlalchemy import select as _select
    async with _db.async_session_factory() as session:
        try:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            orgs = (await session.execute(_select(Organization))).scalars().all()
            admins = (
                await session.execute(_select(User).where(User.is_active == True))  # noqa: E712
            ).scalars().all()
            for org in orgs:
                for u in admins:
                    if u.role not in ("admin", "analyst"):
                        continue
                    try:
                        await enqueue(
                            session,
                            kind="notification_oncall_digest",
                            organization_id=org.id,
                            payload={
                                "user_id": str(u.id),
                                "organization_id": str(org.id),
                                "date": today,
                            },
                            dedup_key=f"digest:{org.id}:{u.id}:{today}",
                            priority=6,
                        )
                    except Exception:  # noqa: BLE001
                        _logger.exception("oncall digest enqueue failed")
        except Exception:  # noqa: BLE001
            await session.rollback()
            _logger.exception("oncall digest tick failed")


async def _retention_conflict_tick_once() -> None:
    if _db.async_session_factory is None:
        return
    try:
        from src.workers.maintenance.retention_conflict import scan_conflicts
    except Exception:  # noqa: BLE001
        _logger.exception("retention conflict scan import failed")
        return
    async with _db.async_session_factory() as session:
        try:
            await scan_conflicts(session)
        except Exception:  # noqa: BLE001
            await session.rollback()
            _logger.exception("retention conflict tick failed")


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
    # Bump the asyncio default executor pool size before the first
    # await. Python 3.12's default is ``min(32, cpu_count + 4)`` which
    # in a typical Docker container with cpuset=1 caps at 5 threads —
    # all of ``getaddrinfo``, blocking SQL prepared-statement compiles
    # and ``socket.connect`` use this same pool, and we run ~12
    # concurrent loops. Saturation manifests as a flood of
    # ``CancelledError`` → outer ``TimeoutError`` at boot, taking
    # Postgres + Redis + Bridge LLM down with it. 64 is comfortable
    # headroom without being wasteful.
    import concurrent.futures as _cf
    _loop = asyncio.get_running_loop()
    _loop.set_default_executor(_cf.ThreadPoolExecutor(max_workers=64))

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
    # Integration-keys cache shares the same stop signal so the
    # worker shuts it down on SIGTERM cleanly.
    from src.core import integration_keys as _integration_keys
    # Public threat-intel FeedScheduler (abuse.ch / GreyNoise / OTX /
    # BGP / CertStream / CIRCL MISP / etc.) runs alongside the worker
    # tick loops so its FeedHealth rows show up next to the others
    # in /admin → Feed Health. Previously it was orphaned in
    # ``src.main feeds|all`` modes that no compose container actually
    # invoked, leaving 17 feeds silently dark.
    from src.feeds.scheduler import FeedScheduler as _FeedScheduler
    _feed_scheduler = _FeedScheduler()

    async def _feed_scheduler_loop():
        try:
            await _feed_scheduler.start()
        except Exception:  # noqa: BLE001
            _logger.exception("public-feeds scheduler crashed")

    async def _feed_scheduler_stop_watch():
        await stop.wait()
        await _feed_scheduler.stop()

    loops = [
        _run_loop("easm", EASM_INTERVAL, _easm_tick_once, stop),
        _run_loop("sla", SLA_INTERVAL, _sla_tick_once, stop),
        _integration_keys.refresh_loop(stop),
        _feed_scheduler_loop(),
        _feed_scheduler_stop_watch(),
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
        _run_loop(
            "reprobe",
            REPROBE_INTERVAL,
            _reprobe_tick_once,
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
    if RANSOMWARE_REFRESH_INTERVAL > 0:
        loops.append(
            _run_loop(
                "ransomware_refresh",
                RANSOMWARE_REFRESH_INTERVAL,
                _ransomware_refresh_tick_once,
                stop,
            )
        )
    if TYPOSQUAT_SCAN_INTERVAL > 0:
        loops.append(
            _run_loop(
                "typosquat_scan",
                TYPOSQUAT_SCAN_INTERVAL,
                _typosquat_scan_tick_once,
                stop,
            )
        )
    if TELEGRAM_PRUNE_INTERVAL > 0:
        loops.append(
            _run_loop(
                "telegram_prune",
                TELEGRAM_PRUNE_INTERVAL,
                _telegram_prune_tick_once,
                stop,
            )
        )
    if NUCLEI_EASM_INTERVAL > 0:
        loops.append(
            _run_loop(
                "nuclei_easm",
                NUCLEI_EASM_INTERVAL,
                _nuclei_easm_tick_once,
                stop,
            )
        )
    if SURICATA_TAIL_INTERVAL > 0:
        loops.append(
            _run_loop(
                "suricata_tail",
                SURICATA_TAIL_INTERVAL,
                _suricata_tail_tick_once,
                stop,
            )
        )
    if PROWLER_AUDIT_INTERVAL > 0:
        loops.append(
            _run_loop(
                "prowler_audit",
                PROWLER_AUDIT_INTERVAL,
                _prowler_audit_tick_once,
                stop,
            )
        )
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
    # ---- Governance ticks (Phase 0)
    if RETENTION_INTERVAL > 0:
        loops.append(
            _run_loop(
                "retention_cleanup",
                RETENTION_INTERVAL,
                _retention_cleanup_tick_once,
                stop,
            )
        )
    if AGENT_DISPATCH_INTERVAL > 0:
        loops.append(
            _run_loop(
                "agent_dispatch",
                AGENT_DISPATCH_INTERVAL,
                _agent_dispatch_tick_once,
                stop,
            )
        )
    if DMARC_MAILBOX_INTERVAL > 0:
        loops.append(
            _run_loop(
                "dmarc_mailbox",
                DMARC_MAILBOX_INTERVAL,
                _dmarc_mailbox_tick_once,
                stop,
            )
        )
    if DMARC_SPIKE_SCAN_INTERVAL > 0:
        loops.append(
            _run_loop(
                "dmarc_spike_scan",
                DMARC_SPIKE_SCAN_INTERVAL,
                _dmarc_spike_scan_tick_once,
                stop,
            )
        )
    if PASTEBIN_INTERVAL > 0:
        loops.append(
            _run_loop(
                "pastebin_monitor",
                PASTEBIN_INTERVAL,
                _pastebin_monitor_tick_once,
                stop,
            )
        )
    if HIBP_CORRELATOR_INTERVAL > 0:
        loops.append(
            _run_loop(
                "hibp_correlator",
                HIBP_CORRELATOR_INTERVAL,
                _hibp_correlator_tick_once,
                stop,
            )
        )
    if LEAKAGE_BRIEFING_INTERVAL > 0:
        loops.append(
            _run_loop(
                "leakage_briefing",
                LEAKAGE_BRIEFING_INTERVAL,
                _leakage_briefing_tick_once,
                stop,
            )
        )
    if RETENTION_CONFLICT_INTERVAL > 0:
        loops.append(
            _run_loop(
                "retention_conflict",
                RETENTION_CONFLICT_INTERVAL,
                _retention_conflict_tick_once,
                stop,
            )
        )
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
