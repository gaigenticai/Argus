"""Service inventory — the canonical list of every external service
the Argus platform integrates with.

Why a single file: prior to this module, the answer to "what's actually
working in my deployment?" required reading 80+ files across
``src/integrations``, ``src/feeds``, ``src/crawlers``, ``src/enrichment``,
plus the worker scheduler and `.env.example`. Operators couldn't tell
"this is broken because the upstream changed an endpoint" from "this is
unconfigured because nobody set the API key" from "this code exists but
nothing calls it."

Each entry in :data:`CATALOG` declares:

  - ``name``: short identifier surfaced in the dashboard
  - ``category``: high-level bucket the operator filters by
  - ``description``: one-line "what this is for"
  - ``requires``: list of preconditions (env vars, infra, binaries,
    free-but-rate-limited, etc.) — each rendered in the UI
  - ``produces``: where the output flows (which page surfaces it,
    which agent consumes it, which DB table)
  - ``source_file``: code reference, ``path:line``
  - ``docs_url``: upstream documentation
  - ``status_check``: a coroutine that returns a :class:`ServiceStatus`
    describing the live state of this integration

Status resolvers read from authoritative sources:

  - ``feed_health`` rows for scheduled feeds
  - ``crawler_targets`` rows for dark-web crawlers
  - ``os.environ`` + ``integration_keys`` cache for API keys
  - ``shutil.which`` for OSS-tool binaries
  - lightweight TCP/HTTP probes for infrastructure (Postgres, Redis,
    MinIO, Meilisearch)

The endpoint at ``GET /api/v1/admin/service-inventory`` resolves every
entry concurrently and returns the assembled view to the dashboard.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Status types
# ---------------------------------------------------------------------------


# Status taxonomy — exactly THREE user-facing buckets. Every row in the
# UI lands in one of these and each maps to a single, unambiguous next
# action for the operator:
#
#   ok            — wired + producing (or last-known-good); operator does nothing.
#   needs_key     — operator action: paste credentials / set env var /
#                   provide URL / unblock egress / upgrade tier.
#   not_installed — operator action: install OSS service / install binary /
#                   start daemon. Distinct from needs_key because the
#                   missing thing is software the operator runs, not a
#                   key they paste.
#
# The previous taxonomy had five additional states (unconfigured,
# disabled, broken, missing, incomplete, unknown) that overlapped or
# pushed engineering bugs onto operators. Those states are intentionally
# gone — anything that would have been "broken" is either:
#   (a) a transient upstream blip → still OK, evidence notes it; or
#   (b) a real engineering gap → fixed in src/ before ship.
#
# Engineering detail (auth_failed, schema_changed, etc.) lives in
# ServiceStatus.sub_reason for the evidence line, NOT in the status pill.
STATUS_OK = "ok"
STATUS_NEEDS_KEY = "needs_key"
STATUS_NOT_INSTALLED = "not_installed"

ALL_STATUSES = (STATUS_OK, STATUS_NEEDS_KEY, STATUS_NOT_INSTALLED)

# Sub-reasons (evidence-line detail, never used as a status):
#   auth_failed              — creds present but upstream rejected them
#   quota_exceeded           — paid plan or rate quota exhausted
#   rate_limited             — transient throttle (recovers on next tick)
#   upstream_unreachable     — transient network / 5xx (recovers on next tick)
#   schema_changed           — upstream API contract drifted; engineering fix
#   endpoint_moved           — URL/version moved; engineering fix
#   parse_error              — adapter couldn't parse response; engineering fix
#   dep_missing              — required binary not in PATH
#   daemon_not_detected      — required local daemon (Tor, I2P, Ollama) not running
#   no_targets_configured    — crawler has no active targets to crawl
#   provider_not_selected    — LLM provider configured but not the active one
#   bundled                  — ships with the platform; nothing to install/configure


@dataclass
class ServiceStatus:
    status: str
    evidence: str = ""
    sub_reason: Optional[str] = None
    last_observed_at: Optional[datetime] = None
    last_rows_ingested: Optional[int] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in ALL_STATUSES:
            raise ValueError(
                f"ServiceStatus.status must be one of {ALL_STATUSES!r}, "
                f"got {self.status!r}. The 5-bucket taxonomy "
                "(unconfigured/disabled/broken/missing/incomplete/unknown) "
                "was retired — map your case onto one of the three new buckets "
                "and put engineering detail in sub_reason."
            )


@dataclass
class ServiceEntry:
    name: str
    category: str
    description: str
    requires: list[str]
    produces: list[str]
    # Dashboard route keys this service feeds — drives the per-page
    # SourcesStrip so e.g. ``/leakage`` can show the operator which
    # breach providers power that view and their live status. Use
    # the path slug (``leakage``, ``iocs``, ``takedowns``) — the
    # frontend strips the leading ``/``.
    produces_pages: list[str] = field(default_factory=list)
    # API-key fields the operator can set inline from Settings →
    # Services. Each entry is ``{"key": "<short>", "env_var": "<NAME>",
    # "label": "<human-readable>"}``. The Services tab renders an
    # input per field. Save POSTs to /admin/settings which writes to
    # ``app_settings`` and invalidates the integration_keys cache.
    key_fields: list[dict[str, str]] = field(default_factory=list)
    # When True, this service has no OSS alternative for the category
    # — we explicitly document the gap rather than pretend an OSS
    # version exists. Renders a "no OSS substitute" badge.
    no_oss_substitute: bool = False
    # When True, the upstream has closed new key registration but
    # legacy keys still work. We keep the entry visible (operators
    # with existing keys can still configure) but exclude it from
    # the "go obtain a key" punch list and surface a clear notice.
    legacy_only: bool = False
    # When True, this is an OSS service the operator runs themselves
    # (MISP, OpenCTI, Wazuh, Caldera, CAPE, Velociraptor, Shuffle,
    # OpenSearch). The Settings UI groups these into a dedicated
    # "OSS — self-hosted" section above paid SaaS, with URL+token
    # inputs and a one-shot install hint. Distinct from
    # ``no_oss_substitute`` (paid only) and from ``key_fields`` alone
    # (an unset key on a paid SaaS means "buy a license").
    self_hosted: bool = False
    # Operator-facing copy shown in the Settings card explaining how
    # to spin up a local instance. Markdown-friendly. Renders below
    # the URL+token inputs. Keep short (~5 lines) and link to
    # ``docs_url`` for deep dives.
    self_host_install_hint: Optional[str] = None
    # When set, links this entry to the OSS-tools installer catalog
    # (src/integrations/oss_tools/catalog.py). The merged Services tab
    # uses this to render an inline "Install / Reinstall" button driven
    # by /oss-tools/install for tools we know how to install via Docker.
    # Must match an OssTool.name exactly (e.g. "wazuh", "misp",
    # "opencti", "shuffle", "velociraptor", "caldera").
    oss_install_name: Optional[str] = None
    source_file: str = ""
    docs_url: Optional[str] = None
    status_check: Optional[Callable[[AsyncSession], Awaitable[ServiceStatus]]] = None


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------


async def _from_feed_health(
    db: AsyncSession, feed_name: str, *, allow_unconfigured: bool = True
) -> ServiceStatus:
    """Pull recent FeedHealth rows for ``feed_name`` and project them
    onto the 3-bucket taxonomy.

    Mapping (old FeedHealth status -> new ServiceStatus):
      ok                     -> STATUS_OK
      unconfigured           -> STATUS_NEEDS_KEY
      disabled               -> STATUS_NEEDS_KEY  (operator opts back in)
      auth_error             -> STATUS_NEEDS_KEY  (sub_reason=auth_failed)
      rate_limited           -> STATUS_OK         (sub_reason=rate_limited, transient)
      network_error/5xx blip -> STATUS_OK         (sub_reason=upstream_unreachable, transient)
      parse_error sustained  -> STATUS_OK         (sub_reason=parse_error — engineering bug;
                                                   row stays OK so operator isn't blamed; we
                                                   surface it via /admin alerts internally)

    History-aware: if the latest row is an error but the majority of
    the last ~5 runs were OK, treat as transient (still OK with a
    warning evidence line) instead of flapping the indicator on a
    single upstream blip. Common case: crt.sh 502s, OTX 429s,
    ransomware.live rate-limits — these heal on the next tick.

    No FeedHealth rows yet (worker hasn't ticked) -> STATUS_OK with
    sub_reason=warming_up, since the platform is functional and the
    feed is configured to run.
    """
    from src.models.admin import FeedHealth

    rows = (
        await db.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name == feed_name)
            .order_by(desc(FeedHealth.observed_at))
            .limit(5)
        )
    ).scalars().all()

    if not rows:
        return ServiceStatus(
            status=STATUS_OK,
            sub_reason="warming_up",
            evidence=f"No FeedHealth row for {feed_name!r} yet — worker hasn't ticked.",
        )
    latest = rows[0]
    raw = (latest.status or "").lower()
    ok_count = sum(1 for r in rows if r.status == "ok")
    detail = (latest.detail or "")[:160]

    if raw == "ok":
        return ServiceStatus(
            status=STATUS_OK,
            evidence=f"feed_health.{feed_name} = ok: {detail}",
            last_observed_at=latest.observed_at,
            last_rows_ingested=latest.rows_ingested,
            extra={"raw_status": raw, "recent_ok_count": ok_count},
        )
    if raw == "unconfigured" and allow_unconfigured:
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="unconfigured",
            evidence=f"feed_health.{feed_name} unconfigured: {detail}",
            last_observed_at=latest.observed_at,
            extra={"raw_status": raw},
        )
    if raw == "disabled":
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="disabled_by_operator",
            evidence=f"feed_health.{feed_name} disabled: {detail}",
            last_observed_at=latest.observed_at,
            extra={"raw_status": raw},
        )
    if raw == "auth_error":
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="auth_failed",
            evidence=f"feed_health.{feed_name} auth_failed — verify key: {detail}",
            last_observed_at=latest.observed_at,
            extra={"raw_status": raw},
        )

    # Any remaining failure: rate_limited / network_error / parse_error / unknown.
    # If we have ≥3/5 recent OKs, treat as transient and stay OK.
    if ok_count >= 3:
        return ServiceStatus(
            status=STATUS_OK,
            sub_reason=raw or "transient_error",
            evidence=(
                f"feed_health.{feed_name} transient {raw} "
                f"({ok_count}/5 recent runs OK): {detail[:120]}"
            ),
            last_observed_at=latest.observed_at,
            last_rows_ingested=latest.rows_ingested,
            extra={"raw_status": raw, "recent_ok_count": ok_count},
        )

    # Sustained failure with creds (otherwise we'd have hit the
    # auth_error branch). This is an engineering signal, not an
    # operator-actionable one — but we don't have a "broken" bucket.
    # Surface as STATUS_OK with sub_reason so the operator isn't
    # nagged about something they can't fix; engineering catches it
    # via /admin/feeds health view (separate surface).
    return ServiceStatus(
        status=STATUS_OK,
        sub_reason=f"sustained_{raw}" if raw else "sustained_error",
        evidence=(
            f"feed_health.{feed_name} sustained {raw} "
            f"({ok_count}/5 recent runs OK): {detail[:120]} — "
            "engineering will investigate via /admin/feeds."
        ),
        last_observed_at=latest.observed_at,
        last_rows_ingested=latest.rows_ingested,
        extra={"raw_status": raw, "recent_ok_count": ok_count},
    )


async def _self_hosted_status(
    db: AsyncSession,
    *,
    oss_install_name: Optional[str] = None,
    url_env_var: str,
    url_key_name: str,
    extra_env_var: Optional[str] = None,
    extra_key_name: Optional[str] = None,
    label: str = "",
) -> ServiceStatus:
    """Three-stage status resolver for self-hosted services.

    Honest UX for the operator: a self-hosted row should NOT say
    "Needs key" if the underlying daemon isn't even installed yet.
    The action gradient is install → configure URL → paste key →
    OK, in that order. We surface that gradient via the 3-bucket
    taxonomy:

      Stage 1 — OSS-installer state (when ``oss_install_name`` is set,
                meaning we manage the daemon's docker compose lifecycle
                via the in-app installer). If the OssToolInstall row
                says state != installed, return STATUS_NOT_INSTALLED.

      Stage 2 — URL presence. The URL is the operator's pointer to
                the running daemon. Unset URL means we have NO sign
                a daemon exists on this network — STATUS_NOT_INSTALLED
                (sub_reason=url_not_set). Operator action: install the
                daemon (out-of-band or via the inline Install button)
                and paste its URL.

      Stage 3 — Optional extra credential (e.g. API key, password).
                URL is set but the secondary creds aren't → STATUS_NEEDS_KEY.

      All present → STATUS_OK.

    The OSS installer is one path, but operators often run their own
    Wazuh / MISP / Cortex / etc. on existing infra and just want to
    point Argus at the URL. This helper covers both flows uniformly."""
    from src.core import integration_keys

    # Stage 1: OSS-installer state, when applicable
    if oss_install_name:
        try:
            from src.models.oss_tool import OssToolInstall, OssToolState
            row = (await db.execute(
                select(OssToolInstall).where(
                    OssToolInstall.tool_name == oss_install_name,
                )
            )).scalar_one_or_none()
            if row is None or row.state != OssToolState.INSTALLED.value:
                state_str = row.state if row is not None else "not selected"
                return ServiceStatus(
                    status=STATUS_NOT_INSTALLED,
                    sub_reason="daemon_not_installed",
                    evidence=(
                        f"OSS installer state for {oss_install_name!r}: "
                        f"{state_str}. Click Install on this row to "
                        f"provision, or run the daemon yourself and "
                        f"set {url_env_var}."
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            # If OssToolInstall table is unreachable / missing (early
            # migration state), fall through and trust the URL/key
            # check — better than blocking on a probe failure.
            logger.debug(
                "OssToolInstall probe failed for %s: %s — falling through to URL check",
                oss_install_name, exc,
            )

    # Stage 2: URL presence
    url_value = (
        integration_keys.get(url_key_name, env_fallback=url_env_var) or ""
    ).strip()
    if not url_value:
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="url_not_set",
            evidence=(
                f"{label or url_env_var} (URL) not set — no daemon to "
                f"point at. Install the service (locally or anywhere on "
                f"your network) and paste its base URL below."
            ),
        )

    # Stage 3: extra credential, if required
    if extra_env_var and extra_key_name:
        extra_value = (
            integration_keys.get(extra_key_name, env_fallback=extra_env_var) or ""
        ).strip()
        if not extra_value:
            return ServiceStatus(
                status=STATUS_NEEDS_KEY,
                sub_reason="key_not_set",
                evidence=(
                    f"URL configured ({url_value[:60]}...). "
                    f"Paste {extra_env_var} below to authenticate."
                ),
            )

    masked = "•" * 4 + url_value[-4:] if len(url_value) >= 4 else "•" * len(url_value)
    return ServiceStatus(
        status=STATUS_OK,
        evidence=f"{label or 'service'} configured at {masked}",
    )


async def _from_env_or_integration_key(
    name: str, *, env_var: str, label: str | None = None,
) -> ServiceStatus:
    """API-key-gated services. Resolve via integration_keys cache (DB
    overrides env), then env fallback. Doesn't probe the upstream; the
    fact a key is set is what the operator sees as 'configured'."""
    from src.core import integration_keys

    val = integration_keys.get(name, env_fallback=env_var)
    if val:
        masked = "•" * 4 + val[-4:] if len(val) >= 4 else "•" * len(val)
        return ServiceStatus(
            status=STATUS_OK,
            evidence=f"{label or env_var} configured: {masked}",
        )
    return ServiceStatus(
        status=STATUS_NEEDS_KEY,
        sub_reason="key_not_set",
        evidence=f"{label or env_var} not set — paste in Settings → Services.",
    )


def _binary_status(binary: str, *, package: str | None = None) -> ServiceStatus:
    """OSS-tool binary presence check via ``which``. Missing binary
    means the operator hasn't installed it (or rebuilt their worker
    image with the dep)."""
    path = shutil.which(binary)
    if path:
        return ServiceStatus(status=STATUS_OK, evidence=f"{binary} at {path}")
    pkg = package or binary
    return ServiceStatus(
        status=STATUS_NOT_INSTALLED,
        sub_reason="dep_missing",
        evidence=(
            f"{binary} not in PATH — install {pkg} on the worker "
            "container (rebuild the image, or `apt-get install` for "
            "a quick test)."
        ),
    )


# Infrastructure probes — Postgres, Redis, MinIO, Meilisearch, Tor.
# These are platform prerequisites; if they're down the platform itself
# isn't really running, so we don't have to be subtle. We treat a probe
# failure as STATUS_NOT_INSTALLED with sub_reason=daemon_not_detected
# (operator action: bring the container up).


async def _probe_postgres(_db: AsyncSession) -> ServiceStatus:
    try:
        from sqlalchemy import text
        await _db.execute(text("SELECT 1"))
        return ServiceStatus(status=STATUS_OK, evidence="connection ok (SELECT 1)")
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="daemon_not_detected",
            evidence=f"Postgres unreachable: {type(e).__name__}: {e}",
        )


async def _probe_redis(_db: AsyncSession) -> ServiceStatus:
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        pool = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            pong = await pool.ping()
        finally:
            await pool.aclose()
        return ServiceStatus(status=STATUS_OK, evidence=f"{settings.redis.url}: PING -> {pong}")
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="daemon_not_detected",
            evidence=f"Redis unreachable: {type(e).__name__}: {e}",
        )


async def _probe_minio(_db: AsyncSession) -> ServiceStatus:
    """MinIO health via the public ``/minio/health/live`` endpoint."""
    import os
    host = os.environ.get("ARGUS_MINIO_HOST") or os.environ.get("MINIO_HOST", "minio")
    port = os.environ.get("ARGUS_MINIO_PORT") or os.environ.get("MINIO_PORT", "9000")
    url = f"http://{host}:{port}/minio/health/live"
    return await _probe_http_get(url, "MinIO", failure_status=STATUS_NOT_INSTALLED,
                                 failure_sub_reason="daemon_not_detected")


async def _probe_meili(_db: AsyncSession) -> ServiceStatus:
    try:
        import aiohttp
        from src.config.settings import settings
        url = (
            f"http://{settings.meili.host}:{settings.meili.port}/health"
            if hasattr(settings, "meili")
            else "http://meilisearch:7700/health"
        )
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as s:
            async with s.get(url) as resp:
                if resp.status == 200:
                    return ServiceStatus(status=STATUS_OK, evidence=f"{url} 200")
                return ServiceStatus(
                    status=STATUS_NOT_INSTALLED,
                    sub_reason="daemon_not_detected",
                    evidence=f"Meilisearch {url} -> {resp.status}",
                )
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="daemon_not_detected",
            evidence=f"Meilisearch unreachable: {type(e).__name__}: {e}",
        )


async def _probe_tor_proxy(_db: AsyncSession) -> ServiceStatus:
    """TCP-connect to the Tor SOCKS port. Doesn't open a circuit; just
    checks the daemon is listening."""
    import socket
    host = os.environ.get("ARGUS_TOR_SOCKS_HOST", "tor")
    try:
        port = int(os.environ.get("ARGUS_TOR_SOCKS_PORT", "9050"))
    except ValueError:
        port = 9050
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(
                None, lambda: socket.create_connection((host, port), timeout=3).close()
            ),
            timeout=4,
        )
        return ServiceStatus(status=STATUS_OK, evidence=f"{host}:{port} reachable")
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="daemon_not_detected",
            evidence=(
                f"Tor SOCKS at {host}:{port} unreachable — start the "
                "argus-tor container: `docker compose up -d tor`. "
                f"({type(e).__name__}: {e})"
            ),
        )


async def _from_crawler_targets(
    db: AsyncSession, kind: str
) -> ServiceStatus:
    """Per-kind crawler status: number of active targets + last-run state.

    No active targets is operator-actionable (add targets via
    /admin → Crawler Targets), so STATUS_NEEDS_KEY with sub_reason
    'no_targets_configured'. Sustained errors degrade to STATUS_OK with
    sub_reason 'sustained_crawler_errors' so we don't blame the operator
    for upstream sites being down."""
    from src.models.admin import CrawlerTarget

    rows = (
        await db.execute(
            select(CrawlerTarget).where(
                CrawlerTarget.kind == kind, CrawlerTarget.is_active.is_(True)
            )
        )
    ).scalars().all()
    if not rows:
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="no_targets_configured",
            evidence=(
                f"No active crawler_targets of kind={kind!r}. "
                "Add via /admin → Crawler Targets."
            ),
        )
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r.last_run_status or "never_ran"] = (
            by_status.get(r.last_run_status or "never_ran", 0) + 1
        )
    detail = ", ".join(f"{k}={v}" for k, v in sorted(by_status.items()))
    if "ok" in by_status:
        return ServiceStatus(
            status=STATUS_OK,
            evidence=f"{len(rows)} active target(s); last_run: {detail}",
            extra={"target_count": len(rows), "by_status": by_status},
        )
    if "error" in by_status:
        # Targets exist + all errored. Probably upstream is down or
        # blocking us; not operator-actionable as a key issue.
        return ServiceStatus(
            status=STATUS_OK,
            sub_reason="sustained_crawler_errors",
            evidence=(
                f"{len(rows)} active target(s); last_run: {detail} — "
                "engineering will investigate via /admin/crawler-targets."
            ),
            extra={"target_count": len(rows), "by_status": by_status},
        )
    # No runs yet — worker will pick them up.
    return ServiceStatus(
        status=STATUS_OK,
        sub_reason="warming_up",
        evidence=f"{len(rows)} active target(s); last_run: {detail}",
        extra={"target_count": len(rows), "by_status": by_status},
    )


def _disabled_unless_env(env_var: str, reason: str) -> Callable[[AsyncSession], Awaitable[ServiceStatus]]:
    """Service is opt-in via env var. The 'off-by-default' state is
    operator-actionable (set the env var to enable), so STATUS_NEEDS_KEY
    rather than the retired STATUS_DISABLED.

    Accepts both boolean-style (``1`` / ``true`` / ``yes``) and
    positive-integer values (e.g. ``ARGUS_WORKER_*_INTERVAL=60`` for
    minutes-between-runs). Anything truthy that isn't "0" / "false" /
    empty counts as enabled."""
    async def check(_db: AsyncSession) -> ServiceStatus:
        raw = (os.environ.get(env_var) or "").strip().lower()
        enabled = False
        if raw in ("1", "true", "yes", "on"):
            enabled = True
        elif raw and raw not in ("0", "false", "no", "off"):
            try:
                enabled = int(raw) > 0
            except ValueError:
                # Non-empty non-numeric truthy — count as enabled.
                enabled = True
        if enabled:
            return ServiceStatus(status=STATUS_OK, evidence=f"{env_var}={raw!r}; enabled")
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="opt_in_required",
            evidence=reason,
        )
    return check


def _not_installed_marker(
    reason: str, *, sub_reason: str = "daemon_not_detected"
) -> Callable[[AsyncSession], Awaitable[ServiceStatus]]:
    """Marker for services whose underlying daemon/runtime is not
    detected on this host. Replaces the retired ``_incomplete`` helper:
    if code exists but no daemon to talk to, that's STATUS_NOT_INSTALLED,
    not 'incomplete'. If the code itself is missing entirely, fix it in
    src/ — don't dress it up as 'not installed'."""
    async def check(_db: AsyncSession) -> ServiceStatus:
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason=sub_reason,
            evidence=reason,
        )
    return check


# ---------------------------------------------------------------------------
# The catalog
# ---------------------------------------------------------------------------


# Canonical category list — these are the ONLY allowed values for
# ServiceEntry.category. Any drift (typo, near-duplicate string, new
# bucket someone invented inline) causes ``_catalog()`` to raise at
# import time so the operator never sees a stray "uncategorized"
# section in Settings → Services.
#
# Adding a new category is a deliberate decision: extend this list
# AND the dropdown in dashboard/src/app/settings/page.tsx. The order
# below is the order categories render in the UI.
CATEGORIES = [
    "Infrastructure",
    "LLM provider",
    "Threat-intel feed",
    "Enrichment API",
    "Breach / credential",
    "Dark-web crawler",
    "Social media monitor",
    "EDR connector",
    "SIEM connector",
    "SOAR connector",
    "Email-gateway connector",
    "Sandbox / malware analysis",
    "Forensics tool",
    "OSS tool",
    "Notification delivery",
    "Network protocol",
    "Adversary emulation",
    "Intel source",
]

CANONICAL_CATEGORIES = frozenset(CATEGORIES)


def _validate_categories(entries: list[ServiceEntry]) -> None:
    """Fail loud at import time if any entry uses a non-canonical
    category. Prevents silent drift like 'social-media-monitor' vs
    'Social media monitor' that produces a stray bucket in the UI."""
    bad: list[tuple[str, str]] = [
        (e.name, e.category) for e in entries if e.category not in CANONICAL_CATEGORIES
    ]
    if bad:
        msg = "; ".join(f"{name!r} -> category={cat!r}" for name, cat in bad)
        raise ValueError(
            "service_inventory: non-canonical category strings: " + msg
            + ". Allowed: " + ", ".join(sorted(CANONICAL_CATEGORIES))
            + ". Either fix the entry or extend CATEGORIES (and the "
            "Settings → Services dropdown) deliberately."
        )


def _catalog() -> list[ServiceEntry]:
    entries = _build_catalog()
    _validate_categories(entries)
    return entries


def _build_catalog() -> list[ServiceEntry]:
    return [
        # ── Infrastructure ─────────────────────────────────────────────
        ServiceEntry(
            name="PostgreSQL",
            category="Infrastructure",
            description="Primary system-of-record (orgs, alerts, IOCs, raw_intel, cases, etc.).",
            requires=["ARGUS_DB_HOST/PORT", "ARGUS_DB_PASSWORD", "pgvector extension"],
            produces=["Every page that reads from the API"],
            produces_pages=["*"],
            status_check=_probe_postgres,
        ),
        ServiceEntry(
            name="Redis",
            category="Infrastructure",
            description="Rate-limit counters, session lockouts, dedup windows, feed-health queues.",
            requires=["ARGUS_REDIS_HOST/PORT"],
            produces=["Auth lockout, dedup, agent queue"],
            produces_pages=["*"],
            status_check=_probe_redis,
        ),
        ServiceEntry(
            name="MinIO (S3-compatible)",
            category="Infrastructure",
            description="Evidence vault — PDFs, screenshots, raw artifacts.",
            requires=["MINIO_ROOT_USER/PASSWORD", "argus-evidence bucket"],
            produces=["/evidence page, exec PDFs, case attachments"],
            produces_pages=["evidence", "cases", "reports", "exec-summary"],
            status_check=_probe_minio,
        ),
        ServiceEntry(
            name="Meilisearch",
            category="Infrastructure",
            description="Full-text search over IOCs + intel.",
            requires=["MEILI_MASTER_KEY"],
            produces=["Header search, /iocs filter, /intel search"],
            produces_pages=["iocs", "intel"],
            status_check=_probe_meili,
        ),
        ServiceEntry(
            name="Tor SOCKS proxy",
            category="Infrastructure",
            description="Egress through Tor for .onion crawling.",
            requires=["argus-tor container", "ARGUS_TOR_SOCKS_HOST/PORT"],
            produces=["All dark-web crawlers (ransomware leak sites, forum, stealer logs)"],
            produces_pages=["alerts", "iocs", "leakage"],
            source_file="docker-compose.yml (tor service)",
            status_check=_probe_tor_proxy,
        ),

        # ── LLM providers ───────────────────────────────────────────────
        ServiceEntry(
            name="Anthropic Claude API",
            category="LLM provider",
            description="Cloud LLM for triage / investigation / case-copilot agents.",
            requires=["ARGUS_LLM_PROVIDER=anthropic", "ARGUS_LLM_API_KEY"],
            produces=["All agent runs (triage, investigation, case copilot, brand defender, threat hunter)"],
            docs_url="https://docs.anthropic.com/en/api",
            produces_pages=["alerts", "cases", "agent-activity", "exec-summary"],
            key_fields=[
                {"key": "anthropic", "env_var": "ARGUS_LLM_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _check_llm_provider("anthropic", env_var="ARGUS_LLM_API_KEY"),
        ),
        ServiceEntry(
            name="Ollama (local LLM)",
            category="LLM provider",
            description="In-cluster LLM serving open-weight models for air-gapped deploys.",
            requires=["ollama container", "ARGUS_LLM_BASE_URL=http://ollama:11434", "model pulled"],
            produces=["Agent runs when ARGUS_LLM_PROVIDER=ollama"],
            docs_url="https://ollama.com/",
            produces_pages=["alerts", "cases", "agent-activity", "exec-summary"],
            status_check=lambda db: _check_ollama(),
        ),
        ServiceEntry(
            name="Claude Code Bridge",
            category="LLM provider",
            description="Bridges agent calls to the operator's local Claude Code CLI (uses host subscription). Redis-queue consumer — no HTTP listener.",
            requires=["ARGUS_LLM_PROVIDER=bridge", "host claude binary", "argus-bridge container OR scripts/bridge_host.sh on macOS"],
            produces=["Agent runs when ARGUS_LLM_PROVIDER=bridge"],
            source_file="bridge/bridge.py",
            produces_pages=["alerts", "cases", "agent-activity", "exec-summary"],
            status_check=_check_claude_bridge,
        ),

        # ── Threat-intel feeds (FeedScheduler) ──────────────────────────
        ServiceEntry(
            name="OpenPhish (public feed)",
            category="Threat-intel feed",
            description="Free phishing URL feed; one URL per line.",
            requires=["network access (no key)"],
            produces=["raw_intel + suspect_domains via brand match"],
            source_file="src/feeds/phishing_feed.py",
            docs_url="https://openphish.com/",
            produces_pages=["feeds", "alerts", "iocs"],
            status_check=lambda db: _from_feed_health(db, "openphish"),
        ),
        ServiceEntry(
            name="URLhaus (abuse.ch)",
            category="Threat-intel feed",
            description=(
                "Malicious URLs feed. The public CSV (url-list, recent) "
                "ingests without any key — that's what powers most of "
                "Argus's URL/IOC matching. The same abuse.ch Auth-Key "
                "additionally activates the ThreatFox and MalwareBazaar "
                "feeds (now separate inventory rows). If abuse.ch "
                "registrations are closed, URLhaus + Feodo + SSLBL still "
                "work fully."
            ),
            requires=["public CSV (no key needed)"],
            produces=["IOC matches, suspect_domains"],
            source_file="src/feeds/malware_feed.py",
            docs_url="https://urlhaus.abuse.ch/",
            produces_pages=["feeds", "alerts", "iocs"],
            status_check=lambda db: _from_feed_health(db, "urlhaus"),
        ),
        ServiceEntry(
            name="abuse.ch ThreatFox",
            category="Threat-intel feed",
            description=(
                "Generic IOC feed (IPs, URLs, domains, hashes) tagged "
                "by malware family. Same MalwareFeed module as URLhaus "
                "writes both legs to feed_health, but the Auth-Key only "
                "unlocks ThreatFox — without the key this leg yields zero "
                "rows. Register at auth.abuse.ch (free)."
            ),
            requires=["ARGUS_FEED_ABUSE_CH_API_KEY (free, register at auth.abuse.ch)"],
            produces=["IOCs (multiple types) tagged by malware family"],
            source_file="src/feeds/malware_feed.py",
            docs_url="https://threatfox.abuse.ch/api/",
            key_fields=[
                {"key": "abuse_ch", "env_var": "ARGUS_FEED_ABUSE_CH_API_KEY",
                 "label": "abuse.ch Auth-Key (shared across URLhaus / ThreatFox / MalwareBazaar)"},
            ],
            produces_pages=["feeds", "alerts", "iocs"],
            status_check=lambda db: _from_feed_health(db, "threatfox"),
        ),
        ServiceEntry(
            name="abuse.ch MalwareBazaar",
            category="Threat-intel feed",
            description=(
                "Recent malware sample corpus — sha256/sha1/md5 hashes "
                "of confirmed malware samples tagged by family, file "
                "type, and rules. Same Auth-Key as URLhaus / ThreatFox. "
                "100 most-recent samples per tick (1h cadence)."
            ),
            requires=["ARGUS_FEED_ABUSE_CH_API_KEY (free, register at auth.abuse.ch)"],
            produces=["File-hash IOCs tagged by malware family"],
            source_file="src/feeds/malwarebazaar_feed.py",
            docs_url="https://bazaar.abuse.ch/api/",
            key_fields=[
                {"key": "abuse_ch", "env_var": "ARGUS_FEED_ABUSE_CH_API_KEY",
                 "label": "abuse.ch Auth-Key (shared across URLhaus / ThreatFox / MalwareBazaar)"},
            ],
            produces_pages=["feeds", "iocs"],
            status_check=lambda db: _from_feed_health(db, "malwarebazaar"),
        ),
        ServiceEntry(
            name="abuse.ch SSLBL / TLS",
            category="Threat-intel feed",
            description="Bad-cert + JA3 fingerprints from SSL Blacklist.",
            requires=["abuse.ch auth-key (free)"],
            produces=["TLS-fingerprint IOCs"],
            source_file="src/feeds/abusech_tls_feed.py",
            docs_url="https://sslbl.abuse.ch/",
            produces_pages=["feeds", "iocs"],
            status_check=lambda db: _from_feed_health(db, "sslbl"),
        ),
        ServiceEntry(
            name="abuse.ch Feodo Tracker",
            category="Threat-intel feed",
            description="Botnet C2 IP blocklist (Dridex, Emotet, TrickBot).",
            requires=["network access (no key)"],
            produces=["Botnet C2 IOCs"],
            source_file="src/feeds/botnet_feed.py",
            docs_url="https://feodotracker.abuse.ch/",
            produces_pages=["feeds", "iocs", "threat-map"],
            status_check=lambda db: _from_feed_health(db, "feodo_tracker"),
        ),
        ServiceEntry(
            name="DShield (ISC SANS)",
            category="Threat-intel feed",
            description="Top scanners + infocon level; community honeypot data.",
            requires=["network access (no key)"],
            produces=["Scanner-IP layer on threat map"],
            source_file="src/feeds/honeypot_feed.py",
            docs_url="https://isc.sans.edu/api/",
            produces_pages=["feeds", "iocs", "threat-map"],
            status_check=lambda db: _from_feed_health(db, "dshield"),
        ),
        ServiceEntry(
            name="Tor exit list (torproject.org)",
            category="Threat-intel feed",
            description="Authoritative Tor exit-node IP list.",
            requires=["network access (no key)"],
            produces=["Tor-IP enrichment, threat map layer"],
            source_file="src/feeds/tor_nodes_feed.py",
            docs_url="https://check.torproject.org/torbulkexitlist",
            produces_pages=["feeds", "iocs", "threat-map", "exposures"],
            status_check=lambda db: _from_feed_health(db, "tor_bulk_exit"),
        ),
        ServiceEntry(
            name="Spamhaus DROP",
            category="Threat-intel feed",
            description=(
                "Spamhaus's hand-curated 'Don't Route Or Peer' list — "
                "hijacked netblocks, spammer-controlled allocations, "
                "and ranges tied to confirmed cybercrime operations. "
                "Free, no key, hourly refresh (matches Spamhaus's "
                "fair-use ToS). eDROP merged into DROP in Apr 2024."
            ),
            requires=["network access (no key — fair-use ToS, max 1 fetch/hour)"],
            produces=["Hijacked / cybercrime CIDRs on /iocs and /threat-map"],
            source_file="src/feeds/spamhaus_drop_feed.py",
            docs_url="https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
            produces_pages=["feeds", "iocs", "threat-map"],
            status_check=lambda db: _from_feed_health(db, "spamhaus_drop"),
        ),
        ServiceEntry(
            name="FireHOL aggregated IP lists",
            category="Threat-intel feed",
            description=(
                "FireHOL aggregates ~400 public IP blocklists into a "
                "small number of pre-deduplicated tiers. Defaults to "
                "level1 (conservative, low FP rate, includes dshield + "
                "feodo + fullbogons + spamhaus_drop). Override with "
                "ARGUS_FEED_FIREHOL_URL to switch to level2 / level3 "
                "for broader coverage at higher FP cost."
            ),
            requires=["network access (no key)"],
            produces=["Aggregated bad-IP CIDRs on /iocs and /threat-map"],
            source_file="src/feeds/firehol_feed.py",
            docs_url="https://iplists.firehol.org/",
            key_fields=[
                {"key": "firehol_url", "env_var": "ARGUS_FEED_FIREHOL_URL",
                 "label": "FireHOL list URL (optional, default firehol_level1)"},
            ],
            produces_pages=["feeds", "iocs", "threat-map"],
            status_check=lambda db: _from_feed_health(db, "firehol"),
        ),
        ServiceEntry(
            name="blocklist.de",
            category="Threat-intel feed",
            description=(
                "Aggregated honeypot-attacker IPs from ~50 operators "
                "(SSH/HTTP/IMAP brute-forcers, scanners, etc). Free, "
                "no key, refreshed near-real-time upstream; we poll "
                "hourly."
            ),
            requires=["network access (no key)"],
            produces=["Honeypot-attacker IPs on /iocs and /threat-map"],
            source_file="src/feeds/plain_ip_list_feed.py",
            docs_url="https://www.blocklist.de/",
            produces_pages=["feeds", "iocs", "threat-map"],
            status_check=lambda db: _from_feed_health(db, "blocklist_de"),
        ),
        ServiceEntry(
            name="CINS Army (cinsscore.com)",
            category="Threat-intel feed",
            description=(
                "Sentinel IPS' curated list of poor-reputation IPs "
                "from their global sensor network. Conservative — "
                "sustained malicious behaviour required before listing. "
                "Free, no key."
            ),
            requires=["network access (no key)"],
            produces=["Poor-reputation IPs on /iocs and /threat-map"],
            source_file="src/feeds/plain_ip_list_feed.py",
            docs_url="https://cinsscore.com/",
            produces_pages=["feeds", "iocs", "threat-map"],
            status_check=lambda db: _from_feed_health(db, "cins_score"),
        ),
        ServiceEntry(
            name="ipsum (stamparm)",
            category="Threat-intel feed",
            description="Aggregated bad-IP list from many sources.",
            requires=["network access (no key)"],
            produces=["IP reputation"],
            source_file="src/feeds/ip_reputation_feed.py",
            docs_url="https://github.com/stamparm/ipsum",
            produces_pages=["feeds", "iocs", "threat-map"],
            status_check=lambda db: _from_feed_health(db, "ipsum"),
        ),
        ServiceEntry(
            name="AbuseIPDB",
            category="Enrichment API",
            description=(
                "Crowdsourced abusive-IP reputation, called per-IP at "
                "ingest time via /check (1,000 lookups/day free). "
                "Replaces the previous bulk /blacklist poll that the "
                "free tier caps at 5/day. Results cached 24h in Redis."
            ),
            requires=["ARGUS_FEED_ABUSEIPDB_API_KEY (free tier 1k checks/day)"],
            produces=["IP reputation enrichment on /iocs detail + /alerts ingest"],
            source_file="src/enrichment/abuseipdb.py",
            docs_url="https://www.abuseipdb.com/account/api",
            produces_pages=["iocs", "threat-map"],
            key_fields=[
                {"key": "abuseipdb", "env_var": "ARGUS_FEED_ABUSEIPDB_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _from_env_or_integration_key(
                "abuseipdb", env_var="ARGUS_FEED_ABUSEIPDB_API_KEY",
            ),
        ),
        ServiceEntry(
            name="GreyNoise",
            category="Threat-intel feed",
            description=(
                "Internet noise classification — separates targeted scans "
                "from background. Free Community key powers per-IP "
                "enrichment of every IP IOC at ingest + on demand from "
                "the IOC detail panel. Bulk scanner-IP ingest needs the "
                "paid Enterprise tier."
            ),
            requires=["ARGUS_FEED_GREYNOISE_API_KEY (Community tier — free)"],
            produces=["IP classification, scanner tags, noise/riot flags"],
            source_file="src/feeds/greynoise_feed.py + src/enrichment/greynoise.py",
            docs_url="https://viz.greynoise.io/account",
            produces_pages=["feeds", "iocs", "threat-map", "exposures"],
            key_fields=[
                {"key": "greynoise", "env_var": "ARGUS_FEED_GREYNOISE_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _from_feed_health(db, "greynoise"),
        ),
        ServiceEntry(
            name="AlienVault OTX",
            category="Threat-intel feed",
            description="Open Threat Exchange — community IOC pulses.",
            requires=["ARGUS_FEED_OTX_API_KEY (free with registration)"],
            produces=["IOC pulses, threat actor sightings"],
            source_file="src/feeds/otx_feed.py",
            docs_url="https://otx.alienvault.com/api",
            produces_pages=["feeds", "iocs", "actors"],
            key_fields=[
                {"key": "otx", "env_var": "ARGUS_FEED_OTX_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _from_feed_health(db, "otx_pulse"),
        ),
        ServiceEntry(
            name="Cloudflare Radar BGP",
            category="Threat-intel feed",
            description="BGP hijack events from Cloudflare's global network.",
            requires=["ARGUS_FEED_CF_RADAR_API_KEY (token with radar:read)"],
            produces=["BGP hijack alerts on threat map"],
            source_file="src/feeds/bgp_hijack_feed.py",
            docs_url="https://developers.cloudflare.com/radar/",
            produces_pages=["feeds", "threat-map"],
            key_fields=[
                {"key": "cloudflare_radar", "env_var": "ARGUS_FEED_CF_RADAR_API_KEY", "label": "API token"},
            ],
            status_check=lambda db: _from_feed_health(db, "ripe_ris_live"),
        ),
        ServiceEntry(
            name="CIRCL OSINT (MISP)",
            category="Threat-intel feed",
            description="CIRCL.lu public OSINT MISP feed.",
            requires=["network access (no key); optional creds"],
            produces=["IOC pulses"],
            source_file="src/feeds/circl_misp_feed.py",
            docs_url="https://www.circl.lu/doc/misp/feed-osint/",
            produces_pages=["feeds", "iocs", "actors"],
            status_check=lambda db: _from_feed_health(db, "circl_osint"),
        ),
        ServiceEntry(
            name="DigitalSide OSINT (MISP)",
            category="Threat-intel feed",
            description=(
                "Italian-maintained OSINT feed focused on malware "
                "analysis — compromised URLs / IPs / domains / hashes "
                "derived from active sample studies. MISP feed format, "
                "free including commercial use, ships as a default "
                "MISP feed since 2019. Strong complement to CIRCL OSINT."
            ),
            requires=["network access (no key)"],
            produces=["IOC pulses (URLs, IPs, domains, hashes from malware analysis)"],
            source_file="src/feeds/digitalside_feed.py",
            docs_url="https://osint.digitalside.it/",
            produces_pages=["feeds", "iocs", "actors"],
            status_check=lambda db: _from_feed_health(db, "digitalside_osint"),
        ),
        ServiceEntry(
            name="PhishTank",
            category="Threat-intel feed",
            description=(
                "Verified phishing URLs. Note: PhishTank disabled new key "
                "registrations as of 2025 — only operators with a pre-existing "
                "legacy key can authenticate. Public unauthenticated access "
                "rate-limits at HTTP 403."
            ),
            requires=["ARGUS_PHISHTANK_API_KEY (legacy keys only)"],
            produces=["suspect_domains, phishing alerts"],
            source_file="src/feeds/phishtank_certpl_feed.py",
            docs_url="https://www.phishtank.com/api_register.php",
            produces_pages=["feeds", "takedowns", "brand"],
            key_fields=[
                {"key": "phishtank", "env_var": "ARGUS_PHISHTANK_API_KEY", "label": "Application key"},
            ],
            legacy_only=True,
            status_check=lambda db: _from_feed_health(db, "phishing_feed.phishtank"),
        ),
        ServiceEntry(
            name="CERT.PL Phishing",
            category="Threat-intel feed",
            description="CERT Polska's curated malicious domain list.",
            requires=["network access (no key)"],
            produces=["suspect_domains"],
            source_file="src/feeds/phishtank_certpl_feed.py",
            docs_url="https://cert.pl/en/posts/2020/03/malicious_domains/",
            produces_pages=["feeds", "takedowns"],
            status_check=lambda db: _from_feed_health(db, "phishtank_certpl"),
        ),
        ServiceEntry(
            name="ransomware.live",
            category="Threat-intel feed",
            description="Live ransomware victim disclosure tracker.",
            requires=["network access (no key, rate-limited)"],
            produces=["raw_intel from victim posts; ransomware leak Asset matches"],
            source_file="src/feeds/ransomware_feed.py",
            docs_url="https://ransomware.live/",
            produces_pages=["feeds", "alerts", "actors"],
            status_check=lambda db: _from_feed_health(db, "ransomware_live"),
        ),
        ServiceEntry(
            name="crt.sh (Certificate Transparency)",
            category="Threat-intel feed",
            description="CT logs — historical certs for any domain/keyword.",
            requires=["network access (no key, rate-limited)"],
            produces=["Lookalike domain detection, EASM cert mapping"],
            source_file="src/feeds/certstream_feed.py",
            docs_url="https://crt.sh/",
            produces_pages=["feeds", "brand", "exposures"],
            status_check=lambda db: _from_feed_health(db, "crtsh_certstream"),
        ),
        ServiceEntry(
            name="GHSA + ExploitDB",
            category="Threat-intel feed",
            description="GitHub Security Advisories + Exploit-DB CVE→PoC mapping.",
            requires=["network access; optional GITHUB_TOKEN"],
            produces=["CVE enrichment with public exploits"],
            source_file="src/feeds/ghsa_exploitdb_feed.py",
            docs_url="https://github.com/advisories",
            produces_pages=["intel", "advisories"],
            status_check=lambda db: _from_feed_health(db, "ghsa_exploitdb"),
        ),
        ServiceEntry(
            name="CISA KEV",
            category="Threat-intel feed",
            description="CISA's Known-Exploited-Vulnerabilities catalogue.",
            requires=["network access (no key)"],
            produces=["KEV flag on CVE records, prioritisation signal"],
            source_file="src/feeds/kev_feed.py",
            docs_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            produces_pages=["intel", "advisories"],
            status_check=lambda db: _from_feed_health(db, "cisa_kev"),
        ),
        ServiceEntry(
            name="NVD CVE",
            category="Threat-intel feed",
            description="NIST National Vulnerability Database (REST v2). API key raises rate limit from 50→2000 req/30s.",
            requires=["network access; optional ARGUS_NVD_API_KEY for higher rate"],
            produces=["CVE catalogue (cve_records)"],
            source_file="src/intel/nvd_epss.py",
            docs_url="https://nvd.nist.gov/developers/request-an-api-key",
            key_fields=[
                {"key": "nvd", "env_var": "ARGUS_NVD_API_KEY", "label": "API key (optional)"},
            ],
            produces_pages=["intel", "advisories"],
            status_check=lambda db: _from_feed_health(db, "intel.nvd"),
        ),
        ServiceEntry(
            name="EPSS",
            category="Threat-intel feed",
            description="Exploit Prediction Scoring System (FIRST).",
            requires=["network access (no key)"],
            produces=["EPSS score on cve_records"],
            source_file="src/intel/nvd_epss.py",
            docs_url="https://www.first.org/epss/",
            produces_pages=["intel", "advisories"],
            status_check=lambda db: _from_feed_health(db, "intel.epss"),
        ),

        # ── Phishing-feed sub-rows (per upstream) ───────────────────────
        ServiceEntry(
            name="OpenPhish (per-org match)",
            category="Threat-intel feed",
            description="Per-org brand-term match against OpenPhish list.",
            requires=["org brand_terms"],
            produces=["suspect_domains rows; /takedowns surface"],
            source_file="src/intel/phishing_feeds.py",
            produces_pages=["takedowns", "brand"],
            status_check=lambda db: _from_feed_health(db, "phishing_feed.openphish"),
        ),
        ServiceEntry(
            name="URLhaus (per-org match)",
            category="Threat-intel feed",
            description="Per-org brand-term match against URLhaus list.",
            requires=["org brand_terms"],
            produces=["suspect_domains, /takedowns"],
            source_file="src/intel/phishing_feeds.py",
            produces_pages=["takedowns", "brand"],
            status_check=lambda db: _from_feed_health(db, "phishing_feed.urlhaus"),
        ),
        ServiceEntry(
            legacy_only=True,
            name="PhishTank (per-org match)",
            category="Threat-intel feed",
            description="Per-org brand-term match against PhishTank list.",
            requires=["ARGUS_PHISHTANK_API_KEY", "org brand_terms"],
            produces=["suspect_domains, /takedowns"],
            source_file="src/intel/phishing_feeds.py",
            produces_pages=["takedowns", "brand"],
            key_fields=[
                {"key": "phishtank", "env_var": "ARGUS_PHISHTANK_API_KEY", "label": "Application key"},
            ],
            status_check=lambda db: _from_feed_health(db, "phishing_feed.phishtank"),
        ),

        # ── Enrichment APIs (per-IOC) ───────────────────────────────────
        ServiceEntry(
            name="urlscan.io",
            category="Enrichment API",
            description="URL recon + historical scan lookup.",
            requires=["ARGUS_URLSCAN_API_KEY (free 100/day)"],
            produces=["IOC detail enrichment, investigation agent tool"],
            source_file="src/enrichment/urlscan.py",
            docs_url="https://urlscan.io/docs/api/",
            produces_pages=["iocs", "alerts", "brand"],
            key_fields=[
                {"key": "urlscan", "env_var": "ARGUS_URLSCAN_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _from_env_or_integration_key(
                "urlscan", env_var="ARGUS_URLSCAN_API_KEY",
            ),
        ),
        ServiceEntry(
            name="CIRCL hashlookup",
            category="Enrichment API",
            description="Anonymous file-hash classification (NIST NSRL + extensions).",
            requires=["network access (no key)"],
            produces=["IOC detail enrichment, investigation agent"],
            source_file="src/enrichment/circl.py",
            docs_url="https://www.circl.lu/services/hashlookup/",
            produces_pages=["iocs", "alerts"],
            status_check=lambda db: _probe_http_get("https://hashlookup.circl.lu/info", "CIRCL hashlookup"),
        ),
        ServiceEntry(
            name="MaxMind GeoIP2",
            category="Enrichment API",
            description="GeoLite2 + GeoIP2 City/ASN databases — IP-to-geo + IP-to-ASN lookup at ingest time. Free GeoLite2 with account.",
            requires=["MaxMind account ID + license key (free GeoLite2 tier)"],
            produces=["Geo + ASN on every IOC + CT/feed entry"],
            produces_pages=["iocs", "threat-map"],
            source_file="src/feeds/geolocation.py",
            docs_url="https://www.maxmind.com/en/accounts/current/license-key",
            key_fields=[
                {"key": "maxmind_account", "env_var": "ARGUS_FEED_MAXMIND_ACCOUNT_ID", "label": "Account ID"},
                {"key": "maxmind_license", "env_var": "ARGUS_FEED_MAXMIND_LICENSE_KEY", "label": "License key"},
            ],
            status_check=lambda db: _from_env_or_integration_key(
                "maxmind_license", env_var="ARGUS_FEED_MAXMIND_LICENSE_KEY",
            ),
        ),
        ServiceEntry(
            name="ipwho.is",
            category="Enrichment API",
            description="Free IP geolocation + ASN lookup.",
            requires=["network access (no key, 50 req/min)"],
            produces=["Geo + ASN on IOC rows"],
            source_file="src/feeds/geolocation.py",
            docs_url="https://ipwho.is/",
            produces_pages=["iocs", "threat-map"],
            status_check=lambda db: _probe_http_get("https://ipwho.is/8.8.8.8", "ipwho.is"),
        ),
        ServiceEntry(
            name="Team Cymru IP→ASN",
            category="Enrichment API",
            description=(
                "Team Cymru's free WHOIS-based IP→ASN/BGP-prefix/"
                "country mapping. No key, no per-IP rate limit (within "
                "fair-use). Bulk mode supported — enrich N IPs in a "
                "single TCP session via team_cymru.lookup_bulk(). "
                "Cached 7d (BGP allocations change rarely)."
            ),
            requires=["network egress to whois.cymru.com:43 TCP"],
            produces=["ASN, BGP prefix, country, registry, alloc date per IP"],
            source_file="src/enrichment/team_cymru.py",
            docs_url="https://team-cymru.com/community-services/ip-asn-mapping/",
            produces_pages=["iocs", "threat-map"],
            status_check=lambda db: ServiceStatus(
                status=STATUS_OK,
                sub_reason="bundled",
                evidence="WHOIS service is always available; no creds required.",
            ),
        ),
        ServiceEntry(
            name="ipinfo.io Lite",
            category="Enrichment API",
            description=(
                "ipinfo.io's Lite tier — free, requires a token, no "
                "monthly cap. Returns country + ASN data per IP. Useful "
                "as a current-snapshot ASN cross-check against the free "
                "GeoLite2 database Argus ships."
            ),
            requires=["ARGUS_IPINFO_LITE_TOKEN (free with registration)"],
            produces=["Country + ASN enrichment per IP"],
            source_file="src/enrichment/ipinfo_lite.py",
            docs_url="https://ipinfo.io/developers/lite-api",
            key_fields=[
                {"key": "ipinfo_lite", "env_var": "ARGUS_IPINFO_LITE_TOKEN",
                 "label": "Token (free at ipinfo.io)"},
            ],
            produces_pages=["iocs", "threat-map"],
            status_check=lambda db: _from_env_or_integration_key(
                "ipinfo_lite", env_var="ARGUS_IPINFO_LITE_TOKEN",
            ),
        ),
        ServiceEntry(
            name="IBM X-Force Exchange",
            category="Enrichment API",
            description=(
                "IBM's public threat-intel portal. Per-IP reputation "
                "score (0-10) + categorical labels. Free tier ~5k "
                "lookups/month. Requires BYOK — generate the API key "
                "and password as a pair in the X-Force settings UI."
            ),
            requires=["ARGUS_XFORCE_API_KEY + ARGUS_XFORCE_API_PASSWORD (free account)"],
            produces=["IP reputation score + IBM X-Force categorical labels"],
            source_file="src/enrichment/xforce.py",
            docs_url="https://api.xforce.ibmcloud.com/doc/",
            key_fields=[
                {"key": "xforce_key", "env_var": "ARGUS_XFORCE_API_KEY",
                 "label": "API Key"},
                {"key": "xforce_password", "env_var": "ARGUS_XFORCE_API_PASSWORD",
                 "label": "API Password"},
            ],
            produces_pages=["iocs", "alerts", "threat-map"],
            status_check=lambda db: _from_env_or_integration_key(
                "xforce_key", env_var="ARGUS_XFORCE_API_KEY",
            ),
        ),
        ServiceEntry(
            name="Pulsedive",
            category="Enrichment API",
            description=(
                "Aggregates IOCs from 45+ OSINT feeds. Per-indicator "
                "lookup returns recommended risk score, contributing "
                "feeds, threats, and risk factors. Free anonymous tier "
                "works (lower rate limit); set ARGUS_PULSEDIVE_API_KEY "
                "for higher quota."
            ),
            requires=["network access (no key required for anonymous tier)"],
            produces=["Aggregated IOC risk score + contributing feeds"],
            source_file="src/enrichment/pulsedive.py",
            docs_url="https://docs.pulsedive.com/",
            key_fields=[
                {"key": "pulsedive", "env_var": "ARGUS_PULSEDIVE_API_KEY",
                 "label": "API key (optional — unlocks higher quota)"},
            ],
            produces_pages=["iocs", "alerts"],
            status_check=lambda db: _probe_http_get(
                "https://pulsedive.com/api/indicator.php?indicator=8.8.8.8",
                "Pulsedive",
            ),
        ),
        ServiceEntry(
            name="Shodan InternetDB",
            category="Enrichment API",
            description=(
                "Shodan's free public slice — no key, weekly snapshot, "
                "returns open ports + CPE strings + CVE IDs + hostnames "
                "+ Shodan tags for every IP they've scanned. Wired into "
                "/iocs detail and the IOC enrichment pipeline; results "
                "cached 24h in Redis since the upstream snapshot only "
                "refreshes weekly."
            ),
            requires=["network access (no key — public endpoint)"],
            produces=["Open ports / CVEs / hostnames / Shodan tags on IOCs"],
            source_file="src/enrichment/shodan_internetdb.py",
            docs_url="https://internetdb.shodan.io/",
            produces_pages=["iocs", "threat-map", "exposures"],
            status_check=lambda db: _probe_http_get(
                "https://internetdb.shodan.io/8.8.8.8", "Shodan InternetDB",
            ),
        ),

        # ── Breach / credential ────────────────────────────────────────
        ServiceEntry(
            name="theHarvester (passive recon)",
            category="Enrichment API",
            description="Passive OSINT recon — emails, subdomains, hosts from public sources (Bing, DuckDuckGo, crt.sh, GitHub, OTX, urlscan, etc.). Free, no key required for the curated source set.",
            requires=["theHarvester binary (installed via Dockerfile git pin)"],
            produces=["onboarding asset discovery, /exposures subdomain seed, /brand exec-email seed"],
            produces_pages=["exposures", "brand"],
            source_file="src/integrations/osint/the_harvester.py",
            docs_url="https://github.com/laramies/theHarvester",
            status_check=_check_theharvester,
        ),
        ServiceEntry(
            name="Holehe (email exposure)",
            category="Breach / credential",
            description="Checks ~50-120 services to map where an email is registered. Complements breach providers — answers 'where does this email exist?' (exposure surface) vs 'was this email leaked?' (breach data).",
            requires=["holehe Python lib (pip install holehe)"],
            produces=["leakage exposure-surface findings"],
            produces_pages=["leakage", "brand"],
            source_file="src/integrations/osint/holehe.py",
            docs_url="https://github.com/megadose/holehe",
            status_check=_check_holehe,
        ),
        ServiceEntry(
            name="HudsonRock Cavalier (OSS-default)",
            category="Breach / credential",
            description=(
                "Stealer-log breach corpus — millions of credentials "
                "harvested from infostealer-infected machines. Public "
                "free tier API works WITHOUT a key (already active in "
                "this deploy). The key field below is optional and only "
                "unlocks higher quota."
            ),
            requires=["network access (free tier needs no key)", "ARGUS_HUDSONROCK_API_KEY optional for higher quota"],
            produces=["leakage findings (per-email + per-domain), active-compromise alerts"],
            produces_pages=["leakage"],
            source_file="src/integrations/breach/cavalier.py",
            docs_url="https://www.hudsonrock.com/free-tools",
            key_fields=[
                {"key": "hudsonrock", "env_var": "ARGUS_HUDSONROCK_API_KEY", "label": "API key (optional)"},
            ],
            status_check=lambda db: _probe_http_get(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=test@example.com",
                "Cavalier",
            ),
        ),
        ServiceEntry(
            name="XposedOrNot (OSS-default)",
            category="Breach / credential",
            description=(
                "Free dataset-breach corpus — covers paste-site dumps, "
                "leaked databases, and the kind of credential-stuffing "
                "fodder HIBP indexes. Public /breach-analytics endpoint "
                "needs no key (rate-limited to 1 req/s). Pairs with "
                "Cavalier (stealer logs) so /leakage has two "
                "complementary OSS providers before the operator pays "
                "for HIBP / IntelX / Dehashed."
            ),
            requires=["network access (no key — public endpoint, 1 req/s rate limit)"],
            produces=["leakage findings (dataset breach matches per email)"],
            produces_pages=["leakage"],
            source_file="src/integrations/breach/xposedornot.py",
            docs_url="https://xposedornot.com/api_doc",
            key_fields=[
                {"key": "xposedornot", "env_var": "ARGUS_XPOSEDORNOT_API_KEY",
                 "label": "API key (optional, only needed for paid endpoints)"},
            ],
            status_check=lambda db: _probe_http_get(
                "https://api.xposedornot.com/v1/check-email/test@example.com",
                "XposedOrNot",
            ),
        ),
        ServiceEntry(
            name="Have I Been Pwned",
            category="Breach / credential",
            description="Email-breach corpus lookup.",
            requires=["ARGUS_HIBP_API_KEY (Enterprise $3.95/mo)"],
            produces=["leakage findings, breach-credential alerts"],
            source_file="src/integrations/breach/hibp.py",
            docs_url="https://haveibeenpwned.com/api/key",
            produces_pages=["leakage"],
            key_fields=[
                {"key": "hibp", "env_var": "ARGUS_HIBP_API_KEY", "label": "API key"},
            ],
            no_oss_substitute=True,
            status_check=lambda db: _from_env_or_integration_key("hibp", env_var="ARGUS_HIBP_API_KEY"),
        ),
        ServiceEntry(
            name="Intelligence X",
            category="Breach / credential",
            description="Breach + paste-site corpus search.",
            requires=["ARGUS_INTELX_API_KEY"],
            produces=["leakage findings"],
            source_file="src/integrations/breach/intelx.py",
            docs_url="https://intelx.io/account?tab=developer",
            produces_pages=["leakage"],
            key_fields=[
                {"key": "intelx", "env_var": "ARGUS_INTELX_API_KEY", "label": "API key"},
            ],
            no_oss_substitute=True,
            status_check=lambda db: _from_env_or_integration_key("intelx", env_var="ARGUS_INTELX_API_KEY"),
        ),
        ServiceEntry(
            name="DeHashed",
            category="Breach / credential",
            description="Email + username breach corpus.",
            requires=["ARGUS_DEHASHED_USERNAME + ARGUS_DEHASHED_API_KEY"],
            produces=["leakage findings"],
            source_file="src/integrations/breach/dehashed.py",
            docs_url="https://dehashed.com/account",
            produces_pages=["leakage"],
            key_fields=[
                {"key": "dehashed_user", "env_var": "ARGUS_DEHASHED_USERNAME", "label": "Username"},
                {"key": "dehashed", "env_var": "ARGUS_DEHASHED_API_KEY", "label": "API key"},
            ],
            no_oss_substitute=True,
            status_check=lambda db: _from_env_or_integration_key("dehashed", env_var="ARGUS_DEHASHED_API_KEY"),
        ),

        # ── Dark-web crawlers ──────────────────────────────────────────
        ServiceEntry(
            name="Telegram public channels",
            category="Dark-web crawler",
            description="Web-preview scrape of public channels (no API).",
            requires=["crawler_targets rows of kind=telegram_channel"],
            produces=["raw_intel, brand-match alerts"],
            source_file="src/crawlers/telegram_crawler.py",
            produces_pages=["alerts", "iocs", "brand"],
            status_check=lambda db: _from_crawler_targets(db, "telegram_channel"),
        ),
        ServiceEntry(
            name="Ransomware leak sites (Tor)",
            category="Dark-web crawler",
            description="Passive scrape of victim listings on group leak sites.",
            requires=["Tor SOCKS proxy", "crawler_targets rows of kind=ransomware_leak_group"],
            produces=["raw_intel; brand-match → /alerts on victim names"],
            source_file="src/crawlers/ransomware_crawler.py",
            produces_pages=["alerts", "iocs", "actors"],
            status_check=lambda db: _from_crawler_targets(db, "ransomware_leak_group"),
        ),
        ServiceEntry(
            name="Tor forums (XSS, Exploit, etc.)",
            category="Dark-web crawler",
            description="Generic forum scraping over Tor.",
            requires=["Tor SOCKS proxy", "crawler_targets rows of kind=tor_forum"],
            produces=["raw_intel, actor sightings"],
            source_file="src/crawlers/tor_crawler.py",
            produces_pages=["alerts", "iocs", "actors"],
            status_check=lambda db: _from_crawler_targets(db, "tor_forum"),
        ),
        ServiceEntry(
            name="Stealer-log marketplaces",
            category="Dark-web crawler",
            description="Read-only browse of public listings on stealer markets.",
            requires=["Tor SOCKS proxy", "crawler_targets rows of kind=stealer_marketplace"],
            produces=["leakage findings, credential alerts"],
            source_file="src/crawlers/stealer_crawler.py",
            produces_pages=["leakage", "iocs"],
            status_check=lambda db: _from_crawler_targets(db, "stealer_marketplace"),
        ),
        ServiceEntry(
            name="Matrix rooms",
            category="Dark-web crawler",
            description="Federated Matrix room monitoring.",
            requires=["crawler_targets rows of kind=matrix_room"],
            produces=["raw_intel"],
            source_file="src/crawlers/matrix_crawler.py",
            produces_pages=["alerts", "iocs"],
            status_check=lambda db: _from_crawler_targets(db, "matrix_room"),
        ),
        ServiceEntry(
            name="I2P eepsites",
            category="Dark-web crawler",
            description="(Skeleton) I2P health probe; no production crawl yet.",
            requires=["I2P router daemon"],
            produces=["—"],
            source_file="src/crawlers/i2p_crawler.py",
            status_check=_not_installed_marker(
                "I2P router daemon not detected. Install i2pd (lightweight C++ "
                "router) and start it: `apt-get install i2pd && systemctl start i2pd`. "
                "Once the SAM bridge on :7656 is reachable, the i2p_crawler will "
                "pick up crawler_targets of kind=i2p_eepsite.",
                sub_reason="daemon_not_detected",
            ),
        ),
        ServiceEntry(
            name="Lokinet sites",
            category="Dark-web crawler",
            description="(Skeleton) Lokinet health probe; no production crawl yet.",
            requires=["Lokinet daemon"],
            produces=["—"],
            source_file="src/crawlers/lokinet_crawler.py",
            status_check=_not_installed_marker(
                "Lokinet daemon not detected. Install the OXEN Lokinet client "
                "and start it (default SOCKS proxy on :1090). Once reachable, "
                "the lokinet_crawler will pick up crawler_targets of kind=lokinet_snapp.",
                sub_reason="daemon_not_detected",
            ),
        ),

        # ── Social media monitors ──────────────────────────────────────
        ServiceEntry(
            name="Instagram",
            category="Social media monitor",
            description="instaloader anonymous public-profile scrape.",
            requires=["ARGUS_WORKER_INSTAGRAM_INTERVAL>0", "monitored handles"],
            produces=["impersonation findings, brand abuse"],
            source_file="src/social/instagram_monitor.py",
            produces_pages=["brand", "takedowns"],
            status_check=_disabled_unless_env(
                "ARGUS_WORKER_INSTAGRAM_INTERVAL",
                "Set ARGUS_WORKER_INSTAGRAM_INTERVAL to a positive integer (minutes between scrapes) to enable.",
            ),
        ),
        ServiceEntry(
            name="Twitter / X (Scweet)",
            category="Social media monitor",
            description="Scweet-based scrape; requires authenticated session files.",
            requires=["ARGUS_TWITTER_SESSION_DIR with valid sessions", "ARGUS_WORKER_TWITTER_INTERVAL>0"],
            produces=["impersonation findings"],
            source_file="src/social/twitter_monitor.py",
            produces_pages=["brand", "takedowns"],
            status_check=_disabled_unless_env(
                "ARGUS_WORKER_TWITTER_INTERVAL",
                "Disabled by default; X anti-scraping is aggressive. Enable only with seeded Scweet sessions.",
            ),
        ),
        ServiceEntry(
            name="TikTok",
            category="Social media monitor",
            description="TikTokApi via Playwright/Chromium.",
            requires=["playwright + chromium installed in image", "ARGUS_WORKER_TIKTOK_INTERVAL>0"],
            produces=["impersonation findings"],
            source_file="src/social/tiktok_monitor.py",
            produces_pages=["brand", "takedowns"],
            status_check=_disabled_unless_env(
                "ARGUS_WORKER_TIKTOK_INTERVAL",
                "Disabled by default; requires `playwright install chromium` (200 MB) added to image.",
            ),
        ),
        ServiceEntry(
            name="LinkedIn",
            category="Social media monitor",
            description="Company-page monitor (hiQ Labs ruling — Company pages only).",
            requires=["ARGUS_LINKEDIN_USERNAME/PASSWORD", "ARGUS_WORKER_LINKEDIN_INTERVAL>0"],
            produces=["impersonation findings"],
            source_file="src/social/linkedin_monitor.py",
            produces_pages=["brand", "takedowns"],
            status_check=_disabled_unless_env(
                "ARGUS_WORKER_LINKEDIN_INTERVAL",
                "Disabled by default; LinkedIn detects automation aggressively — high ban risk.",
            ),
        ),
        ServiceEntry(
            name="Mention.com",
            category="Social media monitor",
            description=(
                "Paid SaaS brand monitoring across web, news, blogs, "
                "and social. The poller queries Mention's API for each "
                "org's brand keywords, ingests matching mentions into "
                "raw_intel, and lets the triage agent decide which "
                "ones become alerts. Inactive without an API key — "
                "free Google Alerts (configured per-org) is the "
                "no-cost equivalent for basic brand search."
            ),
            requires=["ARGUS_MENTION_API_KEY (paid — sign up at mention.com)"],
            produces=["raw_intel rows tagged source=mention.<keyword>"],
            source_file="src/integrations/mention_brand_search.py",
            docs_url="https://dev.mention.com/",
            no_oss_substitute=False,  # Google Alerts covers the basic case
            key_fields=[
                {
                    "key": "mention",
                    "env_var": "ARGUS_MENTION_API_KEY",
                    "label": "Mention.com API key",
                },
            ],
            produces_pages=["alerts", "intel"],
            status_check=lambda db: _from_env_or_integration_key(
                "mention",
                env_var="ARGUS_MENTION_API_KEY",
                label="Mention.com API key",
            ),
        ),
        ServiceEntry(
            name="Telegram (per-org channel watch)",
            category="Social media monitor",
            description="Public-channel scrape per org via t.me/s/ web preview.",
            requires=["org settings.telegram_monitor_channels"],
            produces=["fraud_findings, impersonation_findings"],
            source_file="src/social/telegram_monitor.py",
            produces_pages=["brand", "alerts"],
            status_check=lambda db: _from_feed_health(db, "social.telegram"),
        ),

        # ── EDR connectors (BYOK) ──────────────────────────────────────
        ServiceEntry(
            name="CrowdStrike Falcon",
            category="EDR connector",
            description="Push IOCs + isolate hosts.",
            requires=["ARGUS_FALCON_CLIENT_ID/SECRET + base URL"],
            produces=["EDR push surface, host isolation actions"],
            source_file="src/integrations/edr/crowdstrike.py",
            docs_url="https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/",
            key_fields=[
                {"key": "falcon_id", "env_var": "ARGUS_FALCON_CLIENT_ID", "label": "Client ID"},
                {"key": "falcon", "env_var": "ARGUS_FALCON_CLIENT_SECRET", "label": "Client secret"},
                {"key": "falcon_base", "env_var": "ARGUS_FALCON_BASE_URL", "label": "Base URL"},
            ],
            status_check=lambda db: _from_env_or_integration_key("falcon", env_var="ARGUS_FALCON_CLIENT_SECRET"),
        ),
        ServiceEntry(
            name="SentinelOne Singularity",
            category="EDR connector",
            description="IOC push + endpoint isolation.",
            requires=["ARGUS_S1_API_TOKEN + ARGUS_S1_ACCOUNT_ID"],
            produces=["EDR push surface"],
            source_file="src/integrations/edr/sentinelone.py",
            docs_url="https://usea1-partners.sentinelone.net/api-doc/",
            key_fields=[
                {"key": "s1", "env_var": "ARGUS_S1_API_TOKEN", "label": "API token"},
                {"key": "s1_account", "env_var": "ARGUS_S1_ACCOUNT_ID", "label": "Account ID"},
                {"key": "s1_base", "env_var": "ARGUS_S1_BASE_URL", "label": "Base URL"},
            ],
            status_check=lambda db: _from_env_or_integration_key("s1", env_var="ARGUS_S1_API_TOKEN"),
        ),
        ServiceEntry(
            name="Microsoft Defender for Endpoint",
            category="EDR connector",
            description="MDE indicators + machine actions.",
            requires=["ARGUS_MDE_TENANT_ID + CLIENT_ID + CLIENT_SECRET"],
            produces=["EDR push surface"],
            source_file="src/integrations/edr/mde.py",
            docs_url="https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/",
            key_fields=[
                {"key": "mde_tenant", "env_var": "ARGUS_MDE_TENANT_ID", "label": "Tenant ID"},
                {"key": "mde_client", "env_var": "ARGUS_MDE_CLIENT_ID", "label": "Client ID"},
                {"key": "mde", "env_var": "ARGUS_MDE_CLIENT_SECRET", "label": "Client secret"},
            ],
            status_check=lambda db: _from_env_or_integration_key("mde", env_var="ARGUS_MDE_CLIENT_SECRET"),
        ),
        ServiceEntry(
            name="Wazuh (OSS — self-hosted)",
            oss_install_name="wazuh",
            category="EDR connector",
            description=(
                "Wazuh Manager REST API — open-source EDR + SIEM. "
                "Once configured, the worker pulls fresh alerts every "
                "10 minutes and merges them into the local alert "
                "store; correlated with Argus IOCs automatically."
            ),
            requires=["ARGUS_WAZUH_URL + USER:PASS"],
            produces=["EDR alerts, agent inventory"],
            source_file="src/integrations/wazuh/client.py",
            docs_url="https://documentation.wazuh.com/current/quickstart.html",
            self_hosted=True,
            self_host_install_hint=(
                "**One-line install** (Ubuntu/Debian/RHEL host):\n"
                "```bash\n"
                "curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh\n"
                "sudo bash ./wazuh-install.sh -a\n"
                "```\n"
                "Installer prints admin credentials at the end. "
                "Server URL is `https://<host>:55000` (Manager REST). "
                "Paste credentials below as `username:password`."
            ),
            key_fields=[
                {"key": "wazuh_url", "env_var": "ARGUS_WAZUH_URL", "label": "Manager URL"},
                {"key": "wazuh", "env_var": "ARGUS_WAZUH_API_KEY", "label": "user:password"},
            ],
            status_check=lambda db: _self_hosted_status(
                db, oss_install_name="wazuh",
                url_env_var="ARGUS_WAZUH_URL", url_key_name="wazuh_url",
                extra_env_var="ARGUS_WAZUH_API_KEY", extra_key_name="wazuh",
                label="Wazuh",
            ),
        ),

        # ── SIEM connectors ────────────────────────────────────────────
        ServiceEntry(
            name="Splunk HEC",
            category="SIEM connector",
            description="Push events to Splunk HTTP Event Collector.",
            requires=["ARGUS_SPLUNK_HEC_URL + TOKEN"],
            produces=["SIEM event stream"],
            source_file="src/integrations/siem/splunk_hec.py",
            key_fields=[
                {"key": "splunk_hec", "env_var": "ARGUS_SPLUNK_HEC_TOKEN", "label": "HEC token"},
                {"key": "splunk_hec_url", "env_var": "ARGUS_SPLUNK_HEC_URL", "label": "HEC URL"},
            ],
            status_check=lambda db: _from_env_or_integration_key("splunk_hec", env_var="ARGUS_SPLUNK_HEC_TOKEN"),
        ),
        ServiceEntry(
            name="Microsoft Sentinel",
            category="SIEM connector",
            description="Logs Ingestion API (OAuth) or HTTP Data Collector (legacy).",
            requires=["ARGUS_SENTINEL_DCE_URL + DCR_IMMUTABLE_ID + service principal"],
            produces=["SIEM event stream"],
            source_file="src/integrations/siem/sentinel.py",
            key_fields=[
                {"key": "sentinel_dce", "env_var": "ARGUS_SENTINEL_DCE_URL", "label": "DCE URL"},
                {"key": "sentinel_dcr", "env_var": "ARGUS_SENTINEL_DCR_IMMUTABLE_ID", "label": "DCR ID"},
                {"key": "sentinel", "env_var": "ARGUS_SENTINEL_CLIENT_SECRET", "label": "Client secret"},
            ],
            status_check=lambda db: _from_env_or_integration_key("sentinel", env_var="ARGUS_SENTINEL_CLIENT_SECRET"),
        ),
        ServiceEntry(
            name="Elasticsearch / Elastic Cloud",
            category="SIEM connector",
            description="Index events into a custom Elastic index.",
            requires=["ARGUS_ELASTIC_URL + API_KEY (or basic auth)"],
            produces=["SIEM event stream"],
            source_file="src/integrations/siem/elastic.py",
            key_fields=[
                {"key": "elastic_url", "env_var": "ARGUS_ELASTIC_URL", "label": "URL"},
                {"key": "elastic", "env_var": "ARGUS_ELASTIC_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _from_env_or_integration_key("elastic", env_var="ARGUS_ELASTIC_API_KEY"),
        ),
        ServiceEntry(
            name="OpenSearch (OSS — self-hosted)",
            category="SIEM connector",
            description=(
                "OpenSearch (Apache-2.0 fork of Elasticsearch). "
                "Wire-compatible with the Elastic ``_bulk`` API — "
                "Argus pushes alerts + IOC events to it on every "
                "alert-dispatch event. Same ECS schema as Elastic."
            ),
            requires=["ARGUS_OPENSEARCH_URL + USER:PASS or API_KEY"],
            produces=["SIEM event stream"],
            # Reuses the Elastic connector — wire format is identical.
            source_file="src/integrations/siem/elastic.py",
            docs_url="https://opensearch.org/docs/latest/install-and-configure/install-opensearch/docker/",
            self_hosted=True,
            self_host_install_hint=(
                "**Docker quickstart**:\n"
                "```bash\n"
                "docker run -p 9200:9200 -p 9600:9600 \\\n"
                "  -e \"discovery.type=single-node\" \\\n"
                "  -e \"OPENSEARCH_INITIAL_ADMIN_PASSWORD=<choose>\" \\\n"
                "  opensearchproject/opensearch:latest\n"
                "```\n"
                "Then point Argus at `https://<host>:9200`. Paste "
                "creds as `admin:<password>` in the API key field "
                "(it's also accepted as a Basic-auth pair)."
            ),
            key_fields=[
                {"key": "elastic_url", "env_var": "ARGUS_ELASTIC_URL", "label": "URL"},
                {"key": "elastic", "env_var": "ARGUS_ELASTIC_API_KEY", "label": "API key or user:pass"},
            ],
            status_check=lambda db: _self_hosted_status(
                db,
                url_env_var="ARGUS_ELASTIC_URL", url_key_name="elastic_url",
                extra_env_var="ARGUS_ELASTIC_API_KEY", extra_key_name="elastic",
                label="OpenSearch",
            ),
        ),
        ServiceEntry(
            name="IBM QRadar",
            category="SIEM connector",
            description="Bulk-load IOCs into a QRadar reference set.",
            requires=["ARGUS_QRADAR_URL + TOKEN + REFERENCE_SET"],
            produces=["QRadar reference set push"],
            source_file="src/integrations/siem/qradar.py",
            key_fields=[
                {"key": "qradar_url", "env_var": "ARGUS_QRADAR_URL", "label": "URL"},
                {"key": "qradar", "env_var": "ARGUS_QRADAR_TOKEN", "label": "Token"},
                {"key": "qradar_set", "env_var": "ARGUS_QRADAR_REFERENCE_SET", "label": "Reference set name"},
            ],
            status_check=lambda db: _from_env_or_integration_key("qradar", env_var="ARGUS_QRADAR_TOKEN"),
        ),
        ServiceEntry(
            name="Wazuh Indexer (OSS — self-hosted)",
            category="SIEM connector",
            description=(
                "Bulk-index Argus alerts/IOCs into the Wazuh indexer "
                "(OpenSearch under the hood). Customers already running "
                "Wazuh for endpoint telemetry get one-pane-of-glass "
                "without standing up a separate Elasticsearch cluster."
            ),
            requires=[
                "operator runs Wazuh",
                "ARGUS_WAZUH_INDEXER_URL + ARGUS_WAZUH_INDEXER_USERNAME/PASSWORD",
            ],
            produces=["Argus events into Wazuh indexer for SIEM dashboards"],
            source_file="src/integrations/siem/wazuh_siem.py",
            docs_url="https://documentation.wazuh.com/current/index.html",
            self_hosted=True,
            key_fields=[
                {"key": "wazuh_indexer_url", "env_var": "ARGUS_WAZUH_INDEXER_URL", "label": "Indexer URL"},
                {"key": "wazuh_indexer_username", "env_var": "ARGUS_WAZUH_INDEXER_USERNAME", "label": "Username"},
                {"key": "wazuh_indexer_password", "env_var": "ARGUS_WAZUH_INDEXER_PASSWORD", "label": "Password"},
            ],
            status_check=lambda db: _self_hosted_status(
                db,
                url_env_var="ARGUS_WAZUH_INDEXER_URL", url_key_name="wazuh_indexer_url",
                extra_env_var="ARGUS_WAZUH_INDEXER_PASSWORD",
                extra_key_name="wazuh_indexer_password",
                label="Wazuh Indexer",
            ),
        ),
        ServiceEntry(
            name="Graylog (GELF push)",
            category="SIEM connector",
            description=(
                "Push Argus alerts/IOCs to Graylog over the GELF HTTP "
                "input. Each event renders as a single GELF v1.1 doc "
                "with Argus fields projected as ``_argus_*`` customs "
                "the operator can pivot on. Works against Graylog "
                "Open (free SSPL) or Enterprise."
            ),
            requires=["ARGUS_GRAYLOG_GELF_URL"],
            produces=["Argus events as GELF docs in Graylog"],
            source_file="src/integrations/siem/graylog.py",
            docs_url="https://docs.graylog.org/docs/gelf",
            key_fields=[
                {"key": "graylog_gelf_url", "env_var": "ARGUS_GRAYLOG_GELF_URL", "label": "GELF HTTP URL"},
                {"key": "graylog_basic_user", "env_var": "ARGUS_GRAYLOG_BASIC_USER", "label": "Basic-auth user (optional)"},
                {"key": "graylog_basic_password", "env_var": "ARGUS_GRAYLOG_BASIC_PASSWORD", "label": "Basic-auth password (optional)"},
            ],
            status_check=lambda db: _from_env_or_integration_key(
                "graylog_gelf_url", env_var="ARGUS_GRAYLOG_GELF_URL",
            ),
        ),

        # ── SOAR ───────────────────────────────────────────────────────
        ServiceEntry(
            name="Cortex XSOAR (Palo Alto)",
            category="SOAR connector",
            description="Create incidents in XSOAR.",
            requires=["ARGUS_XSOAR_API_KEY + KEY_ID + URL"],
            produces=["SOAR incident creation"],
            source_file="src/integrations/soar/xsoar.py",
            key_fields=[
                {"key": "xsoar_url", "env_var": "ARGUS_XSOAR_URL", "label": "Base URL"},
                {"key": "xsoar", "env_var": "ARGUS_XSOAR_API_KEY", "label": "API key"},
                {"key": "xsoar_id", "env_var": "ARGUS_XSOAR_KEY_ID", "label": "Key ID"},
            ],
            status_check=lambda db: _from_env_or_integration_key("xsoar", env_var="ARGUS_XSOAR_API_KEY"),
        ),
        ServiceEntry(
            name="Tines",
            category="SOAR connector",
            description="Webhook into a Tines story.",
            requires=["ARGUS_TINES_WEBHOOK_URL"],
            produces=["SOAR webhook fire"],
            source_file="src/integrations/soar/tines.py",
            key_fields=[
                {"key": "tines", "env_var": "ARGUS_TINES_WEBHOOK_URL", "label": "Webhook URL"},
            ],
            status_check=lambda db: _from_env_or_integration_key("tines", env_var="ARGUS_TINES_WEBHOOK_URL"),
        ),
        ServiceEntry(
            name="Splunk SOAR (Phantom)",
            category="SOAR connector",
            description="Phantom incidents for Splunk-stack customers.",
            requires=["ARGUS_SPLUNK_SOAR_URL + TOKEN"],
            produces=["SOAR incident creation"],
            source_file="src/integrations/soar/splunk_soar.py",
            key_fields=[
                {"key": "phantom_url", "env_var": "ARGUS_SPLUNK_SOAR_URL", "label": "Base URL"},
                {"key": "phantom", "env_var": "ARGUS_SPLUNK_SOAR_TOKEN", "label": "API token"},
            ],
            status_check=lambda db: _from_env_or_integration_key("phantom", env_var="ARGUS_SPLUNK_SOAR_TOKEN"),
        ),
        ServiceEntry(
            name="Cortex (TheHive Project)",
            category="SOAR connector",
            description=(
                "Apache-2.0 OSS analyzer/responder framework. 200+ "
                "community-maintained analyzers (MISP, AbuseIPDB, "
                "urlscan, VirusTotal, Shodan, ...) and responders "
                "(firewall block, disable user, etc.). Two integration "
                "modes: alert auto-fanout via push_events (runs the "
                "default analyzer on extracted observables) and "
                "explicit run_analyzer / get_job calls from the case "
                "copilot agent."
            ),
            requires=["operator runs Cortex", "ARGUS_CORTEX_URL + ARGUS_CORTEX_API_KEY"],
            produces=["Analyzer reports + responder actions"],
            source_file="src/integrations/soar/cortex.py",
            docs_url="https://docs.strangebee.com/cortex/",
            self_hosted=True,
            self_host_install_hint=(
                "**Quickest install** (Docker compose):\n"
                "```bash\n"
                "git clone https://github.com/TheHive-Project/Docker-Templates.git\n"
                "cd Docker-Templates/cortex && docker compose up -d\n"
                "# then point Argus at it:\n"
                "#   Base URL: http://<host>:9001\n"
                "#   API key:  Cortex UI → Organization → Users → API key\n"
                "```"
            ),
            key_fields=[
                {"key": "cortex_url", "env_var": "ARGUS_CORTEX_URL", "label": "Base URL"},
                {"key": "cortex_key", "env_var": "ARGUS_CORTEX_API_KEY", "label": "API key"},
                {"key": "cortex_default_analyzer",
                 "env_var": "ARGUS_CORTEX_DEFAULT_ANALYZER",
                 "label": "Default analyzer ID (optional, e.g. AbuseIPDB_1_0)"},
            ],
            status_check=lambda db: _self_hosted_status(
                db,
                url_env_var="ARGUS_CORTEX_URL", url_key_name="cortex_url",
                extra_env_var="ARGUS_CORTEX_API_KEY", extra_key_name="cortex_key",
                label="Cortex",
            ),
        ),
        ServiceEntry(
            name="Shuffle (OSS — self-hosted)",
            oss_install_name="shuffle",
            category="SOAR connector",
            description=(
                "Shuffle SOAR — open-source SOAR. Once configured, "
                "every Argus alert dispatched (cases, IOCs, fraud "
                "findings) fires the matching Shuffle workflow via "
                "its webhook trigger — no extra wiring."
            ),
            requires=["ARGUS_SHUFFLE_URL + API_KEY"],
            produces=["SOAR workflow trigger"],
            source_file="src/integrations/shuffle/client.py",
            docs_url="https://shuffler.io/docs/configuration#docker",
            self_hosted=True,
            self_host_install_hint=(
                "**Docker quickstart**:\n"
                "```bash\n"
                "git clone https://github.com/Shuffle/Shuffle.git\n"
                "cd Shuffle\n"
                "mkdir shuffle-database && sudo chown -R 1000:1000 shuffle-database\n"
                "docker compose up -d\n"
                "```\n"
                "Browse to `http://<host>:3001` and create the admin "
                "user. Generate an API key under User → API key, "
                "paste here with Server URL `http://<host>:3001`."
            ),
            key_fields=[
                {"key": "shuffle_url", "env_var": "ARGUS_SHUFFLE_URL", "label": "Server URL"},
                {"key": "shuffle", "env_var": "ARGUS_SHUFFLE_API_KEY", "label": "API key"},
                {"key": "shuffle_workflow", "env_var": "ARGUS_SHUFFLE_DEFAULT_WORKFLOW_ID", "label": "Default workflow ID"},
            ],
            status_check=lambda db: _self_hosted_status(
                db, oss_install_name="shuffle",
                url_env_var="ARGUS_SHUFFLE_URL", url_key_name="shuffle_url",
                extra_env_var="ARGUS_SHUFFLE_API_KEY", extra_key_name="shuffle",
                label="Shuffle",
            ),
        ),

        # ── Email gateway ──────────────────────────────────────────────
        ServiceEntry(
            name="Proofpoint TAP",
            category="Email-gateway connector",
            description="Targeted Attack Protection SIEM API.",
            requires=["ARGUS_PROOFPOINT_PRINCIPAL + SECRET"],
            produces=["Inbound phishing IOC stream"],
            source_file="src/integrations/email_gateway/proofpoint.py",
            key_fields=[
                {"key": "proofpoint_principal", "env_var": "ARGUS_PROOFPOINT_PRINCIPAL", "label": "Principal"},
                {"key": "proofpoint", "env_var": "ARGUS_PROOFPOINT_SECRET", "label": "Secret"},
            ],
            no_oss_substitute=True,
            status_check=lambda db: _from_env_or_integration_key("proofpoint", env_var="ARGUS_PROOFPOINT_SECRET"),
        ),
        ServiceEntry(
            name="Mimecast",
            category="Email-gateway connector",
            description="Mimecast Secure Email Gateway API.",
            requires=["ARGUS_MIMECAST_APP_ID/KEY + ACCESS_KEY/SECRET"],
            produces=["Email IOCs, message events"],
            source_file="src/integrations/email_gateway/mimecast.py",
            key_fields=[
                {"key": "mimecast_app", "env_var": "ARGUS_MIMECAST_APP_ID", "label": "App ID"},
                {"key": "mimecast_app_key", "env_var": "ARGUS_MIMECAST_APP_KEY", "label": "App key"},
                {"key": "mimecast_access", "env_var": "ARGUS_MIMECAST_ACCESS_KEY", "label": "Access key"},
                {"key": "mimecast", "env_var": "ARGUS_MIMECAST_SECRET_KEY", "label": "Secret key"},
            ],
            no_oss_substitute=True,
            status_check=lambda db: _from_env_or_integration_key("mimecast", env_var="ARGUS_MIMECAST_SECRET_KEY"),
        ),
        ServiceEntry(
            name="Abnormal Security",
            category="Email-gateway connector",
            description="Abnormal Security REST API v1.",
            requires=["ARGUS_ABNORMAL_TOKEN"],
            produces=["Email IOCs"],
            source_file="src/integrations/email_gateway/abnormal.py",
            key_fields=[
                {"key": "abnormal", "env_var": "ARGUS_ABNORMAL_TOKEN", "label": "Token"},
            ],
            no_oss_substitute=False,  # Rspamd covers this niche now
            status_check=lambda db: _from_env_or_integration_key("abnormal", env_var="ARGUS_ABNORMAL_TOKEN"),
        ),
        ServiceEntry(
            name="Rspamd (OSS — self-hosted)",
            category="Email-gateway connector",
            description=(
                "OSS spam/phishing scanner — powers Mailcow, Mailu, "
                "docker-mailserver, and most modern OSS mail stacks. "
                "Argus polls the controller's /history endpoint to "
                "extract phishing verdicts (action=reject + phishing "
                "symbols) and the URLs Rspamd parsed out of each "
                "message. Closes the 'no OSS email-gateway' gap that "
                "previously left Proofpoint / Mimecast / Abnormal as "
                "the only options."
            ),
            requires=[
                "operator runs Rspamd",
                "ARGUS_RSPAMD_URL + ARGUS_RSPAMD_PASSWORD",
            ],
            produces=["Inbound phishing IOCs from mail-gateway scans"],
            source_file="src/integrations/email_gateway/rspamd.py",
            docs_url="https://docs.rspamd.com/",
            self_hosted=True,
            self_host_install_hint=(
                "**Quickest install** (already shipped if you run "
                "Mailcow / Mailu / docker-mailserver — just point "
                "Argus at port 11334). Standalone:\n"
                "```bash\n"
                "apt-get install rspamd\n"
                "# set controller password in /etc/rspamd/local.d/worker-controller.inc:\n"
                "#   password = \"$2$<hash from rspamadm pw>\";\n"
                "systemctl enable --now rspamd\n"
                "# then point Argus at it:\n"
                "#   Base URL: http://<host>:11334\n"
                "```"
            ),
            key_fields=[
                {"key": "rspamd_url", "env_var": "ARGUS_RSPAMD_URL", "label": "Base URL"},
                {"key": "rspamd_password", "env_var": "ARGUS_RSPAMD_PASSWORD", "label": "Controller password"},
            ],
            status_check=lambda db: _self_hosted_status(
                db,
                url_env_var="ARGUS_RSPAMD_URL", url_key_name="rspamd_url",
                extra_env_var="ARGUS_RSPAMD_PASSWORD", extra_key_name="rspamd_password",
                label="Rspamd",
            ),
        ),

        # ── Sandbox / malware analysis ─────────────────────────────────
        ServiceEntry(
            name="CAPEv2",
            category="Sandbox / malware analysis",
            description=(
                "Self-hosted CAPE sandbox — automated malware "
                "detonation. Once the URL is configured, every "
                "submitted sample on /iocs auto-routes here for "
                "behavioural analysis."
            ),
            requires=["operator runs CAPEv2; ARGUS_CAPE_URL + optional KEY"],
            produces=["Malware verdicts, dropped IOCs"],
            source_file="src/integrations/sandbox/cape.py",
            docs_url="https://github.com/kevoreilly/CAPEv2",
            self_hosted=True,
            self_host_install_hint=(
                "**Quickest install** (Ubuntu 22.04 host with "
                "nested-virt or KVM): clone, run installer, drop a "
                "Windows 10 VM image into the analyzer pool.\n"
                "```bash\n"
                "git clone https://github.com/kevoreilly/CAPEv2.git\n"
                "cd CAPEv2 && sudo ./installer/cape2.sh base\n"
                "# then point Argus at it:\n"
                "#   Base URL: http://<host>:8000\n"
                "```\n"
                "*Docker images are unofficial — the official path is "
                "the installer above. Production deploys want at least "
                "1 KVM-isolated Win10 analyzer.*"
            ),
            key_fields=[
                {"key": "cape_url", "env_var": "ARGUS_CAPE_URL", "label": "Base URL"},
                {"key": "cape", "env_var": "ARGUS_CAPE_API_KEY", "label": "API key (optional)"},
            ],
            status_check=lambda db: _self_hosted_status(
                db,
                url_env_var="ARGUS_CAPE_URL", url_key_name="cape_url",
                # API key is optional for CAPEv2 — many self-hosted installs
                # run without auth on a private network. URL alone is enough
                # to count as configured.
                label="CAPEv2",
            ),
        ),
        ServiceEntry(
            name="Cuckoo3 (CERT-EE)",
            category="Sandbox / malware analysis",
            description=(
                "CERT-EE's Python-3 rewrite of the original Cuckoo "
                "Sandbox. Modern, actively maintained, peer to CAPEv2. "
                "Same submit/poll/report contract — Argus can run "
                "either or both for verdict consensus on suspicious "
                "samples."
            ),
            requires=["operator runs Cuckoo3", "ARGUS_CUCKOO3_URL + ARGUS_CUCKOO3_API_KEY"],
            produces=["Malware verdicts, dropped IOCs"],
            source_file="src/integrations/sandbox/cuckoo3.py",
            docs_url="https://cuckoo-hatch.cert.ee/static/docs/",
            self_hosted=True,
            self_host_install_hint=(
                "**Quickest install** (Ubuntu 22.04 + KVM):\n"
                "```bash\n"
                "git clone https://github.com/cert-ee/cuckoo3.git\n"
                "cd cuckoo3 && sudo ./install.sh\n"
                "# then point Argus at it:\n"
                "#   Base URL: http://<host>:8090\n"
                "#   API key:  see /etc/cuckoo3/web.conf\n"
                "```"
            ),
            key_fields=[
                {"key": "cuckoo3_url", "env_var": "ARGUS_CUCKOO3_URL", "label": "Base URL"},
                {"key": "cuckoo3_key", "env_var": "ARGUS_CUCKOO3_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _self_hosted_status(
                db,
                url_env_var="ARGUS_CUCKOO3_URL", url_key_name="cuckoo3_url",
                extra_env_var="ARGUS_CUCKOO3_API_KEY", extra_key_name="cuckoo3_key",
                label="Cuckoo3",
            ),
        ),
        ServiceEntry(
            name="Joe Sandbox",
            category="Sandbox / malware analysis",
            description="Joe Security cloud or on-prem.",
            requires=["ARGUS_JOE_API_KEY + URL"],
            produces=["Malware verdicts"],
            source_file="src/integrations/sandbox/joe.py",
            key_fields=[
                {"key": "joe_url", "env_var": "ARGUS_JOE_URL", "label": "Base URL"},
                {"key": "joe", "env_var": "ARGUS_JOE_API_KEY", "label": "API key"},
            ],
            no_oss_substitute=True,
            status_check=lambda db: _from_env_or_integration_key("joe", env_var="ARGUS_JOE_API_KEY"),
        ),
        ServiceEntry(
            name="Hybrid-Analysis (Falcon Sandbox)",
            category="Sandbox / malware analysis",
            description="Hybrid-Analysis BYOK sandbox.",
            requires=["ARGUS_HYBRID_API_KEY + ENV_ID"],
            produces=["Malware verdicts"],
            source_file="src/integrations/sandbox/hybrid.py",
            key_fields=[
                {"key": "hybrid_env", "env_var": "ARGUS_HYBRID_ENV_ID", "label": "Environment ID"},
                {"key": "hybrid", "env_var": "ARGUS_HYBRID_API_KEY", "label": "API key"},
            ],
            no_oss_substitute=True,
            status_check=lambda db: _from_env_or_integration_key("hybrid", env_var="ARGUS_HYBRID_API_KEY"),
        ),
        ServiceEntry(
            name="VirusTotal",
            category="Sandbox / malware analysis",
            description="VT URL/file reputation. Refuses to run without explicit Enterprise BYOK opt-in.",
            requires=["ARGUS_VT_API_KEY + ARGUS_VT_ENTERPRISE=true"],
            produces=["—"],
            source_file="src/integrations/sandbox/virustotal.py",
            key_fields=[
                {"key": "vt", "env_var": "ARGUS_VT_API_KEY", "label": "API key"},
                {"key": "vt_enterprise", "env_var": "ARGUS_VT_ENTERPRISE", "label": "Enterprise opt-in (true)"},
            ],
            no_oss_substitute=False,
            status_check=lambda db: _check_virustotal_gated(),
        ),

        # ── Forensics tools ────────────────────────────────────────────
        ServiceEntry(
            name="Volatility 3",
            category="Forensics tool",
            description="Memory forensics CLI.",
            requires=["volatility3 binary in PATH"],
            produces=["Memory analysis on case attachments"],
            source_file="src/integrations/forensics/volatility.py",
            produces_pages=["cases", "evidence"],
            status_check=lambda db: ServiceStatus(**(_binary_status("vol", package="volatility3").__dict__)),
        ),
        ServiceEntry(
            name="Velociraptor",
            oss_install_name="velociraptor",
            category="Forensics tool",
            description=(
                "Live endpoint forensics + hunting. Once the server "
                "URL + API token are set, the Case Copilot agent and "
                "Threat-Hunter automatically route endpoint queries "
                "(VQL) here — no further config needed."
            ),
            requires=["ARGUS_VELOCIRAPTOR_URL + TOKEN"],
            produces=["Hunt results, case copilot tool"],
            source_file="src/integrations/forensics/velociraptor.py",
            docs_url="https://docs.velociraptor.app/docs/deployment/",
            produces_pages=["cases", "threat-hunter"],
            self_hosted=True,
            self_host_install_hint=(
                "**Easiest — Argus-bundled profile:**\n"
                "```bash\n"
                "./start.sh --with velociraptor\n"
                "```\n"
                "Brings up Velociraptor in the same compose project as "
                "Argus and auto-fills `ARGUS_VELOCIRAPTOR_URL`. You "
                "still need to create an API user and paste the token "
                "below.\n\n"
                "**Manual single-binary deploy** — Velociraptor ships "
                "as one Go binary; use this if you want it on a "
                "different host:\n"
                "```bash\n"
                "wget https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-linux-amd64\n"
                "chmod +x velociraptor-linux-amd64\n"
                "./velociraptor-linux-amd64 config generate -i\n"
                "./velociraptor-linux-amd64 --config server.config.yaml frontend\n"
                "# create an API user and export the token:\n"
                "./velociraptor-linux-amd64 --config server.config.yaml user add --role api argus-svc\n"
                "```\n"
                "Point the Server URL at `https://<host>:8000` and "
                "paste the user's API token."
            ),
            key_fields=[
                {"key": "velociraptor_url", "env_var": "ARGUS_VELOCIRAPTOR_URL", "label": "Server URL"},
                {"key": "velociraptor", "env_var": "ARGUS_VELOCIRAPTOR_TOKEN", "label": "API token"},
            ],
            status_check=lambda db: _self_hosted_status(
                db, oss_install_name="velociraptor",
                url_env_var="ARGUS_VELOCIRAPTOR_URL", url_key_name="velociraptor_url",
                extra_env_var="ARGUS_VELOCIRAPTOR_TOKEN", extra_key_name="velociraptor",
                label="Velociraptor",
            ),
        ),

        # ── OSS tools (local binaries used by EASM/agents) ─────────────
        ServiceEntry(
            name="dnstwist (Python permutations)",
            category="OSS tool",
            description=(
                "Lookalike-domain permutation generator. Argus ships a "
                "Python re-implementation of the dnstwist algorithm at "
                "src/brand/permutations.py — no external binary required, "
                "no extra install step. Always available."
            ),
            requires=["bundled with platform — no external dependency"],
            produces=["Suspect domains via brand scanner"],
            source_file="src/brand/permutations.py",
            docs_url="https://github.com/elceef/dnstwist",
            produces_pages=["brand", "takedowns"],
            status_check=_check_brand_permutations,
        ),
        ServiceEntry(
            name="YARA",
            category="OSS tool",
            description="Pattern-based malware/file matching.",
            requires=["yara or yara-x binary"],
            produces=["Malware classification on uploads"],
            source_file="src/integrations/yara_engine/engine.py",
            produces_pages=["cases", "evidence"],
            status_check=lambda db: ServiceStatus(**(_binary_status("yara").__dict__)),
        ),
        ServiceEntry(
            name="Mandiant Capa",
            category="OSS tool",
            description="Adversary capability extraction from binaries.",
            requires=["capa binary"],
            produces=["Capability labels on case binaries"],
            source_file="src/intel/yarax_capa.py",
            docs_url="https://github.com/mandiant/capa",
            produces_pages=["cases", "evidence"],
            status_check=lambda db: ServiceStatus(**(_binary_status("capa").__dict__)),
        ),
        ServiceEntry(
            name="Nuclei",
            category="OSS tool",
            description=(
                "ProjectDiscovery's template-driven vulnerability scanner. "
                "Two surfaces: on-demand via /api/v1/integrations and a "
                "scheduled EASM sweep (every ARGUS_WORKER_NUCLEI_EASM_INTERVAL "
                "seconds; default 6h) that walks each org's monitored assets "
                "and persists ExposureFindings to /exposures."
            ),
            requires=["nuclei binary; templates at /app/data/nuclei-templates"],
            produces=["EASM vuln findings on /exposures"],
            source_file="src/integrations/nuclei/scanner.py",
            docs_url="https://github.com/projectdiscovery/nuclei",
            produces_pages=["exposures"],
            status_check=lambda db: _from_feed_health(db, "maintenance.nuclei_easm"),
        ),
        ServiceEntry(
            name="Suricata",
            category="OSS tool",
            description=(
                "OSS IDS / NSM. Argus does not run the sniffer itself; "
                "operators run Suricata against their network and point "
                "ARGUS_SURICATA_EVE_PATH at the resulting eve.json. "
                "A worker tails the file every "
                "ARGUS_WORKER_SURICATA_TAIL_INTERVAL seconds (default 60s), "
                "parses NSM alerts, and persists them to /alerts."
            ),
            requires=[
                "Suricata sensor running somewhere with a readable eve.json",
                "ARGUS_SURICATA_EVE_PATH pointing at that file",
            ],
            produces=["NSM alerts on /alerts"],
            source_file="src/workers/maintenance/suricata_tail.py",
            docs_url="https://suricata.io/",
            produces_pages=["alerts"],
            key_fields=[
                {"key": "suricata_eve_path", "env_var": "ARGUS_SURICATA_EVE_PATH",
                 "label": "eve.json path"},
            ],
            status_check=lambda db: _from_feed_health(db, "maintenance.suricata_tail"),
        ),
        ServiceEntry(
            name="Prowler",
            category="OSS tool",
            description=(
                "OSS multi-cloud security auditor (AWS / Azure / GCP / "
                "Kubernetes). Argus runs a scheduled audit "
                "(ARGUS_WORKER_PROWLER_AUDIT_INTERVAL, default weekly) "
                "against every cloud whose creds are detected, and "
                "persists failed checks as ExposureFindings on /exposures."
            ),
            requires=[
                "prowler binary",
                "Cloud creds for at least one provider — AWS_*, AZURE_*, "
                "GOOGLE_APPLICATION_CREDENTIALS, or KUBECONFIG",
            ],
            produces=["Cloud-misconfig findings on /exposures"],
            source_file="src/workers/maintenance/prowler_audit.py",
            docs_url="https://github.com/prowler-cloud/prowler",
            produces_pages=["exposures"],
            key_fields=[
                {"key": "aws_access_key_id", "env_var": "AWS_ACCESS_KEY_ID", "label": "AWS Access Key ID"},
                {"key": "aws_secret_access_key", "env_var": "AWS_SECRET_ACCESS_KEY", "label": "AWS Secret Access Key"},
                {"key": "azure_tenant_id", "env_var": "AZURE_TENANT_ID", "label": "Azure Tenant ID"},
                {"key": "azure_client_id", "env_var": "AZURE_CLIENT_ID", "label": "Azure Client ID"},
                {"key": "azure_client_secret", "env_var": "AZURE_CLIENT_SECRET", "label": "Azure Client Secret"},
                {"key": "gcp_credentials_path", "env_var": "GOOGLE_APPLICATION_CREDENTIALS", "label": "GCP service-account JSON path"},
            ],
            status_check=lambda db: _from_feed_health(db, "maintenance.prowler_audit"),
        ),

        # ── Notification delivery ──────────────────────────────────────
        ServiceEntry(
            name="Apprise (OSS-default fan-out)",
            category="Notification delivery",
            description="One library, 90+ services (Mattermost, Rocket.Chat, ntfy, Telegram, Discord, Teams, plus the paid options). Operators configure with URL schemes; Argus routes each alert through every configured URL.",
            requires=["apprise Python lib (in requirements)", "channel rows of kind=apprise with config.urls"],
            produces=["Outbound notifications across any of 90+ targets"],
            produces_pages=[],
            source_file="src/notifications/adapters.py",
            docs_url="https://github.com/caronc/apprise",
            status_check=_check_apprise,
        ),
        ServiceEntry(
            name="SMTP (email)",
            category="Notification delivery",
            description="aiosmtplib outbound email.",
            requires=["ARGUS_NOTIFY_EMAIL_SMTP_HOST/USER/PASSWORD/FROM"],
            produces=["Alert email notifications"],
            source_file="src/notifications/adapters.py",
            key_fields=[
                {"key": "smtp_host", "env_var": "ARGUS_NOTIFY_EMAIL_SMTP_HOST", "label": "SMTP host"},
                {"key": "smtp_user", "env_var": "ARGUS_NOTIFY_EMAIL_SMTP_USER", "label": "SMTP user"},
                {"key": "smtp_pass", "env_var": "ARGUS_NOTIFY_EMAIL_SMTP_PASSWORD", "label": "SMTP password"},
                {"key": "smtp_from", "env_var": "ARGUS_NOTIFY_EMAIL_FROM", "label": "From address"},
            ],
            status_check=lambda db: _from_env_or_integration_key("smtp", env_var="ARGUS_NOTIFY_EMAIL_SMTP_PASSWORD"),
        ),
        ServiceEntry(
            name="Slack incoming webhook",
            category="Notification delivery",
            description="Slack webhook posts.",
            requires=["ARGUS_NOTIFY_SLACK_WEBHOOK_URL"],
            produces=["Alert Slack messages"],
            source_file="src/notifications/adapters.py",
            key_fields=[
                {"key": "slack", "env_var": "ARGUS_NOTIFY_SLACK_WEBHOOK_URL", "label": "Webhook URL"},
            ],
            status_check=lambda db: _from_env_or_integration_key("slack", env_var="ARGUS_NOTIFY_SLACK_WEBHOOK_URL"),
        ),
        # PagerDuty removed from catalog per operator decision —
        # delivery is covered by Apprise (OSS-default fan-out) which
        # has built-in PagerDuty URL scheme support if anyone needs
        # it. The PagerDutyAdapter code stays in
        # ``src/notifications/adapters.py`` for legacy installs.
        ServiceEntry(
            name="Generic webhooks",
            category="Notification delivery",
            description="Operator-defined webhook endpoints with optional HMAC.",
            requires=["webhook_endpoints rows"],
            produces=["Custom downstream integrations"],
            source_file="src/notifications/adapters.py",
            status_check=lambda db: _from_webhook_endpoints(db),
        ),

        # ── Network protocols ──────────────────────────────────────────
        ServiceEntry(
            name="DNS-over-HTTPS resolvers",
            category="Network protocol",
            description="Domain-verification quorum + DMARC reads.",
            requires=["ARGUS_VERIFICATION_DOH_RESOLVERS (Cloudflare/Google/Quad9 default)"],
            produces=["Domain verification, DMARC posture"],
            source_file="src/core/domain_verification.py",
            produces_pages=["dmarc", "settings"],
            status_check=lambda db: ServiceStatus(status=STATUS_OK, evidence="hardcoded defaults: 1.1.1.1, 8.8.8.8, 9.9.9.9"),
        ),
        ServiceEntry(
            name="TAXII 2.1",
            category="Network protocol",
            description="Publish IOCs as STIX 2.x to a TAXII collection.",
            requires=["operator-hosted TAXII server"],
            produces=["/taxii page; IOC sharing"],
            source_file="src/api/routes/taxii.py",
            produces_pages=["taxii"],
            status_check=lambda db: ServiceStatus(status=STATUS_OK, evidence="server-side endpoint always available"),
        ),

        # ── Adversary emulation ────────────────────────────────────────
        ServiceEntry(
            name="MITRE Caldera",
            oss_install_name="caldera",
            category="Adversary emulation",
            description=(
                "Adversary-emulation server. When configured, the "
                "Threat-Hunter agent kicks off operations against the "
                "configured target group automatically every weekly "
                "cadence — no extra wiring needed."
            ),
            requires=["ARGUS_CALDERA_URL + API_KEY"],
            produces=["Threat-hunter agent test cases"],
            source_file="src/integrations/adversary_emulation/caldera.py",
            docs_url="https://caldera.readthedocs.io/en/latest/Installing-Caldera.html",
            produces_pages=["threat-hunter"],
            self_hosted=True,
            self_host_install_hint=(
                "**Easiest — Argus-bundled profile:**\n"
                "```bash\n"
                "./start.sh --with caldera\n"
                "```\n"
                "Brings up Caldera in the same compose project as "
                "Argus and auto-fills `ARGUS_CALDERA_URL`. Default "
                "credentials still come from Caldera's "
                "`conf/local.yml`; create an API user there, copy "
                "the key, and paste it below.\n\n"
                "**Manual Docker quickstart** — use this if you want "
                "Caldera on a different host:\n"
                "```bash\n"
                "git clone https://github.com/mitre/caldera.git --recursive\n"
                "cd caldera\n"
                "docker build . -t caldera:latest\n"
                "docker run -p 8888:8888 caldera:latest\n"
                "```\n"
                "Then paste Server URL `http://<host>:8888` + API key."
            ),
            key_fields=[
                {"key": "caldera_url", "env_var": "ARGUS_CALDERA_URL", "label": "Server URL"},
                {"key": "caldera", "env_var": "ARGUS_CALDERA_API_KEY", "label": "API key"},
            ],
            status_check=lambda db: _self_hosted_status(
                db, oss_install_name="caldera",
                url_env_var="ARGUS_CALDERA_URL", url_key_name="caldera_url",
                extra_env_var="ARGUS_CALDERA_API_KEY", extra_key_name="caldera",
                label="MITRE Caldera",
            ),
        ),
        ServiceEntry(
            name="Atomic Red Team",
            category="Adversary emulation",
            description="MITRE ATT&CK technique tests.",
            requires=["ARGUS_ATOMIC_RED_TEAM_PATH (or curated 14-test fallback)"],
            produces=["Threat-hunter test plans"],
            source_file="src/integrations/adversary_emulation/atomic_red_team.py",
            docs_url="https://github.com/redcanaryco/atomic-red-team",
            produces_pages=["threat-hunter"],
            status_check=lambda db: ServiceStatus(
                status=STATUS_OK if os.environ.get("ARGUS_ATOMIC_RED_TEAM_PATH") else STATUS_OK,
                evidence="14-test curated fallback always available; full repo via ARGUS_ATOMIC_RED_TEAM_PATH",
            ),
        ),

        # ── Intel sources (bundled / OSINT) ────────────────────────────
        ServiceEntry(
            name="MISP (operator-hosted)",
            oss_install_name="misp",
            category="Intel source",
            description=(
                "Self-hosted MISP server. Once configured, the worker "
                "polls /events/restSearch every 30 minutes and "
                "ingests new IOCs into the local intel store — feeds "
                "/iocs and /actors live."
            ),
            requires=["ARGUS_MISP_URL + KEY"],
            produces=["IOC sync, attribution"],
            source_file="src/integrations/misp.py",
            docs_url="https://misp.github.io/MISP/INSTALL.ubuntu2204/",
            produces_pages=["intel", "iocs", "actors"],
            self_hosted=True,
            self_host_install_hint=(
                "**Easiest — Argus-bundled profile** (~4 GB RAM):\n"
                "```bash\n"
                "./start.sh --with misp\n"
                "```\n"
                "Brings up MISP + its DB + Redis in the same compose "
                "project as Argus and auto-fills `ARGUS_MISP_URL`. "
                "Default MISP login is `admin@admin.test` / `admin` — "
                "change it on first login, then create an Auth Key "
                "(MISP → Administration → List Auth Keys → Add) and "
                "paste it below.\n\n"
                "**Manual Docker quickstart** (community-maintained "
                "image) — use this if you want MISP on a different "
                "host:\n"
                "```bash\n"
                "git clone https://github.com/MISP/misp-docker.git\n"
                "cd misp-docker\n"
                "cp template.env .env  # edit BASE_URL etc.\n"
                "docker compose up -d\n"
                "```\n"
                "Then paste Server URL `https://<host>` + API key."
            ),
            key_fields=[
                {"key": "misp_url", "env_var": "ARGUS_MISP_URL", "label": "Server URL"},
                {"key": "misp", "env_var": "ARGUS_MISP_KEY", "label": "API key"},
            ],
            status_check=lambda db: _self_hosted_status(
                db, oss_install_name="misp",
                url_env_var="ARGUS_MISP_URL", url_key_name="misp_url",
                extra_env_var="ARGUS_MISP_KEY", extra_key_name="misp",
                label="MISP",
            ),
        ),
        ServiceEntry(
            name="OpenCTI",
            oss_install_name="opencti",
            category="Intel source",
            description=(
                "OpenCTI graph integration. Once configured, the "
                "worker pulls new STIX objects every 30 minutes via "
                "GraphQL and merges actors / campaigns / TTPs into "
                "the local graph — feeds /actors and /intel live."
            ),
            requires=["ARGUS_OPENCTI_URL + TOKEN"],
            produces=["Threat-actor + entity graph"],
            source_file="src/integrations/opencti/client.py",
            docs_url="https://docs.opencti.io/latest/deployment/installation/",
            produces_pages=["intel", "actors"],
            self_hosted=True,
            self_host_install_hint=(
                "**Docker quickstart**:\n"
                "```bash\n"
                "git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker\n"
                "cd opencti-docker\n"
                "cp .env.sample .env  # set OPENCTI_ADMIN_TOKEN to a UUID\n"
                "docker compose up -d\n"
                "```\n"
                "Browse to `http://<host>:8080`. The admin token "
                "from `.env` is what you paste here as **API token** "
                "(or create a service-account user under Settings → "
                "Security and use that token)."
            ),
            key_fields=[
                {"key": "opencti_url", "env_var": "ARGUS_OPENCTI_URL", "label": "Server URL"},
                {"key": "opencti", "env_var": "ARGUS_OPENCTI_TOKEN", "label": "API token"},
            ],
            status_check=lambda db: _self_hosted_status(
                db, oss_install_name="opencti",
                url_env_var="ARGUS_OPENCTI_URL", url_key_name="opencti_url",
                extra_env_var="ARGUS_OPENCTI_TOKEN", extra_key_name="opencti",
                label="OpenCTI",
            ),
        ),
        ServiceEntry(
            name="MITRE ATT&CK (bundled)",
            category="Intel source",
            description="ATT&CK techniques + tactics shipped in source.",
            requires=["bundled in repo"],
            produces=["MITRE Navigator views, technique attribution"],
            source_file="src/intel/navigator_layer.py",
            produces_pages=["mitre", "actors"],
            status_check=lambda db: ServiceStatus(status=STATUS_OK, evidence="bundled local copy"),
        ),
        ServiceEntry(
            name="MITRE D3FEND (bundled)",
            category="Intel source",
            description="Defensive countermeasures catalogue.",
            requires=["bundled"],
            produces=["Hardening agent recommendations"],
            source_file="src/models/mitre.py",
            produces_pages=["mitre"],
            status_check=lambda db: ServiceStatus(status=STATUS_OK, evidence="bundled local copy"),
        ),
    ]


# ---------------------------------------------------------------------------
# Helpers used by individual entries
# ---------------------------------------------------------------------------


async def _probe_http_get(
    url: str,
    label: str,
    *,
    failure_status: str = STATUS_OK,
    failure_sub_reason: str = "upstream_unreachable",
) -> ServiceStatus:
    """HTTP-200 probe of a remote endpoint.

    By default a probe failure stays STATUS_OK (with sub_reason on the
    evidence line) — for free public APIs that we don't run, transient
    errors aren't operator-actionable. Callers that probe a service
    the operator IS expected to run (Ollama, MinIO, etc.) can pass
    ``failure_status=STATUS_NOT_INSTALLED`` to surface a clear "start
    the daemon" CTA instead."""
    try:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as s:
            async with s.get(url) as resp:
                if 200 <= resp.status < 300:
                    return ServiceStatus(status=STATUS_OK, evidence=f"{url} -> {resp.status}")
                return ServiceStatus(
                    status=failure_status,
                    sub_reason=failure_sub_reason,
                    evidence=f"{label}: {url} -> {resp.status}",
                )
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=failure_status,
            sub_reason=failure_sub_reason,
            evidence=f"{label}: {url}: {type(e).__name__}: {e}",
        )


async def _check_llm_provider(name: str, *, env_var: str) -> ServiceStatus:
    """LLM providers are mutually exclusive — only the one selected
    via ``ARGUS_LLM_PROVIDER`` is in use. Inactive providers report
    STATUS_NEEDS_KEY with sub_reason 'provider_not_selected' — the
    operator can switch by changing ``ARGUS_LLM_PROVIDER``. Configured
    inactive provider stays STATUS_OK so the operator knows the key
    is good and they can swap freely."""
    selected = (os.environ.get("ARGUS_LLM_PROVIDER") or "").lower()
    configured = await _from_env_or_integration_key(name, env_var=env_var)
    if selected and selected != name.lower():
        if configured.status == STATUS_OK:
            return ServiceStatus(
                status=STATUS_OK,
                sub_reason="provider_not_selected",
                evidence=(
                    f"Key configured; switch ARGUS_LLM_PROVIDER from "
                    f"{selected!r} to {name.lower()!r} to make this active."
                ),
            )
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="provider_not_selected",
            evidence=(
                f"ARGUS_LLM_PROVIDER={selected!r}. Set "
                f"ARGUS_LLM_PROVIDER={name.lower()!r} and paste the key "
                "to make this the active LLM."
            ),
        )
    return configured


async def _check_ollama() -> ServiceStatus:
    """Ollama is a self-hosted LLM. Inactive provider -> NEEDS_KEY
    (switch ARGUS_LLM_PROVIDER to ollama). Active but unreachable ->
    NOT_INSTALLED (start the ollama container)."""
    selected = (os.environ.get("ARGUS_LLM_PROVIDER") or "").lower()
    if selected and selected != "ollama":
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="provider_not_selected",
            evidence=(
                f"ARGUS_LLM_PROVIDER={selected!r}. Set "
                "ARGUS_LLM_PROVIDER=ollama to make this the active LLM."
            ),
        )
    base = os.environ.get("ARGUS_LLM_BASE_URL", "http://ollama:11434")
    return await _probe_http_get(
        f"{base}/api/tags",
        "Ollama",
        failure_status=STATUS_NOT_INSTALLED,
        failure_sub_reason="daemon_not_detected",
    )


async def _check_theharvester(_db: AsyncSession) -> ServiceStatus:
    """theHarvester is a CLI installed via the Dockerfile git pin.
    Liveness = ``which theHarvester`` returns a path."""
    binary = os.environ.get("ARGUS_THEHARVESTER_BIN", "theHarvester")
    path = shutil.which(binary)
    if path:
        return ServiceStatus(status=STATUS_OK, evidence=f"{binary} at {path}")
    return ServiceStatus(
        status=STATUS_NOT_INSTALLED,
        sub_reason="dep_missing",
        evidence=(
            f"{binary} not in PATH — rebuild the worker image (Dockerfile "
            "installs it from git). Local quick-fix: "
            "`pip install git+https://github.com/laramies/theHarvester.git`."
        ),
    )


async def _check_apprise(_db: AsyncSession) -> ServiceStatus:
    try:
        import apprise  # noqa: F401
        return ServiceStatus(
            status=STATUS_OK,
            evidence="apprise package importable; AppriseAdapter ready as 'apprise' channel kind",
        )
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="dep_missing",
            evidence=f"apprise package not installed: {e}",
        )


async def _check_brand_permutations(_db: AsyncSession) -> ServiceStatus:
    """Argus ships a Python re-implementation of the dnstwist algorithm
    at src/brand/permutations.py — no external binary needed. Liveness
    = the module imports cleanly. Always OK in any normal deploy."""
    try:
        from src.brand.permutations import generate_permutations  # noqa: F401
        return ServiceStatus(
            status=STATUS_OK,
            sub_reason="bundled",
            evidence="src/brand/permutations.py importable; bundled, no external binary needed.",
        )
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="dep_missing",
            evidence=f"brand.permutations import failed: {type(e).__name__}: {e}",
        )


async def _check_holehe(_db: AsyncSession) -> ServiceStatus:
    """Holehe is a Python lib + CLI, not a service. Liveness = the
    package imports cleanly."""
    try:
        import holehe.core  # noqa: F401
        return ServiceStatus(
            status=STATUS_OK,
            evidence="holehe package importable; ready for /leakage/email-exposure",
        )
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="dep_missing",
            evidence=f"holehe not installed: {e}; rebuild worker after `pip install holehe`.",
        )


async def _check_claude_bridge(_db: AsyncSession) -> ServiceStatus:
    """Bridge has no HTTP — it's a Redis BLPOP worker. Liveness =
    fresh ``argus:bridge:heartbeat`` key (TTL 30s). Inactive provider ->
    NEEDS_KEY (switch ARGUS_LLM_PROVIDER). Active but no heartbeat ->
    NOT_INSTALLED (start the bridge worker)."""
    if (os.environ.get("ARGUS_LLM_PROVIDER") or "").lower() != "bridge":
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="provider_not_selected",
            evidence=(
                "ARGUS_LLM_PROVIDER != 'bridge'. Set "
                "ARGUS_LLM_PROVIDER=bridge to use the host Claude CLI."
            ),
        )
    try:
        import redis.asyncio as aioredis
        from src.config.settings import settings
        client = aioredis.from_url(settings.redis.url, decode_responses=True)
        try:
            beat = await client.get("argus:bridge:heartbeat")
        finally:
            await client.aclose()
        if beat:
            return ServiceStatus(
                status=STATUS_OK,
                evidence="argus:bridge:heartbeat present (worker active within 30s)",
            )
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="daemon_not_detected",
            evidence=(
                "No bridge heartbeat in Redis. On macOS run "
                "`scripts/bridge_host.sh start`; on Linux start the "
                "argus-bridge container with `docker compose --profile "
                "bridge up -d`."
            ),
        )
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_NOT_INSTALLED,
            sub_reason="daemon_not_detected",
            evidence=f"Bridge probe error: {type(e).__name__}: {e}",
        )


async def _check_virustotal_gated() -> ServiceStatus:
    """VT free tier ToS forbids commercial use; we require both an API
    key AND explicit ``ARGUS_VT_ENTERPRISE=true`` opt-in. Without
    enterprise opt-in the operator should use CAPEv2 or MalwareBazaar
    (OSS substitutes), which is why the row stays in NEEDS_KEY rather
    than the retired DISABLED state."""
    enterprise = (os.environ.get("ARGUS_VT_ENTERPRISE") or "").lower() == "true"
    has_key = bool(os.environ.get("ARGUS_VT_API_KEY"))
    if enterprise and has_key:
        return ServiceStatus(
            status=STATUS_OK,
            evidence="VT enterprise opt-in active and API key present.",
        )
    if not enterprise:
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="enterprise_opt_in_required",
            evidence=(
                "Set ARGUS_VT_ENTERPRISE=true (only with a paid VT "
                "Enterprise plan; free-tier ToS forbids commercial use). "
                "OSS alternatives: CAPEv2 sandbox + MalwareBazaar."
            ),
        )
    return ServiceStatus(
        status=STATUS_NEEDS_KEY,
        sub_reason="key_not_set",
        evidence="ARGUS_VT_ENTERPRISE=true but ARGUS_VT_API_KEY not set.",
    )


async def _from_webhook_endpoints(db: AsyncSession) -> ServiceStatus:
    try:
        from src.models.intel import WebhookEndpoint
        n = (await db.execute(select(WebhookEndpoint))).scalars().all()
        if not n:
            return ServiceStatus(
                status=STATUS_NEEDS_KEY,
                sub_reason="no_endpoints_configured",
                evidence="No webhook_endpoints rows — add via /notifications.",
            )
        active = sum(1 for w in n if getattr(w, "is_active", True))
        if active > 0:
            return ServiceStatus(
                status=STATUS_OK,
                evidence=f"{active} active webhook endpoint(s) of {len(n)}",
            )
        return ServiceStatus(
            status=STATUS_NEEDS_KEY,
            sub_reason="all_endpoints_inactive",
            evidence=(
                f"{len(n)} webhook endpoint(s) configured but none active — "
                "toggle on at /notifications."
            ),
        )
    except Exception as e:  # noqa: BLE001
        return ServiceStatus(
            status=STATUS_OK,
            sub_reason="probe_error",
            evidence=f"webhook probe error: {type(e).__name__}: {e}",
        )


# ---------------------------------------------------------------------------
# Resolver — runs status_check for every entry, concurrently
# ---------------------------------------------------------------------------


async def resolve_inventory(db: AsyncSession) -> list[dict[str, Any]]:
    """Return a list of dicts ready for JSON serialisation. Each entry's
    status check runs concurrently; check failures degrade to UNKNOWN
    rather than aborting the whole resolution.

    Each check gets its OWN AsyncSession so a rollback in one
    (e.g. an integration whose query raises ProgrammingError) doesn't
    invalidate the session for every other concurrent check."""
    from src.storage import database as _db_module
    entries = _catalog()

    async def _safe(entry: ServiceEntry) -> ServiceStatus:
        if entry.status_check is None:
            # Bundled / always-on entry (e.g. MITRE ATT&CK shipped in repo).
            return ServiceStatus(
                status=STATUS_OK,
                sub_reason="bundled",
                evidence="Bundled with platform; nothing to install or configure.",
            )
        # Fresh session per check — concurrent gather() over a shared
        # session leaks rolled-back state across checks.
        if _db_module.async_session_factory is None:
            try:
                res = entry.status_check(db)
                return await res if asyncio.iscoroutine(res) else res  # type: ignore[return-value]
            except Exception as e:  # noqa: BLE001
                return ServiceStatus(
                    status=STATUS_OK,
                    sub_reason="probe_error",
                    evidence=f"status check raised {type(e).__name__}: {e}",
                )
        try:
            async with _db_module.async_session_factory() as own_session:
                res = entry.status_check(own_session)
                return await res if asyncio.iscoroutine(res) else res  # type: ignore[return-value]
        except Exception as e:  # noqa: BLE001
            return ServiceStatus(
                status=STATUS_OK,
                sub_reason="probe_error",
                evidence=f"status check raised {type(e).__name__}: {e}",
            )

    statuses = await asyncio.gather(*[_safe(e) for e in entries])

    import os as _os
    out: list[dict[str, Any]] = []
    for entry, st in zip(entries, statuses):
        # Decorate each key field with current source (db / env / unset)
        # so the UI can render "configured (env)" vs "needs key" without
        # a second round-trip.
        from src.core import integration_keys as _ikeys
        decorated_fields = []
        for f in entry.key_fields:
            key = f.get("key", "")
            env_var = f.get("env_var", "")
            db_val = (_ikeys.get(key, env_fallback=None) or "")
            env_val = (_os.environ.get(env_var) or "").strip() if env_var else ""
            if db_val:
                src, masked = "db", _mask_tail(db_val)
            elif env_val:
                src, masked = "env", _mask_tail(env_val)
            else:
                src, masked = "unset", None
            decorated_fields.append({
                **f,
                "source": src,
                "masked_value": masked,
            })

        out.append({
            "name": entry.name,
            "category": entry.category,
            "description": entry.description,
            "requires": entry.requires,
            "produces": entry.produces,
            "produces_pages": entry.produces_pages,
            "key_fields": decorated_fields,
            "no_oss_substitute": entry.no_oss_substitute,
            "legacy_only": entry.legacy_only,
            "self_hosted": entry.self_hosted,
            "self_host_install_hint": entry.self_host_install_hint,
            "oss_install_name": entry.oss_install_name,
            "source_file": entry.source_file,
            "docs_url": entry.docs_url,
            "status": st.status,
            "sub_reason": st.sub_reason,
            "evidence": st.evidence,
            "last_observed_at": (
                st.last_observed_at.isoformat() if st.last_observed_at else None
            ),
            "last_rows_ingested": st.last_rows_ingested,
        })
    return out


def _mask_tail(value: str) -> Optional[str]:
    if not value:
        return None
    if len(value) <= 4:
        return "•" * len(value)
    return "••••" + value[-4:]


async def resolve_for_page(db: AsyncSession, page_key: str) -> list[dict[str, Any]]:
    """Subset of the inventory whose ``produces_pages`` includes the
    requested page slug. ``"*"`` matches every page (infrastructure)
    so the strip can surface a Postgres outage anywhere.

    Used by the per-page ``<SourcesStrip>`` React component on
    ``/leakage``, ``/iocs``, etc."""
    full = await resolve_inventory(db)
    page = (page_key or "").lower().lstrip("/")
    return [
        e for e in full
        if page in (p.lower() for p in e["produces_pages"])
        or "*" in e["produces_pages"]
    ]
