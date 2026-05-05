"""Per-org intel-collection setup orchestrator.

When an Organization is first created (or when an operator re-enters
the onboarding wizard), Argus runs a one-time scaffold that wires up:

1. **Google Alerts custom_http target** — placeholder URL the operator
   replaces with their RSS Alert URL. Brand-search RSS is the highest-
   leverage org-specific feed because the operator can configure it
   in 5 minutes from Google Alerts and no API key is needed.
2. **Mention.com placeholder integration** — works only if the
   operator pastes a Mention API key into Settings → Services.
3. **Stealer-marketplace placeholders** — disabled crawler_targets for
   common stealer markets. Operator must enable + provide current
   onion URLs (those rotate frequently and we won't ship live links).
4. **VIP scaffolding** — empty placeholder rows the operator fills
   from the dashboard's `/admin → VIPs` surface. Permutation expansion
   in the triage prompt kicks in automatically once names are added.
5. **Typosquat scan** — immediate scan now + recurring daily cron via
   the existing brand scanner, scoped to ``org.domains``.
6. **NEEDS_REVIEW gate** — sets a sensible ``confidence_threshold`` on
   the org's settings. Borderline LLM judgments become NEEDS_REVIEW
   alerts (human-in-the-loop) instead of either silent NEW alerts or
   silent drops. Default is 0.55 — tune in Settings.

Each step is idempotent: re-running this function never duplicates a
row. Failure of any one step is logged and reported but does NOT block
the others — onboarding never wedges because of a single misconfig.

The function returns a structured report so the dashboard's onboarding
done-page can render a checklist showing which items are configured
vs. which still need operator input (e.g. "paste your Google Alerts
RSS URL", "enable stealer markets you have legal authority to scrape").
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.threat import Organization, VIPTarget
from src.models.admin import CrawlerKind, CrawlerTarget

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Tunables
# ----------------------------------------------------------------------

# Sensible default confidence threshold. Below this, the triage agent
# emits NEEDS_REVIEW alerts (human gate) instead of NEW alerts. The
# operator can dial up to be more strict (fewer alerts) or down to
# auto-promote more (less human review). 0.55 is a balanced starting
# point for banking / regulated verticals where you want analyst
# eyeballs on borderline brand mentions.
DEFAULT_CONFIDENCE_THRESHOLD = 0.55

# Curated list of well-known stealer marketplaces. We seed disabled
# rows with placeholder onion URLs so the operator sees the surface
# and can opt in. We don't ship LIVE onion URLs because they rotate
# every few weeks and shipping a stale or seized URL would just waste
# crawler budget and confuse the operator.
_STEALER_MARKETPLACES_CATALOG = [
    ("russianmarket", "Russian Market"),
    ("genesis_2", "Genesis Market 2.0"),
    ("twoeasy", "2easy.shop"),
    ("ascarus", "Ascarus"),
    ("amigos", "Amigos"),
]

# Google Alerts setup is fully operator-driven on Google's side; we
# just create the crawler_target and document the URL format.
_GOOGLE_ALERT_PLACEHOLDER = (
    "https://www.google.com/alerts/feeds/REPLACE_FEED_ID"
)


# ----------------------------------------------------------------------
# Result types
# ----------------------------------------------------------------------

StepStatus = Literal["configured", "needs_input", "skipped", "error"]


@dataclass
class StepResult:
    name: str
    status: StepStatus
    message: str
    operator_action: str | None = None  # human-readable next-step hint


@dataclass
class IntelSetupReport:
    organization_id: str
    steps: list[StepResult] = field(default_factory=list)

    @property
    def needs_input(self) -> list[StepResult]:
        return [s for s in self.steps if s.status == "needs_input"]

    @property
    def errors(self) -> list[StepResult]:
        return [s for s in self.steps if s.status == "error"]

    def to_dict(self) -> dict:
        return {
            "organization_id": self.organization_id,
            "steps": [
                {
                    "name": s.name,
                    "status": s.status,
                    "message": s.message,
                    "operator_action": s.operator_action,
                }
                for s in self.steps
            ],
            "needs_input_count": len(self.needs_input),
            "error_count": len(self.errors),
        }


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------

async def seed_org_intel(
    db: AsyncSession, org: Organization
) -> IntelSetupReport:
    """Run the full per-org intel scaffold. Idempotent + resilient.

    Caller is responsible for committing the transaction. We flush
    after each step so a later step's read sees the prior step's writes.
    """
    # Make sure the org's mapped attributes are populated and not in
    # an expired state. Any attribute access on an expired instance
    # under an AsyncSession triggers a sync ORM refresh, which fails
    # with MissingGreenlet. ``await db.refresh`` does the load via
    # the async dialect, so subsequent ``.settings`` / ``.keywords``
    # / etc. reads inside each step are safe.
    await db.refresh(org)

    org_id_str = str(org.id)
    report = IntelSetupReport(organization_id=org_id_str)

    for step_fn in (
        _step_confidence_threshold,
        _step_google_alerts_target,
        _step_mention_placeholder,
        _step_stealer_marketplace_placeholders,
        _step_vip_scaffold,
        _step_typosquat_immediate,
    ):
        try:
            result = await step_fn(db, org)
            report.steps.append(result)
            await db.flush()
        except Exception as exc:  # noqa: BLE001 — never wedge onboarding
            logger.exception(
                "[intel_setup] step %s failed for org %s",
                step_fn.__name__, org_id_str,
            )
            # A failed step may have left the session in a half-committed
            # state. Roll back so subsequent steps get a clean session.
            try:
                await db.rollback()
            except Exception:  # noqa: BLE001
                pass
            report.steps.append(
                StepResult(
                    name=step_fn.__name__.removeprefix("_step_"),
                    status="error",
                    message=f"Setup step failed: {exc}",
                    operator_action=(
                        "Re-run onboarding from Settings → Services, "
                        "or contact support if the error persists."
                    ),
                )
            )

    return report


# ----------------------------------------------------------------------
# Step 1 — Confidence threshold (NEEDS_REVIEW gate)
# ----------------------------------------------------------------------

async def _step_confidence_threshold(
    db: AsyncSession, org: Organization
) -> StepResult:
    """Set a sensible default ``confidence_threshold`` on the org.

    Borderline LLM triage results become NEEDS_REVIEW alerts (human
    gate) instead of being either auto-promoted or silently dropped.
    Idempotent: only writes if the operator hasn't customised the
    threshold — we never overwrite an explicit setting.
    """
    settings = dict(org.settings or {})
    if "confidence_threshold" in settings:
        return StepResult(
            name="confidence_threshold",
            status="configured",
            message=(
                f"Threshold already set to "
                f"{settings['confidence_threshold']}. Lower values let more "
                f"borderline LLM matches through as NEW; higher values "
                f"route them to NEEDS_REVIEW for analyst approval."
            ),
        )

    settings["confidence_threshold"] = DEFAULT_CONFIDENCE_THRESHOLD
    org.settings = settings
    return StepResult(
        name="confidence_threshold",
        status="configured",
        message=(
            f"Set confidence_threshold to {DEFAULT_CONFIDENCE_THRESHOLD}. "
            f"Triage matches below this score will be flagged as "
            f"NEEDS_REVIEW for analyst approval instead of auto-promoted "
            f"to NEW alerts."
        ),
        operator_action=(
            "Tune via Settings → Profile if you want stricter "
            "(more review) or looser (fewer reviews) gating."
        ),
    )


# ----------------------------------------------------------------------
# Step 2 — Google Alerts custom_http target
# ----------------------------------------------------------------------

async def _step_google_alerts_target(
    db: AsyncSession, org: Organization
) -> StepResult:
    """Create a disabled custom_http target for Google Alerts.

    The operator must:
      1. Sign in to Google → https://www.google.com/alerts
      2. Create alerts for each brand keyword (e.g. "Emirates NBD",
         "ENBD", "emiratesnbd.com").
      3. Set "Deliver to" → "RSS feed".
      4. Copy the feed URL and paste it into the target's URL field
         in /crawlers (Custom HTTP / RSS / JSON kind).
      5. Toggle the target active.

    We seed one placeholder per configured keyword so the operator
    has a row to fill in.
    """
    keywords = list(org.keywords or [])
    if not keywords:
        return StepResult(
            name="google_alerts",
            status="needs_input",
            message="No brand keywords configured — can't seed Google Alerts targets.",
            operator_action=(
                "Add brand keywords on the org first (Settings → Profile), "
                "then re-run onboarding."
            ),
        )

    created = 0
    skipped = 0
    for kw in keywords:
        identifier = f"google-alerts-{_slugify(kw)}"
        existing = await db.execute(
            select(CrawlerTarget).where(
                CrawlerTarget.kind == CrawlerKind.CUSTOM_HTTP.value,
                CrawlerTarget.identifier == identifier,
                CrawlerTarget.organization_id == org.id,
            )
        )
        if existing.scalars().first():
            skipped += 1
            continue
        db.add(
            CrawlerTarget(
                organization_id=org.id,
                kind=CrawlerKind.CUSTOM_HTTP.value,
                identifier=identifier,
                display_name=f"Google Alerts — {kw}",
                config={
                    "url": _GOOGLE_ALERT_PLACEHOLDER,
                    "parser": "rss",
                    "max_items": 50,
                    "_setup_hint": (
                        f"Replace url with the RSS feed URL of your "
                        f"Google Alert for '{kw}'. See "
                        f"https://www.google.com/alerts → Edit alert → "
                        f"Deliver to: RSS feed."
                    ),
                },
                is_active=False,  # operator must enable after pasting URL
            )
        )
        created += 1

    if created == 0:
        return StepResult(
            name="google_alerts",
            status="configured",
            message=f"Google Alerts targets already seeded for {skipped} keyword(s).",
        )
    return StepResult(
        name="google_alerts",
        status="needs_input",
        message=(
            f"Created {created} Google Alerts placeholder target(s) "
            f"({skipped} already existed)."
        ),
        operator_action=(
            "Sign in at https://www.google.com/alerts, create one alert "
            "per brand keyword with 'Deliver to: RSS feed', and paste "
            "each feed URL into the matching placeholder under "
            "/crawlers → Custom HTTP / RSS / JSON. Then toggle the "
            "target active."
        ),
    )


# ----------------------------------------------------------------------
# Step 3 — Mention.com placeholder
# ----------------------------------------------------------------------

async def _step_mention_placeholder(
    db: AsyncSession, org: Organization
) -> StepResult:
    """Mention.com brand-search integration.

    Mention.com is a paid SaaS brand-monitoring service. We add it to
    the global Service Inventory (see ``src/core/service_inventory.py``)
    as a Needs-Key row; the integration only activates when an admin
    pastes a Mention API key into Settings → Services. No per-org row
    needed here — the integration is shared across all orgs and the
    worker filters Mention's response by each org's keywords.
    """
    return StepResult(
        name="mention",
        status="needs_input",
        message=(
            "Mention.com integration is registered in Service Inventory "
            "but inactive until an API key is configured."
        ),
        operator_action=(
            "Optional: paid SaaS brand monitoring. Sign up at "
            "https://mention.com, copy your API key from "
            "Settings → API access, then paste it into "
            "/settings?tab=services → Mention → Configure. "
            "Free Google Alerts (above) is the no-cost equivalent."
        ),
    )


# ----------------------------------------------------------------------
# Step 4 — Stealer marketplace placeholders
# ----------------------------------------------------------------------

async def _step_stealer_marketplace_placeholders(
    db: AsyncSession, org: Organization
) -> StepResult:
    """Seed disabled stealer-marketplace crawler_targets.

    We DON'T ship live onion URLs because:
    * They rotate weekly and shipping stale ones wastes crawl budget.
    * Operators have different legal authority to scrape these.

    We seed one disabled row per known marketplace slug. The operator
    enables, fills in the current onion URL, and the existing
    stealer-log crawler picks it up automatically.
    """
    created = 0
    skipped = 0
    for slug, display_name in _STEALER_MARKETPLACES_CATALOG:
        existing = await db.execute(
            select(CrawlerTarget).where(
                CrawlerTarget.kind == CrawlerKind.STEALER_MARKETPLACE.value,
                CrawlerTarget.identifier == slug,
                CrawlerTarget.organization_id == org.id,
            )
        )
        if existing.scalars().first():
            skipped += 1
            continue
        db.add(
            CrawlerTarget(
                organization_id=org.id,
                kind=CrawlerKind.STEALER_MARKETPLACE.value,
                identifier=slug,
                display_name=display_name,
                config={
                    "onion_urls": [],
                    "max_pages": 3,
                    "_setup_hint": (
                        "Paste current onion URL(s) for this marketplace "
                        "into onion_urls before enabling. Verify operator "
                        "has authority to scrape."
                    ),
                },
                is_active=False,
            )
        )
        created += 1

    if created == 0:
        return StepResult(
            name="stealer_marketplaces",
            status="configured",
            message=f"Placeholders already seeded ({skipped} entries).",
        )
    return StepResult(
        name="stealer_marketplaces",
        status="needs_input",
        message=(
            f"Created {created} disabled stealer-marketplace placeholder(s)."
        ),
        operator_action=(
            "Optional: Open /crawlers → Stealer-log marketplace. For each "
            "marketplace you have authority to scrape, paste the current "
            "onion URL into 'onion_urls' and toggle the target active. "
            "Then matches against your VIP email permutations will surface "
            "as alerts."
        ),
    )


# ----------------------------------------------------------------------
# Step 5 — VIP scaffolding
# ----------------------------------------------------------------------

async def _step_vip_scaffold(
    db: AsyncSession, org: Organization
) -> StepResult:
    """Ensure the org has at least one VIP placeholder visible.

    We don't auto-populate VIPs because:
    * We can't legally / ethically scrape exec names without consent.
    * Auto-populated names would be wrong for many orgs and confuse the
      operator about what's real vs. seeded.

    Behaviour:
    * If the org has zero VIPs → we don't create placeholder rows
      (empty rows just clutter the table). Instead we report
      ``needs_input`` so the onboarding done-page can prompt the
      operator with a clear CTA.
    * If the org already has VIPs → we mark this step ``configured``.
    """
    vip_count = await db.execute(
        select(VIPTarget).where(VIPTarget.organization_id == org.id)
    )
    vips = vip_count.scalars().all()
    if vips:
        return StepResult(
            name="vips",
            status="configured",
            message=(
                f"{len(vips)} VIP target(s) configured. Triage prompt "
                f"now expands their names into email + username "
                f"permutations automatically."
            ),
        )
    return StepResult(
        name="vips",
        status="needs_input",
        message="No VIP targets configured.",
        operator_action=(
            "Add executives, board members, and other high-value targets "
            "via /admin → VIPs. For each, enter name, title, and any "
            "known emails/usernames. Argus will auto-expand names into "
            "common email patterns (j.smith@, jsmith@, etc.) at triage "
            "time so leaked credentials and impersonation attempts get "
            "detected even when the literal email isn't on the list."
        ),
    )


# ----------------------------------------------------------------------
# Step 6 — Immediate typosquat scan
# ----------------------------------------------------------------------

async def _step_typosquat_immediate(
    db: AsyncSession, org: Organization
) -> StepResult:
    """Kick off an immediate typosquat scan against the org's domains.

    Uses the existing ``src.brand.scanner.scan_organization`` which
    generates lookalike permutations via ``src.brand.permutations`` and
    resolves each candidate. The result populates ``suspect_domains``
    rows which the brand-protection dashboard renders.

    The recurring daily scan is registered separately in the worker
    cron (``src/workers/runner.py``) — this step just kicks off the
    one-time first scan so operators see results within minutes
    instead of waiting 24h for the first cron tick.

    We import the scanner lazily because it pulls in DNS-resolution
    deps that aren't always present in the org-create code path.
    """
    domains = list(org.domains or [])
    if not domains:
        return StepResult(
            name="typosquat",
            status="needs_input",
            message="No domains configured — typosquat scan needs at least one.",
            operator_action=(
                "Add primary domains to the org (Settings → Profile or "
                "Settings → Domains) and re-run onboarding."
            ),
        )

    try:
        from src.brand.scanner import scan_organization
    except ImportError as exc:
        return StepResult(
            name="typosquat",
            status="error",
            message=f"Brand scanner module unavailable: {exc}",
            operator_action=(
                "Check that ``src/brand/scanner.py`` is importable in "
                "this deployment."
            ),
        )

    try:
        report = await scan_organization(db, organization_id=org.id)
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "[intel_setup] typosquat scan failed for org %s", org.id
        )
        return StepResult(
            name="typosquat",
            status="error",
            message=f"Typosquat scan errored: {exc}",
            operator_action=(
                "Will retry on the daily cron. Check logs for the "
                "specific failure (DNS resolver, rate limit, etc.)."
            ),
        )

    suspects = getattr(report, "suspect_count", None) or getattr(
        report, "candidates_resolved", 0
    )
    return StepResult(
        name="typosquat",
        status="configured",
        message=(
            f"Initial typosquat scan complete across {len(domains)} "
            f"domain(s). {suspects} candidate domain(s) flagged."
        ),
        operator_action=(
            "Review flagged lookalikes in /brand. The daily cron will "
            "keep this fresh."
        ),
    )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _slugify(s: str) -> str:
    """Lowercase + collapse non-alphanumerics to single hyphens."""
    import re
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "IntelSetupReport",
    "StepResult",
    "seed_org_intel",
]
