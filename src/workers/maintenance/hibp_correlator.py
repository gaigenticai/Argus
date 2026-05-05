"""HIBP breach-correlator for recent leakage findings.

Walks DlpFinding + CardLeakageFinding rows from the last 7 days that
haven't been correlated yet, extracts emails from their excerpts, and
asks HIBP whether each email appears in any historical breach. Hits
are persisted to ``finding.breach_correlations``::

    {
        "emails": {"alice@bank.com": ["LinkedIn 2012", "Adobe 2013"]},
        "checked_at": "...",
    }

Per-tick caps:
  * 200 unique email lookups (HIBP Enterprise's 1.5 req/sec rate limit
    means a 200-email tick takes ~135s before retries).
  * Inter-request sleep of 0.7s to stay safely under the published
    rate limit.

If HIBP isn't configured we record an ``unconfigured`` FeedHealth row
and exit — no point churning the worker loop without an API key.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.integrations.breach.hibp import HibpProvider
from src.models.leakage import CardLeakageFinding, DlpFinding

logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.hibp_correlator"

_LOOKUP_CAP_PER_TICK = 200
_INTER_CALL_SLEEP = 0.7  # HIBP Enterprise: 1.5 rps; we stay just under
_WINDOW_DAYS = 7

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _emails_from_dlp(finding: DlpFinding) -> list[str]:
    blob = "\n".join(finding.matched_excerpts or [])
    return list({m.group(0).lower() for m in _EMAIL_RE.finditer(blob)})


def _emails_from_card(finding: CardLeakageFinding) -> list[str]:
    blob = finding.excerpt or ""
    return list({m.group(0).lower() for m in _EMAIL_RE.finditer(blob)})


async def correlate_pending(db: AsyncSession) -> None:
    """One iteration of the HIBP correlator.

    * Loads recent DlpFinding + CardLeakageFinding rows lacking
      ``breach_correlations``.
    * Builds a unique email set, capped to ``_LOOKUP_CAP_PER_TICK``.
    * Queries HIBP for each, sleeping ``_INTER_CALL_SLEEP`` seconds
      between calls.
    * Writes ``breach_correlations = {"emails": {...}, ...}`` for each
      finding using only the emails present in that finding's text.
    * Records a single FeedHealth row.
    """
    started = time.monotonic()

    provider = HibpProvider()
    if not provider.is_configured():
        await feed_health.mark_unconfigured(
            db,
            feed_name=FEED_NAME,
            detail="HIBP API key (ARGUS_HIBP_API_KEY) is not configured",
        )
        await db.commit()
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=_WINDOW_DAYS)
    dlp_rows = (
        await db.execute(
            select(DlpFinding).where(
                and_(
                    DlpFinding.detected_at >= cutoff,
                    DlpFinding.breach_correlations.is_(None),
                )
            ).order_by(DlpFinding.detected_at.desc()).limit(500)
        )
    ).scalars().all()
    card_rows = (
        await db.execute(
            select(CardLeakageFinding).where(
                and_(
                    CardLeakageFinding.detected_at >= cutoff,
                    CardLeakageFinding.breach_correlations.is_(None),
                )
            ).order_by(CardLeakageFinding.detected_at.desc()).limit(500)
        )
    ).scalars().all()

    # Build per-finding email lists once, then collect the global unique
    # set so we look each address up at most once per tick.
    dlp_emails: dict = {f: _emails_from_dlp(f) for f in dlp_rows}
    card_emails: dict = {f: _emails_from_card(f) for f in card_rows}

    unique_emails: list[str] = []
    seen: set[str] = set()
    for emails in list(dlp_emails.values()) + list(card_emails.values()):
        for e in emails:
            if e in seen:
                continue
            seen.add(e)
            unique_emails.append(e)
            if len(unique_emails) >= _LOOKUP_CAP_PER_TICK:
                break
        if len(unique_emails) >= _LOOKUP_CAP_PER_TICK:
            break

    if not unique_emails:
        # Nothing to correlate; still record the run.
        await feed_health.mark_ok(
            db,
            feed_name=FEED_NAME,
            rows_ingested=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=(
                f"window={_WINDOW_DAYS}d; "
                f"dlp_pending={len(dlp_rows)}; card_pending={len(card_rows)}; "
                "no email candidates extracted"
            ),
        )
        # Mark every pending finding with an empty correlation envelope so
        # the next tick doesn't re-scan rows that simply have no emails.
        now_iso = datetime.now(timezone.utc).isoformat()
        for f in dlp_rows:
            f.breach_correlations = {"emails": {}, "checked_at": now_iso, "reason": "no_email"}
        for f in card_rows:
            f.breach_correlations = {"emails": {}, "checked_at": now_iso, "reason": "no_email"}
        await db.commit()
        return

    # Step 2: query HIBP for each unique email.
    email_to_breaches: dict[str, list[str]] = {}
    errors = 0
    for email in unique_emails:
        try:
            result = await provider.search_email(email)
        except Exception as exc:  # noqa: BLE001
            logger.warning("hibp lookup for %s crashed: %s", email, exc)
            errors += 1
            await asyncio.sleep(_INTER_CALL_SLEEP)
            continue
        if not result.success:
            errors += 1
        breaches = sorted({h.breach_name for h in (result.hits or []) if h.breach_name})
        email_to_breaches[email] = breaches
        await asyncio.sleep(_INTER_CALL_SLEEP)

    # Step 3: write per-finding correlations using only that finding's
    # email set. Keep finding-local detail; aggregate stays elsewhere.
    now_iso = datetime.now(timezone.utc).isoformat()
    persisted = 0
    for finding, emails in dlp_emails.items():
        if not emails:
            finding.breach_correlations = {
                "emails": {},
                "checked_at": now_iso,
                "reason": "no_email",
            }
            persisted += 1
            continue
        per = {e: email_to_breaches.get(e, []) for e in emails if e in email_to_breaches}
        if not per:
            # Finding's emails fell outside the per-tick cap; skip — next
            # tick will pick this finding up again.
            continue
        finding.breach_correlations = {
            "emails": per,
            "checked_at": now_iso,
        }
        persisted += 1
    for finding, emails in card_emails.items():
        if not emails:
            finding.breach_correlations = {
                "emails": {},
                "checked_at": now_iso,
                "reason": "no_email",
            }
            persisted += 1
            continue
        per = {e: email_to_breaches.get(e, []) for e in emails if e in email_to_breaches}
        if not per:
            continue
        finding.breach_correlations = {
            "emails": per,
            "checked_at": now_iso,
        }
        persisted += 1

    detail = (
        f"window={_WINDOW_DAYS}d; emails_checked={len(unique_emails)}; "
        f"hibp_errors={errors}; "
        f"findings_correlated={persisted}; "
        f"dlp_pending={len(dlp_rows)}; card_pending={len(card_rows)}"
    )
    await feed_health.mark_ok(
        db,
        feed_name=FEED_NAME,
        rows_ingested=persisted,
        duration_ms=int((time.monotonic() - started) * 1000),
        detail=detail,
    )
    await db.commit()
    logger.info("hibp_correlator: %s", detail)


__all__ = ["correlate_pending", "FEED_NAME"]
