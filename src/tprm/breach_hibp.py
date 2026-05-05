"""HIBP-based vendor breach signal.

Walks a small set of probable vendor email addresses on the vendor's
primary domain (admin@, security@, support@, info@, contact@,
abuse@, sales@, hr@, billing@) and asks HIBP whether any are in known
breaches. Free for low volume — HIBP enforces 1 req / 1.5s; we sleep
between calls to stay polite even if rate-limit headers go unread.

Returns:

    score (0..100, lower = more breached) + evidence dict containing
    ``probed_emails``, ``hits`` (list of `{email, breach_count, latest}`),
    ``classes_seen`` (set of data classes leaked across hits).

When HIBP is unconfigured, the helper returns ``score=70`` (neutral)
plus an explanation so the scorecard records *why* the signal is
unavailable.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.integrations.breach.hibp import HibpProvider

_logger = logging.getLogger(__name__)


_VENDOR_EMAIL_LOCALPARTS = (
    "admin",
    "security",
    "support",
    "info",
    "contact",
    "abuse",
    "sales",
    "hr",
    "billing",
    "ciso",
)


async def assess_vendor_breach(domain: str) -> tuple[float, dict[str, Any]]:
    if not domain:
        return 70.0, {"reason": "no primary_domain"}
    domain = domain.strip().lower()
    provider = HibpProvider()
    if not provider.is_configured():
        return 70.0, {
            "reason": "HIBP not configured",
            "domain": domain,
            "guidance": "Set ARGUS_HIBP_API_KEY (or rotate the key in Settings) to enable.",
        }

    probed_emails = [f"{lp}@{domain}" for lp in _VENDOR_EMAIL_LOCALPARTS]
    breach_total = 0
    classes_seen: set[str] = set()
    hits_summary: list[dict[str, Any]] = []
    rate_limited = False

    for email in probed_emails:
        try:
            res = await provider.search_email(email)
        except Exception as e:  # noqa: BLE001
            _logger.warning("hibp lookup failed for %s: %s", email, e)
            continue
        if not res.success:
            if res.error and "rate" in res.error.lower():
                rate_limited = True
                break
            continue
        if res.hits:
            for h in res.hits:
                breach_total += 1
                for c in h.data_classes:
                    classes_seen.add(c)
            latest = max(
                (h.breach_date for h in res.hits if h.breach_date),
                default=None,
            )
            hits_summary.append(
                {
                    "email": email,
                    "breach_count": len(res.hits),
                    "latest": latest,
                    "names": [h.breach_name for h in res.hits[:5]],
                }
            )
        await asyncio.sleep(1.6)  # polite pacing

    # Composite: subtract per-breach penalty + extra weight for sensitive
    # data classes.
    sensitive = {"Passwords", "Email addresses", "Credit cards", "Phone numbers"}
    sensitive_hit = bool(classes_seen & sensitive)
    score = max(
        0.0,
        100.0 - breach_total * 8.0 - (15.0 if sensitive_hit else 0.0),
    )
    return float(score), {
        "domain": domain,
        "probed": probed_emails,
        "hits": hits_summary,
        "classes_seen": sorted(classes_seen),
        "sensitive_hit": sensitive_hit,
        "rate_limited": rate_limited,
        "score": score,
    }


__all__ = ["assess_vendor_breach"]
