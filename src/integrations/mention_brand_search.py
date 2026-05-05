"""Mention.com brand-search poller.

Polls Mention.com's API for brand mentions across web, news, blogs,
and social — matched against each Organization's configured ``keywords``
list — and ingests results into ``raw_intel`` so the existing triage /
alert pipeline can decide which ones become alerts.

This is a paid SaaS integration: it activates only when an admin sets
``integration.mention.api_key`` (DB-set via Settings → Services) or
``ARGUS_MENTION_API_KEY`` (env). Without a key the poller is a no-op
and the Service Inventory shows it as Needs-Key.

The free / no-API-key equivalent is per-org Google Alerts targets
seeded by ``src/onboarding/intel_setup.py::_step_google_alerts_target``;
operators who don't want a Mention.com subscription can rely on those.

Mention API reference: https://dev.mention.com/

Architecture notes
------------------
* One Mention "alert" object on Mention's side maps to one Argus brand
  keyword. We don't auto-create alerts on Mention (that requires a
  user-facing OAuth flow); operators set them up manually inside
  Mention's dashboard. We only poll the alerts they've already created.
* Each Mention "mention" row → one ``raw_intel`` row with
  ``source_type="brand_search"`` and ``source_name=f"mention/{alert_id}"``
  — that's the convention the triage pipeline expects.
* Idempotency: we dedupe via the existing content_hash mechanism in
  ``ingestion.pipeline._store_raw``. Re-polling the same window won't
  create duplicate raw_intel rows.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import integration_keys
from src.core.activity import ActivityType, emit as activity_emit
from src.models.threat import Organization, RawIntel

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------

MENTION_API_BASE = "https://api.mention.net/api"
MENTION_TIMEOUT_SECONDS = 30
MENTION_MAX_PER_ALERT = 50  # cap rows per poll to avoid runaway batches


async def poll_mention_for_org(
    db: AsyncSession, org: Organization
) -> dict[str, int]:
    """Pull recent Mention.com mentions for one org.

    Returns ``{"keywords_polled": N, "mentions_ingested": M, "duplicates": K}``.
    Caller is responsible for the ``await db.commit()``.

    No-ops cleanly when:
    * No Mention API key is configured (returns zeros).
    * Org has no ``keywords`` (Mention's API needs an alert id, which we
      assume the operator named after the keyword).
    * Mention's API is unreachable (logged, returns zeros — next tick
      will retry).
    """
    api_key = integration_keys.get(
        "mention", env_fallback="ARGUS_MENTION_API_KEY"
    )
    if not api_key:
        return {"keywords_polled": 0, "mentions_ingested": 0, "duplicates": 0}

    keywords = list(org.keywords or [])
    if not keywords:
        return {"keywords_polled": 0, "mentions_ingested": 0, "duplicates": 0}

    await activity_emit(
        ActivityType.SYSTEM,
        "mention",
        f"Polling Mention.com for {org.name} ({len(keywords)} keyword(s))",
        {"org": org.name, "keywords": keywords},
    )

    # Mention's API requires an account_id + alert_id pair. We discover
    # them once per call by listing the user's account + alerts and
    # mapping each Argus keyword to the alert whose ``query.included_keywords``
    # contains it. Operators name their Mention alerts after the brand.
    async with httpx.AsyncClient(timeout=MENTION_TIMEOUT_SECONDS) as client:
        try:
            account_id = await _resolve_account_id(client, api_key)
            alerts_by_keyword = await _list_alerts_by_keyword(
                client, api_key, account_id
            )
        except _MentionAuthError:
            logger.warning(
                "[mention] auth rejected — operator should rotate the key "
                "in Settings → Services → Mention.com.",
            )
            return {"keywords_polled": 0, "mentions_ingested": 0, "duplicates": 0}
        except Exception:  # noqa: BLE001 — never wedge ingestion
            logger.exception("[mention] discovery call failed")
            return {"keywords_polled": 0, "mentions_ingested": 0, "duplicates": 0}

        ingested = 0
        duplicates = 0
        polled = 0
        for kw in keywords:
            alert_id = alerts_by_keyword.get(kw.lower())
            if not alert_id:
                # The operator hasn't created a Mention alert for this
                # brand keyword. Not an error — they may only care about
                # one of several keywords.
                continue
            polled += 1
            try:
                rows = await _fetch_mentions(
                    client, api_key, account_id, alert_id
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "[mention] fetch failed for keyword=%r alert=%s",
                    kw, alert_id,
                )
                continue

            for row in rows[:MENTION_MAX_PER_ALERT]:
                stored = await _store_mention_as_raw_intel(
                    db, org_id=org.id, keyword=kw, alert_id=alert_id, row=row,
                )
                if stored:
                    ingested += 1
                else:
                    duplicates += 1

        return {
            "keywords_polled": polled,
            "mentions_ingested": ingested,
            "duplicates": duplicates,
        }


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------

class _MentionAuthError(Exception):
    """Raised when Mention's API rejects the key (401/403)."""


async def _resolve_account_id(
    client: httpx.AsyncClient, api_key: str
) -> str:
    """Fetch the caller's Mention account_id.

    Mention's REST is structured as ``/accounts/{account_id}/alerts/...``
    and the auth principal can list its own accounts at ``/accounts/me``.
    """
    r = await client.get(
        f"{MENTION_API_BASE}/accounts/me",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    if r.status_code in (401, 403):
        raise _MentionAuthError("Mention API rejected the credentials")
    r.raise_for_status()
    body = r.json()
    accounts = body.get("accounts") or []
    if not accounts:
        raise RuntimeError("Mention API returned no accounts for this key")
    # Operators with multiple accounts can pin a specific one via
    # ARGUS_MENTION_ACCOUNT_ID — falls back to the first account.
    import os
    pinned = os.environ.get("ARGUS_MENTION_ACCOUNT_ID")
    if pinned:
        for a in accounts:
            if str(a.get("id")) == pinned:
                return pinned
    return str(accounts[0]["id"])


async def _list_alerts_by_keyword(
    client: httpx.AsyncClient, api_key: str, account_id: str
) -> dict[str, str]:
    """Map ``keyword.lower() -> alert_id`` for every alert on the account.

    Operators name their Mention alerts after the brand (e.g.
    ``"Emirates NBD"``); we match by name. This avoids needing a
    secondary mapping config in the org's settings.
    """
    r = await client.get(
        f"{MENTION_API_BASE}/accounts/{account_id}/alerts",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    r.raise_for_status()
    body = r.json()
    alerts = body.get("alerts") or []
    out: dict[str, str] = {}
    for a in alerts:
        name = (a.get("name") or "").strip().lower()
        if name and a.get("id"):
            out[name] = str(a["id"])
    return out


async def _fetch_mentions(
    client: httpx.AsyncClient,
    api_key: str,
    account_id: str,
    alert_id: str,
) -> list[dict[str, Any]]:
    """Pull recent mentions for one alert.

    Defaults to the most recent 100 (Mention's max per page). Operator
    can dial up by tweaking the URL params in code if needed; for the
    paid-SaaS path we don't expose that as an env var since the rate
    limits are tier-dependent.
    """
    r = await client.get(
        f"{MENTION_API_BASE}/accounts/{account_id}/alerts/{alert_id}/mentions",
        params={"limit": 100, "order": "desc"},
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    r.raise_for_status()
    body = r.json()
    return body.get("mentions") or []


async def _store_mention_as_raw_intel(
    db: AsyncSession,
    *,
    org_id,
    keyword: str,
    alert_id: str,
    row: dict[str, Any],
) -> bool:
    """Persist one Mention row as ``raw_intel``. Returns True on insert.

    Dedupes via content_hash — re-polling overlapping windows won't
    create duplicate rows.
    """
    title = (row.get("title") or "").strip()[:500]
    content = (
        row.get("description")
        or row.get("content_summary")
        or row.get("title")
        or ""
    ).strip()
    url = row.get("original_url") or row.get("url") or ""
    if not content:
        return False

    content_hash = hashlib.sha256(
        f"mention:{alert_id}:{url}:{content}".encode("utf-8")
    ).hexdigest()

    # Skip if we've stored the same hash before.
    existing = await db.execute(
        select(RawIntel).where(RawIntel.content_hash == content_hash).limit(1)
    )
    if existing.scalars().first() is not None:
        return False

    published = row.get("published_at") or row.get("created_at")
    try:
        published_dt = (
            datetime.fromisoformat(published.replace("Z", "+00:00"))
            if published else datetime.now(timezone.utc)
        )
    except Exception:  # noqa: BLE001
        published_dt = datetime.now(timezone.utc)

    raw = RawIntel(
        source_type="surface_web",  # SourceType.SURFACE_WEB — Mention scrapes the public web
        source_name=f"mention/{alert_id}",
        source_url=url,
        title=title or None,
        content=content,
        author=row.get("author_name"),
        published_at=published_dt,
        content_hash=content_hash,
        raw_data={
            "mention_id": row.get("id"),
            "keyword": keyword,
            "language": row.get("language"),
            "tone": row.get("tone"),
            "source_url": url,
            "via": "mention.com",
        },
    )
    db.add(raw)
    return True


__all__ = ["poll_mention_for_org"]
