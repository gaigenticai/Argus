"""Raw-ingest webhook — operator-supplied scrapers post findings here.

Why this endpoint exists
------------------------
The custom_http crawler covers RSS / JSON / HTML-CSS sources that
Argus polls itself. Some operators have a fully custom scraper
already running — in n8n, an AWS Lambda, a cron job — and want
those findings to flow into Argus without writing a new crawler
class. ``POST /api/v1/ingest/raw`` is that path.

Each posted item becomes a ``ThreatFeedEntry`` row exactly the way
the built-in crawlers' results do, then the existing IOC pipeline
+ AI Triage Agent consume them downstream — no special path.

Auth: API key via ``X-Argus-Api-Key`` header (operator-provisioned
in Settings → API Keys). The key's owning user becomes the audit
trail attribution.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.models.feeds import ThreatFeedEntry
from src.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["Threat Intelligence"])


_VALID_TYPES = {
    "ip", "ipv4", "ipv6", "domain", "url", "hash", "md5", "sha1",
    "sha256", "cve", "ja3", "email", "victim", "status",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class RawIngestItem(BaseModel):
    """One indicator from an operator's external scraper."""

    type: str = Field(..., description="Indicator type — see allowed list in /ingest/raw docstring")
    value: str = Field(..., min_length=1, max_length=2048)
    source: str = Field(..., min_length=1, max_length=100,
                        description="Short name of the scraper (becomes feed_name)")
    layer: str = Field("custom_http",
                       description="Threat layer — defaults to custom_http")
    label: str | None = None
    description: str | None = None
    severity: str = Field("medium")
    confidence: float = Field(0.7, ge=0.0, le=1.0)
    country_code: str | None = None
    asn: str | None = None
    feed_metadata: dict[str, Any] | None = None
    expires_hours: int | None = Field(720, ge=1, le=8760,
                                       description="TTL on the threat feed entry; default 30 days")


class RawIngestRequest(BaseModel):
    items: list[RawIngestItem] = Field(..., min_length=1, max_length=500,
                                        description="Up to 500 items per call.")


class RawIngestResponse(BaseModel):
    accepted: int
    skipped: int
    skipped_reasons: dict[str, int]


@router.post("/raw", response_model=RawIngestResponse, status_code=202)
async def ingest_raw(
    body: RawIngestRequest,
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> RawIngestResponse:
    """Accept a batch of indicators from an external scraper.

    Idempotent on (feed_name, value): re-posting the same indicator
    just bumps ``last_seen``. Items with unknown types or severities
    are skipped and counted in the response so the caller can fix
    its payload without retry storms.
    """
    now = datetime.now(timezone.utc)
    accepted = 0
    skipped_reasons: dict[str, int] = {}

    def _bump(reason: str) -> None:
        skipped_reasons[reason] = skipped_reasons.get(reason, 0) + 1

    for raw in body.items:
        entry_type = raw.type.lower().strip()
        if entry_type not in _VALID_TYPES:
            _bump(f"unknown_type:{entry_type}")
            continue
        severity = raw.severity.lower().strip()
        if severity not in _VALID_SEVERITIES:
            _bump(f"unknown_severity:{severity}")
            continue

        expires_at = now + timedelta(hours=raw.expires_hours or 720)
        # Upsert keyed on (feed_name, value, entry_type) — any
        # re-post bumps last_seen + severity if higher.
        stmt = pg_insert(ThreatFeedEntry).values(
            id=uuid.uuid4(),
            created_at=now,
            updated_at=now,
            feed_name=raw.source.strip(),
            layer=raw.layer.strip() or "custom_http",
            entry_type=entry_type,
            value=raw.value.strip(),
            label=raw.label,
            description=raw.description,
            severity=severity,
            confidence=raw.confidence,
            country_code=(raw.country_code or None),
            asn=(raw.asn or None),
            feed_metadata={
                **(raw.feed_metadata or {}),
                "ingested_via": "raw_webhook",
                "ingested_by": user.email,
            },
            first_seen=now,
            last_seen=now,
            expires_at=expires_at,
        ).on_conflict_do_update(
            constraint="uq_feed_name_value",
            set_={
                "last_seen": now,
                "updated_at": now,
                "expires_at": expires_at,
            },
        )
        try:
            await db.execute(stmt)
            accepted += 1
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "[ingest/raw] %s/%s failed: %s",
                raw.source, raw.value[:60], exc,
            )
            _bump("db_error")

    if accepted > 0:
        await db.commit()

    return RawIngestResponse(
        accepted=accepted,
        skipped=sum(skipped_reasons.values()),
        skipped_reasons=skipped_reasons,
    )
