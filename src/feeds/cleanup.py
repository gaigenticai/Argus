"""Feed cleanup — prune expired threat-feed entries from the database."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.feeds import ThreatFeedEntry

logger = logging.getLogger(__name__)


async def cleanup_expired_entries(db: AsyncSession) -> int:
    """Delete ``ThreatFeedEntry`` rows whose ``expires_at`` has passed.

    Args:
        db: An active async database session (caller owns the lifecycle).

    Returns:
        Number of rows deleted.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(
        delete(ThreatFeedEntry).where(ThreatFeedEntry.expires_at < now)
    )
    count: int = result.rowcount  # type: ignore[assignment]
    if count > 0:
        await db.commit()
        logger.info("[feed-cleanup] Deleted %d expired entries", count)
    return count
