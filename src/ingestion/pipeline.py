"""Ingestion pipeline — connects crawlers → storage → triage agents."""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.triage_agent import TriageAgent
from src.crawlers.base import BaseCrawler, CrawlResult
from src.models.threat import (
    Alert,
    AlertStatus,
    Organization,
    RawIntel,
    VIPTarget,
)

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """Orchestrates: crawl → deduplicate → store → triage → alert."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.triage = TriageAgent()

    async def ingest_from_crawler(self, crawler: BaseCrawler) -> int:
        """Run a crawler and process all results. Returns number of new alerts."""
        alert_count = 0

        async with crawler:
            async for result in crawler.crawl():
                try:
                    raw_intel = await self._store_raw(result)
                    if raw_intel is None:
                        continue  # duplicate

                    alerts = await self._triage_against_all_orgs(raw_intel, result)
                    alert_count += len(alerts)

                except Exception as e:
                    logger.error(f"[pipeline] Error processing result from {crawler.name}: {e}")

        return alert_count

    async def _store_raw(self, result: CrawlResult) -> RawIntel | None:
        """Store raw intel, returns None if duplicate."""
        existing = await self.db.execute(
            select(RawIntel).where(RawIntel.content_hash == result.content_hash)
        )
        if existing.scalar_one_or_none():
            return None

        raw = RawIntel(
            source_type=result.source_type.value,
            source_url=result.source_url,
            source_name=result.source_name,
            title=result.title,
            content=result.content,
            author=result.author,
            published_at=result.published_at,
            raw_data=result.raw_data,
            content_hash=result.content_hash,
        )
        self.db.add(raw)
        await self.db.flush()
        return raw

    async def _triage_against_all_orgs(
        self, raw: RawIntel, result: CrawlResult
    ) -> list[Alert]:
        """Run triage against every monitored organization."""
        orgs = await self.db.execute(select(Organization))
        organizations = orgs.scalars().all()

        alerts = []
        for org in organizations:
            org_profile = await self._build_org_profile(org)
            triage_result = await self.triage.analyze(
                raw_content=raw.content,
                source_type=raw.source_type,
                source_name=raw.source_name or "",
                org_profile=org_profile,
            )

            if triage_result:
                alert = Alert(
                    organization_id=org.id,
                    raw_intel_id=raw.id,
                    category=triage_result["category"],
                    severity=triage_result["severity"],
                    status=AlertStatus.NEW.value,
                    title=triage_result.get("title", "Untitled Alert"),
                    summary=triage_result.get("summary", ""),
                    details=triage_result,
                    matched_entities=triage_result.get("matched_entities"),
                    confidence=triage_result.get("confidence", 0.5),
                    agent_reasoning=triage_result.get("reasoning"),
                    recommended_actions=triage_result.get("recommended_actions"),
                )
                self.db.add(alert)
                alerts.append(alert)
                logger.info(
                    f"[pipeline] Alert: {alert.severity} {alert.category} for {org.name} — {alert.title}"
                )

        if alerts:
            await self.db.flush()

        raw.is_processed = True
        await self.db.commit()

        return alerts

    async def _build_org_profile(self, org: Organization) -> dict:
        """Build org profile dict for triage agent."""
        vips_result = await self.db.execute(
            select(VIPTarget).where(VIPTarget.organization_id == org.id)
        )
        vips = vips_result.scalars().all()

        return {
            "name": org.name,
            "domains": org.domains or [],
            "keywords": org.keywords or [],
            "industry": org.industry,
            "tech_stack": org.tech_stack or {},
            "vips": [
                {
                    "name": v.name,
                    "title": v.title,
                    "emails": v.emails or [],
                    "usernames": v.usernames or [],
                }
                for v in vips
            ],
        }
