"""Ingestion pipeline — connects crawlers → storage → triage agents → IOC extraction → actor tracking."""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.triage_agent import TriageAgent
from src.core.webhook_dispatcher import dispatch_alert
from src.crawlers.base import BaseCrawler, CrawlResult
from src.enrichment.ioc_extractor import extract_iocs, IOCTypeEnum
from src.enrichment.actor_tracker import create_or_update_actor
from src.models.intel import CrawlerSource, IOC, SourceHealthStatus
from src.models.threat import (
    Alert,
    AlertStatus,
    Organization,
    RawIntel,
    VIPTarget,
)

from src.core.activity import ActivityType, emit as activity_emit

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """Orchestrates: crawl → deduplicate → store → triage → alert."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.triage = TriageAgent(db=db_session)

    async def ingest_from_crawler(
        self, crawler: BaseCrawler, source_id: uuid.UUID | None = None
    ) -> int:
        """Run a crawler and process all results. Returns number of new alerts."""
        alert_count = 0
        result_count = 0
        crawl_success = False

        await activity_emit(
            ActivityType.CRAWLER_START,
            crawler.name,
            f"Starting {crawler.name} crawl",
            {"crawler": crawler.name, "source_type": crawler.source_type.value},
        )

        try:
            async with crawler:
                async for result in crawler.crawl():
                    result_count += 1
                    crawl_success = True
                    try:
                        await activity_emit(
                            ActivityType.CRAWLER_RESULT,
                            crawler.name,
                            f"Processing: {result.title or result.content[:80]}",
                            {"title": result.title, "source": result.source_name, "hash": result.content_hash[:12]},
                        )

                        raw_intel = await self._store_raw(result)
                        if raw_intel is None:
                            await activity_emit(
                                ActivityType.PIPELINE_DUPLICATE,
                                "pipeline",
                                f"Duplicate skipped: {result.title or result.content[:60]}",
                                {"hash": result.content_hash[:12]},
                            )
                            continue

                        await activity_emit(
                            ActivityType.PIPELINE_STORE,
                            "pipeline",
                            f"Stored raw intel #{raw_intel.id}: {result.title or 'untitled'}",
                            {"raw_intel_id": str(raw_intel.id), "source": result.source_name},
                        )

                        alerts = await self._triage_against_all_orgs(raw_intel, result)
                        alert_count += len(alerts)

                        for alert in alerts:
                            await activity_emit(
                                ActivityType.PIPELINE_ALERT,
                                "pipeline",
                                f"Alert created: [{alert.severity.upper()}] {alert.title}",
                                {
                                    "alert_id": str(alert.id),
                                    "severity": alert.severity,
                                    "category": alert.category,
                                    "org_id": str(alert.organization_id),
                                },
                                severity="warning" if alert.severity in ("critical", "high") else "info",
                            )

                        # --- IOC extraction ---
                        first_alert_id = alerts[0].id if alerts else None
                        await self._extract_and_store_iocs(
                            raw_intel, first_alert_id, result,
                        )

                        # --- Actor tracking ---
                        if result.author:
                            platform = result.source_type.value if result.source_type else (result.source_name or "unknown")
                            await create_or_update_actor(
                                username=result.author,
                                platform=platform,
                                raw_intel_id=raw_intel.id,
                                alert_id=first_alert_id,
                                db=self.db,
                            )

                        await self.db.commit()

                    except Exception as e:
                        logger.error(f"[pipeline] Error processing result from {crawler.name}: {e}")
                        await activity_emit(
                            ActivityType.CRAWLER_ERROR,
                            crawler.name,
                            f"Pipeline error: {e}",
                            {"error": str(e)},
                            severity="error",
                        )
                        await self.db.rollback()
        except Exception as e:
            logger.error(f"[pipeline] Crawler {crawler.name} failed: {e}")
            crawl_success = False

        # Update source health if source_id was provided
        if source_id is not None:
            await self._update_source_health(
                source_id=source_id,
                success=crawl_success,
                items_collected=result_count,
            )
            await self.db.commit()

        await activity_emit(
            ActivityType.CRAWLER_COMPLETE,
            crawler.name,
            f"{crawler.name} finished — {result_count} results, {alert_count} alerts",
            {"results": result_count, "alerts": alert_count},
        )

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
                # Determine alert status based on confidence threshold
                confidence = triage_result.get("confidence", 0.5)
                org_settings = org.settings or {}
                confidence_threshold = float(org_settings.get("confidence_threshold", 0.0))

                if confidence_threshold > 0 and confidence < confidence_threshold:
                    status = AlertStatus.NEEDS_REVIEW.value
                else:
                    status = AlertStatus.NEW.value

                alert = Alert(
                    organization_id=org.id,
                    raw_intel_id=raw.id,
                    category=triage_result["category"],
                    severity=triage_result["severity"],
                    status=status,
                    title=triage_result.get("title", "Untitled Alert"),
                    summary=triage_result.get("summary", ""),
                    details=triage_result,
                    matched_entities=triage_result.get("matched_entities"),
                    confidence=confidence,
                    agent_reasoning=triage_result.get("reasoning"),
                    recommended_actions=triage_result.get("recommended_actions"),
                )
                self.db.add(alert)
                alerts.append(alert)
                logger.info(
                    f"[pipeline] Alert ({status}): {alert.severity} {alert.category} "
                    f"for {org.name} — {alert.title} (confidence={confidence:.2f})"
                )

        if alerts:
            await self.db.flush()

            # Dispatch webhooks only for NEW alerts (not NEEDS_REVIEW)
            for alert in alerts:
                if alert.status == AlertStatus.NEW.value:
                    try:
                        await dispatch_alert(alert, self.db)
                    except Exception as e:
                        logger.error(f"[pipeline] Webhook dispatch failed for alert {alert.id}: {e}")

        raw.is_processed = True

        return alerts

    async def _update_source_health(
        self,
        source_id: uuid.UUID,
        success: bool,
        items_collected: int = 0,
        structure_hash: str | None = None,
    ) -> None:
        """Update CrawlerSource health metrics after a crawl completes."""
        source = await self.db.get(CrawlerSource, source_id)
        if source is None:
            logger.warning(f"[pipeline] CrawlerSource {source_id} not found for health update")
            return

        now = datetime.now(timezone.utc)

        if success:
            source.health_status = SourceHealthStatus.HEALTHY.value
            source.consecutive_failures = 0
            source.last_success_at = now
            source.total_items_collected += items_collected
        else:
            source.consecutive_failures += 1
            if source.consecutive_failures >= 3:
                source.health_status = SourceHealthStatus.DEGRADED.value
                await activity_emit(
                    ActivityType.SYSTEM,
                    "pipeline",
                    f"Source {source.name} degraded — {source.consecutive_failures} consecutive failures",
                    {
                        "source_id": str(source_id),
                        "source_name": source.name,
                        "consecutive_failures": source.consecutive_failures,
                        "health_status": SourceHealthStatus.DEGRADED.value,
                    },
                    severity="warning",
                )

        # Detect structure changes (e.g., site layout changed, selectors may be stale)
        if structure_hash is not None and structure_hash != source.last_structure_hash:
            old_hash = source.last_structure_hash
            source.last_structure_hash = structure_hash
            source.structure_changed_at = now
            await activity_emit(
                ActivityType.SYSTEM,
                "pipeline",
                f"Source {source.name} structure changed — selectors may need updating",
                {
                    "source_id": str(source_id),
                    "source_name": source.name,
                    "old_hash": old_hash,
                    "new_hash": structure_hash,
                },
                severity="warning",
            )

        source.last_crawled_at = now
        await self.db.flush()

    async def _extract_and_store_iocs(
        self,
        raw: RawIntel,
        alert_id: "uuid.UUID | None",
        result: CrawlResult,
    ) -> list[IOC]:
        """Extract IOCs from raw content and upsert into the database."""
        import uuid

        text = raw.content
        if raw.title:
            text = raw.title + "\n" + text

        extracted = extract_iocs(text)
        if not extracted:
            return []

        now = datetime.now(timezone.utc)
        stored: list[IOC] = []

        for ext in extracted:
            # Upsert: check if this (type, value) pair already exists
            existing_result = await self.db.execute(
                select(IOC).where(
                    IOC.ioc_type == ext.ioc_type.value,
                    IOC.value == ext.value,
                )
            )
            existing = existing_result.scalar_one_or_none()

            if existing:
                # Update existing IOC — increment sighting count, update last_seen
                existing.sighting_count += 1
                existing.last_seen = now
                if ext.confidence > existing.confidence:
                    existing.confidence = ext.confidence
                # Link to alert if not already linked
                if alert_id and not existing.source_alert_id:
                    existing.source_alert_id = alert_id
                stored.append(existing)
            else:
                ioc = IOC(
                    ioc_type=ext.ioc_type.value,
                    value=ext.value,
                    confidence=ext.confidence,
                    first_seen=now,
                    last_seen=now,
                    sighting_count=1,
                    context={"snippet": ext.context_snippet, "source": result.source_name},
                    source_alert_id=alert_id,
                    source_raw_intel_id=raw.id,
                )
                self.db.add(ioc)
                stored.append(ioc)

        if stored:
            await self.db.flush()
            logger.info(
                "[pipeline] Extracted %d IOCs from raw_intel %s", len(stored), raw.id,
            )

        return stored

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
