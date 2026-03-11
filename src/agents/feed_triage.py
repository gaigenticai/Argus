"""Feed Triage Service — the agentic bridge between threat feeds and intelligence.

Takes batches of ThreatFeedEntries, auto-creates IOCs, and uses the LLM
to generate correlated alerts with severity assessment and recommended actions.
"""

import logging
import uuid as _uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

import time

from src.agents.triage_agent import TriageAgent
from src.config.settings import settings
from src.core.activity import ActivityType, emit as activity_emit
from src.models.feeds import ThreatFeedEntry
from src.models.intel import IOC, IOCType, TriageRun
from src.models.threat import Alert, AlertStatus, Organization

logger = logging.getLogger(__name__)

# Map feed entry_type → IOC type
ENTRY_TYPE_TO_IOC: dict[str, str] = {
    "ip": IOCType.IPV4.value,
    "ipv4": IOCType.IPV4.value,
    "ipv6": IOCType.IPV6.value,
    "domain": IOCType.DOMAIN.value,
    "url": IOCType.URL.value,
    "hash": IOCType.SHA256.value,
    "md5": IOCType.MD5.value,
    "sha1": IOCType.SHA1.value,
    "sha256": IOCType.SHA256.value,
    "cve": IOCType.CVE.value,
    "ja3": IOCType.JA3.value,
    "email": IOCType.EMAIL.value,
}

# Feed layers that generate alerts automatically (high-signal)
ALERT_WORTHY_LAYERS = {
    "ransomware",
    "botnet_c2",
    "exploited_cve",
    "malware",
    "phishing",
}

# Severity → INFOCON mapping thresholds
INFOCON_THRESHOLDS = {
    "red": {"critical": 5, "high": 20},
    "orange": {"critical": 2, "high": 10},
    "yellow": {"critical": 1, "high": 5},
}

# Category mapping from layer
LAYER_TO_CATEGORY = {
    "ransomware": "ransomware",
    "botnet_c2": "exploit",
    "phishing": "phishing",
    "malware": "exploit",
    "exploited_cve": "exploit",
    "ip_reputation": "dark_web_mention",
    "ssl_abuse": "exploit",
    "tor_exit": "underground_chatter",
    "honeypot": "initial_access",
}


class FeedTriageService:
    """Processes feed entries into IOCs and alerts with LLM correlation."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.triage = TriageAgent(db=db)

    async def process_new_entries(
        self, hours: int = 1, batch_size: int = 500, trigger: str = "manual",
    ) -> dict:
        """Process recent feed entries: create IOCs, generate alerts, update INFOCON.

        Persists a TriageRun record tracking the run's outcome.
        Returns summary dict with counts.
        """
        t0 = time.monotonic()
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Create TriageRun record up front so it's visible immediately
        run = TriageRun(
            trigger=trigger,
            hours_window=hours,
            entries_processed=0,
            iocs_created=0,
            alerts_generated=0,
            duration_seconds=0.0,
            status="running",
        )
        self.db.add(run)
        await self.db.flush()

        await activity_emit(
            ActivityType.TRIAGE_START,
            "feed_triage",
            f"Starting feed triage for entries in last {hours}h",
            {"hours": hours},
        )

        error_message: str | None = None
        ioc_count = 0
        alert_count = 0
        entries_processed = 0

        try:
            # 1. Create IOCs from feed entries
            ioc_count = await self._create_iocs_from_feeds(since, batch_size)

            # Count entries that were processed
            from sqlalchemy import func as sqlfunc
            result = await self.db.execute(
                select(sqlfunc.count()).select_from(ThreatFeedEntry).where(
                    ThreatFeedEntry.created_at >= since,
                    ThreatFeedEntry.entry_type.in_(list(ENTRY_TYPE_TO_IOC.keys())),
                )
            )
            entries_processed = result.scalar() or 0
            await self.db.commit()

            # 2. Generate alerts from high-severity entries using LLM
            try:
                alert_count = await self._generate_alerts(since)
                await self.db.commit()
            except Exception as e:
                logger.error(f"[feed-triage] Alert generation failed: {e}")
                error_message = f"Alert generation failed: {str(e)[:400]}"
                await self.db.rollback()

            # 3. Update global threat status (INFOCON level)
            try:
                await self._update_infocon()
                await self.db.commit()
            except Exception as e:
                logger.error(f"[feed-triage] INFOCON update failed: {e}")
                await self.db.rollback()

        except Exception as e:
            logger.error(f"[feed-triage] Triage failed: {e}")
            error_message = str(e)[:500]
            try:
                await self.db.rollback()
            except Exception:
                pass

        # Finalize the TriageRun record
        duration = time.monotonic() - t0
        run.entries_processed = entries_processed
        run.iocs_created = ioc_count
        run.alerts_generated = alert_count
        run.duration_seconds = round(duration, 2)
        run.status = "completed" if error_message is None else "error"
        run.error_message = error_message

        try:
            await self.db.commit()
        except Exception:
            logger.error("[feed-triage] Failed to persist TriageRun record")

        summary = {
            "iocs_created": ioc_count,
            "alerts_generated": alert_count,
            "entries_processed": entries_processed,
            "time_range_hours": hours,
            "duration_seconds": round(duration, 2),
            "status": run.status,
        }

        await activity_emit(
            ActivityType.TRIAGE_RESULT,
            "feed_triage",
            f"Feed triage complete: {ioc_count} IOCs, {alert_count} alerts",
            summary,
        )

        return summary

    async def _create_iocs_from_feeds(self, since: datetime, batch_size: int) -> int:
        """Convert ThreatFeedEntries to IOCs (deduped)."""
        # Get entries that have IOC-mappable types
        result = await self.db.execute(
            select(ThreatFeedEntry)
            .where(
                ThreatFeedEntry.created_at >= since,
                ThreatFeedEntry.entry_type.in_(list(ENTRY_TYPE_TO_IOC.keys())),
            )
            .order_by(ThreatFeedEntry.created_at.desc())
            .limit(batch_size)
        )
        entries = result.scalars().all()

        if not entries:
            return 0

        created = 0
        now = datetime.now(timezone.utc)

        for entry in entries:
            ioc_type = ENTRY_TYPE_TO_IOC.get(entry.entry_type)
            if not ioc_type:
                continue

            # Atomic upsert: INSERT ... ON CONFLICT DO UPDATE
            stmt = pg_insert(IOC).values(
                id=_uuid.uuid4(),
                created_at=now,
                updated_at=now,
                ioc_type=ioc_type,
                value=entry.value,
                confidence=entry.confidence,
                first_seen=entry.first_seen or now,
                last_seen=now,
                sighting_count=1,
                tags=[entry.feed_name, entry.layer],
                context={
                    "feed": entry.feed_name,
                    "layer": entry.layer,
                    "severity": entry.severity,
                    "country": entry.country_code,
                    "label": entry.label,
                },
            ).on_conflict_do_update(
                constraint="uq_ioc_type_value",
                set_={
                    "sighting_count": IOC.sighting_count + 1,
                    "last_seen": now,
                    "confidence": func.greatest(IOC.confidence, entry.confidence),
                },
            ).returning(IOC.created_at)
            result = await self.db.execute(stmt)
            row = result.one()
            if (now - row.created_at).total_seconds() < 2:
                created += 1

            # Flush every 100
            if created > 0 and created % 100 == 0:
                await self.db.flush()

        await self.db.flush()
        logger.info(f"[feed-triage] Created {created} IOCs from {len(entries)} feed entries")
        return created

    async def _generate_alerts(self, since: datetime) -> int:
        """Generate alerts from high-severity feed entries using LLM analysis."""
        # Get critical/high entries from alert-worthy layers
        result = await self.db.execute(
            select(ThreatFeedEntry)
            .where(
                ThreatFeedEntry.created_at >= since,
                ThreatFeedEntry.layer.in_(ALERT_WORTHY_LAYERS),
                ThreatFeedEntry.severity.in_(["critical", "high"]),
            )
            .order_by(ThreatFeedEntry.severity.desc(), ThreatFeedEntry.confidence.desc())
            .limit(50)  # Cap LLM calls
        )
        entries = result.scalars().all()

        if not entries:
            return 0

        # Get all organizations for matching
        orgs_result = await self.db.execute(select(Organization))
        organizations = orgs_result.scalars().all()

        # Group entries by layer for batch analysis
        by_layer: dict[str, list[ThreatFeedEntry]] = {}
        for entry in entries:
            by_layer.setdefault(entry.layer, []).append(entry)

        alert_count = 0

        for layer, layer_entries in by_layer.items():
            # Build a summary of the batch for LLM
            batch_summary = self._build_batch_summary(layer, layer_entries)
            category = LAYER_TO_CATEGORY.get(layer, "dark_web_mention")

            if organizations:
                # Triage against each org
                for org in organizations:
                    org_profile = await self._build_org_profile(org)
                    triage_result = await self.triage.analyze(
                        raw_content=batch_summary,
                        source_type=f"threat_feed_{layer}",
                        source_name=f"Feed Aggregator ({layer})",
                        org_profile=org_profile,
                    )

                    if triage_result:
                        alert = Alert(
                            organization_id=org.id,
                            category=triage_result.get("category", category),
                            severity=triage_result.get("severity", "medium"),
                            status=AlertStatus.NEW.value,
                            title=triage_result.get("title", f"Feed Alert: {layer}"),
                            summary=triage_result.get("summary", ""),
                            confidence=triage_result.get("confidence", 0.7),
                            agent_reasoning=triage_result.get("reasoning"),
                            recommended_actions=triage_result.get("recommended_actions"),
                            matched_entities=triage_result.get("matched_entities"),
                        )
                        self.db.add(alert)
                        alert_count += 1
            else:
                # No orgs configured — log but skip alert creation (alerts require org context)
                logger.info(
                    f"[feed-triage] {len(layer_entries)} high-severity {layer} entries found "
                    f"but no organizations configured — skipping alert generation. "
                    f"Create an organization to enable LLM-powered triage."
                )

        if alert_count > 0:
            await self.db.flush()

        logger.info(f"[feed-triage] Generated {alert_count} alerts from {len(entries)} high-severity entries")
        return alert_count

    def _build_batch_summary(self, layer: str, entries: list[ThreatFeedEntry]) -> str:
        """Build human-readable summary of a batch for LLM analysis."""
        lines = [
            f"## Threat Feed Intelligence Report — {layer.replace('_', ' ').title()}",
            f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"Total indicators: {len(entries)}",
            "",
            "### Indicators:",
        ]

        for entry in entries[:30]:  # Cap context size
            meta = ""
            if entry.country_code:
                meta += f" | Country: {entry.country_code}"
            if entry.asn:
                meta += f" | ASN: {entry.asn}"
            if entry.label:
                meta += f" | Label: {entry.label}"

            lines.append(
                f"- [{entry.severity.upper()}] {entry.entry_type}: {entry.value} "
                f"(feed: {entry.feed_name}, confidence: {entry.confidence:.0%}{meta})"
            )

        if len(entries) > 30:
            lines.append(f"... and {len(entries) - 30} more indicators")

        # Add country distribution
        countries = {}
        for e in entries:
            if e.country_code:
                countries[e.country_code] = countries.get(e.country_code, 0) + 1
        if countries:
            top_countries = sorted(countries.items(), key=lambda x: -x[1])[:10]
            lines.append("")
            lines.append("### Geographic Distribution:")
            for cc, count in top_countries:
                lines.append(f"- {cc}: {count} indicators")

        return "\n".join(lines)

    def _build_alert_summary(self, layer: str, entries: list[ThreatFeedEntry]) -> str:
        """Build alert summary without LLM."""
        feeds = set(e.feed_name for e in entries)
        countries = set(e.country_code for e in entries if e.country_code)
        severities = {}
        for e in entries:
            severities[e.severity] = severities.get(e.severity, 0) + 1

        parts = [
            f"{len(entries)} new threat indicators detected in the {layer.replace('_', ' ')} layer.",
            f"Sources: {', '.join(feeds)}.",
        ]
        if severities:
            sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severities.items()))
            parts.append(f"Severity breakdown: {sev_str}.")
        if countries:
            parts.append(f"Originating from {len(countries)} countries: {', '.join(sorted(countries)[:10])}.")

        return " ".join(parts)

    def _get_recommended_actions(self, layer: str) -> list[str]:
        """Get default recommended actions per layer."""
        actions = {
            "ransomware": [
                "Check if any named victims are in your supply chain",
                "Verify backup integrity and test restoration procedures",
                "Review endpoint detection rules for named ransomware variants",
            ],
            "botnet_c2": [
                "Block listed C2 IPs/domains at the firewall",
                "Search network logs for connections to these indicators",
                "Update IDS/IPS signatures",
            ],
            "phishing": [
                "Add phishing domains to email gateway blocklist",
                "Alert security awareness team for targeted campaigns",
                "Check if any org domains are being spoofed",
            ],
            "malware": [
                "Update antivirus/EDR with new hash signatures",
                "Block malware distribution URLs at web proxy",
                "Scan endpoints for listed indicators",
            ],
            "exploited_cve": [
                "Prioritize patching for listed CVEs",
                "Check asset inventory for vulnerable software versions",
                "Deploy virtual patches or WAF rules as interim mitigation",
            ],
        }
        return actions.get(layer, ["Review indicators and assess organizational impact"])

    async def _update_infocon(self) -> None:
        """Update the global INFOCON level based on current threat landscape."""
        from src.models.feeds import GlobalThreatStatus

        now = datetime.now(timezone.utc)
        last_24h = now - timedelta(hours=24)

        # Count severities in last 24h
        sev_counts = {}
        for sev in ["critical", "high", "medium"]:
            result = await self.db.execute(
                select(func.count()).select_from(ThreatFeedEntry).where(
                    ThreatFeedEntry.severity == sev,
                    ThreatFeedEntry.created_at >= last_24h,
                )
            )
            sev_counts[sev] = result.scalar() or 0

        # Determine INFOCON level
        level = "green"
        for infocon, thresholds in INFOCON_THRESHOLDS.items():
            if all(sev_counts.get(sev, 0) >= count for sev, count in thresholds.items()):
                level = infocon
                break

        # Count active entries per layer
        layer_counts = {}
        for layer_name in ["ransomware", "botnet_c2", "phishing", "exploited_cve", "tor_exit", "malware", "ip_reputation"]:
            result = await self.db.execute(
                select(func.count()).select_from(ThreatFeedEntry).where(
                    ThreatFeedEntry.layer == layer_name,
                    ThreatFeedEntry.expires_at > now,
                )
            )
            layer_counts[layer_name] = result.scalar() or 0

        # Upsert global status
        existing = await self.db.execute(select(GlobalThreatStatus).limit(1))
        status = existing.scalar_one_or_none()

        values = {
            "infocon_level": level,
            "active_ransomware_groups": layer_counts.get("ransomware", 0),
            "active_c2_servers": layer_counts.get("botnet_c2", 0),
            "active_phishing_campaigns": layer_counts.get("phishing", 0),
            "exploited_cves_count": layer_counts.get("exploited_cve", 0),
            "tor_exit_nodes_count": layer_counts.get("tor_exit", 0),
            "malware_urls_count": layer_counts.get("malware", 0),
            "malicious_ips_count": layer_counts.get("ip_reputation", 0),
        }

        if status:
            for k, v in values.items():
                setattr(status, k, v)
        else:
            status = GlobalThreatStatus(**values)
            self.db.add(status)

        await self.db.flush()

    async def _build_org_profile(self, org: Organization) -> dict:
        """Build org profile for triage agent."""
        from src.models.threat import VIPTarget

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
