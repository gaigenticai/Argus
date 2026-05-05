"""Feed Triage Service — the agentic bridge between threat feeds and intelligence.

Takes batches of ThreatFeedEntries, auto-creates IOCs, and uses the LLM
to generate correlated alerts with severity assessment and recommended actions.
"""

from __future__ import annotations


import asyncio
import logging
import uuid as _uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

import time

from src.agents.triage_agent import TriageAgent
from src.config.settings import settings
from src.core.activity import ActivityType, emit as activity_emit
from src.models.feeds import ThreatFeedEntry
from src.models.intel import IOC, IOCType, TriageRun
from src.models.threat import (
    Alert,
    AlertStatus,
    Organization,
    ThreatCategory,
    ThreatSeverity,
)

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
            except Exception as e:  # noqa: BLE001
                # Alert generation calls into the LLM (async network)
                # plus DB writes plus IOC enrichment — too many distinct
                # failure surfaces to enumerate. Catch broadly so the
                # rest of the run continues; the error_message below
                # carries the actual cause.
                logger.exception("[feed-triage] Alert generation failed: %s", e)
                error_message = f"Alert generation failed: {str(e)[:400]}"
                await self.db.rollback()

            # 3. Update global threat status (INFOCON level)
            try:
                await self._update_infocon()
                await self.db.commit()
            except Exception as e:  # noqa: BLE001
                # Same rationale as above — INFOCON update touches the
                # API layer and DB. Failure must not poison the run.
                logger.exception("[feed-triage] INFOCON update failed: %s", e)
                await self.db.rollback()

        except Exception as e:  # noqa: BLE001
            # Top-level run boundary. Catches everything below and
            # records it on the TriageRun record so the dashboard
            # surfaces the failure instead of the run silently
            # completing with zero IOCs.
            logger.exception("[feed-triage] Triage failed: %s", e)
            error_message = str(e)[:500]
            try:
                await self.db.rollback()
            except Exception as rollback_exc:  # noqa: BLE001
                logger.error(
                    "[feed-triage] rollback after error itself failed: %s",
                    rollback_exc,
                )

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
        except SQLAlchemyError as commit_exc:
            # If the final TriageRun commit itself fails, the run row
            # never lands — there is no TriageRun for the dashboard
            # to show. Log with full context so an operator can grep
            # for stuck runs.
            logger.exception(
                "[feed-triage] Failed to persist TriageRun record: %s",
                commit_exc,
            )

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
        # Domain-verification gate (off by default; on for production
        # ``ARGUS_REQUIRE_DOMAIN_VERIFICATION=true`` deployments).
        # Skipping here keeps an unverified org from getting LLM-
        # generated alerts wired up that the operator hasn't proven
        # they own the asset for. The org row still exists so the
        # operator can verify and re-run.
        from src.core.domain_verification import is_domain_verified
        orgs_result = await self.db.execute(select(Organization))
        all_orgs = list(orgs_result.scalars().all())
        organizations = []
        skipped_unverified = 0
        for o in all_orgs:
            primary_domain = (o.domains or [None])[0]
            if primary_domain and not is_domain_verified(o.settings, primary_domain):
                skipped_unverified += 1
                continue
            organizations.append(o)
        if skipped_unverified:
            logger.info(
                "[feed-triage] skipped %d org(s) with unverified primary domain "
                "(ARGUS_REQUIRE_DOMAIN_VERIFICATION is on)",
                skipped_unverified,
            )

        # Group entries by layer for batch analysis
        by_layer: dict[str, list[ThreatFeedEntry]] = {}
        for entry in entries:
            by_layer.setdefault(entry.layer, []).append(entry)

        if not organizations:
            # No orgs configured — log but skip alert creation (alerts require org context)
            logger.info(
                f"[feed-triage] {sum(len(v) for v in by_layer.values())} high-severity entries found "
                f"but no organizations configured — skipping alert generation. "
                f"Create an organization to enable LLM-powered triage."
            )
            return 0

        # ---------------------------------------------------------------
        # Per-org term pre-filter (LLM cost guard).
        #
        # Without this we issue ``layers × orgs`` LLM calls regardless
        # of whether any entry in the batch is even plausibly relevant
        # to the org. The LLM dutifully returns ``is_threat: false`` and
        # we burn tokens for no signal.
        #
        # Match terms per org = tech_stack vendors/products
        #                     + brand keywords
        #                     + verified domains
        #                     + org name
        # All lowercased; min length 3 to avoid pathological matches
        # (e.g. ".NET" → "internet"). An entry "matches" an org if any
        # of those terms appears as a substring in its description,
        # label, or value.
        #
        # This is intentionally cheap — substring scan, no LLM, no
        # NLP — because the LLM is the only expensive call in this
        # path and the goal is to gate it. False positives at this
        # stage are fine; the LLM still adjudicates ``is_threat``.
        # False negatives are the risk: a CVE that affects you but
        # whose advisory text uses an unexpected name slips through.
        # Mitigate by encouraging operators to enrich Tech Stack.
        # ---------------------------------------------------------------
        def _org_terms(o: Organization) -> list[str]:
            terms: list[str] = []
            if o.name:
                terms.append(o.name)
            for d in (o.domains or []):
                if d:
                    terms.append(d)
            for k in (o.keywords or []):
                if k:
                    terms.append(k)
            ts = o.tech_stack or {}
            if isinstance(ts, dict):
                for vals in ts.values():
                    if isinstance(vals, list):
                        for v in vals:
                            if isinstance(v, str) and v.strip():
                                terms.append(v.strip())
            # Dedup case-insensitively, drop terms <3 chars.
            seen: set[str] = set()
            out: list[str] = []
            for t in terms:
                lk = t.lower()
                if len(lk) < 3 or lk in seen:
                    continue
                seen.add(lk)
                out.append(t)
            return out

        def _entry_matches(entry: ThreatFeedEntry, terms_lower: list[str]) -> bool:
            haystack = " ".join(
                filter(None, [entry.description, entry.label, entry.value])
            ).lower()
            if not haystack:
                return False
            return any(t in haystack for t in terms_lower)

        org_terms_lower: dict = {
            o.id: [t.lower() for t in _org_terms(o)] for o in organizations
        }

        # Pre-build the work plan sequentially so the rest can run in
        # parallel. ``_build_system_prompt`` and ``_build_org_profile``
        # both read from ``self.db`` / ``self.triage._db`` and the
        # SQLAlchemy AsyncSession is not concurrency-safe — one
        # session = one in-flight statement. So we serialise the DB
        # reads here, then fan out the LLM calls (which only touch
        # network) under a semaphore.
        system_prompt = await self.triage._build_system_prompt()
        org_profiles: dict = {}
        for org in organizations:
            org_profiles[org.id] = await self._build_org_profile(org)

        # ``max_concurrent_calls`` is the platform-wide knob (default
        # 4). Higher values overwhelm slower providers and starve
        # other agents that share the same bridge worker; lower kills
        # throughput. Respect it.
        sem = asyncio.Semaphore(
            max(1, int(getattr(settings.llm, "max_concurrent_calls", 4)))
        )

        async def _run_one(layer: str, batch_summary: str, org) -> tuple[str, object, dict | None]:
            org_profile = org_profiles[org.id]
            user_prompt = self.triage._build_prompt(
                batch_summary,
                f"threat_feed_{layer}",
                f"Feed Aggregator ({layer})",
                org_profile,
            )
            org_name = org_profile.get("name", "Unknown")
            await activity_emit(
                ActivityType.TRIAGE_START,
                "triage_agent",
                f"Analyzing intel from Feed Aggregator ({layer}) against {org_name}",
                {"source_type": f"threat_feed_{layer}", "org": org_name},
            )
            async with sem:
                try:
                    await activity_emit(
                        ActivityType.TRIAGE_LLM_CALL,
                        "triage_agent",
                        f"Calling {self.triage.provider}/{self.triage.model} for threat classification",
                        {"provider": self.triage.provider, "model": self.triage.model, "org": org_name},
                    )
                    response = await self.triage._call_llm(system_prompt, user_prompt)
                    parsed = self.triage._parse_json_response(response)
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"[feed-triage] LLM call failed for {org_name}/{layer}: {e}")
                    return layer, org, None
            if not parsed or not parsed.get("is_threat", False):
                return layer, org, None
            parsed["category"] = self.triage._validate_enum(
                parsed.get("category"), ThreatCategory, ThreatCategory.DARK_WEB_MENTION
            )
            parsed["severity"] = self.triage._validate_enum(
                parsed.get("severity"), ThreatSeverity, ThreatSeverity.LOW
            )
            parsed["confidence"] = max(0.0, min(1.0, float(parsed.get("confidence", 0.5))))
            return layer, org, parsed

        # Build per-(layer, org) batches AFTER pre-filtering so the
        # task list reflects the post-filter cardinality and the IOC
        # linking step (below) only links indicators the LLM actually
        # reasoned about.
        tasks = []
        per_org_batches: dict[tuple[str, _uuid.UUID], list[ThreatFeedEntry]] = {}
        skipped_empty = 0
        total_pairs = 0
        for layer, layer_entries in by_layer.items():
            for org in organizations:
                total_pairs += 1
                terms_lower = org_terms_lower.get(org.id, [])
                if not terms_lower:
                    # Org has no declared identity at all — every
                    # entry would trivially fail. Skip rather than
                    # waste the LLM call.
                    skipped_empty += 1
                    continue
                matching = [e for e in layer_entries if _entry_matches(e, terms_lower)]
                if not matching:
                    skipped_empty += 1
                    continue
                per_org_batches[(layer, org.id)] = matching
                tasks.append(
                    _run_one(
                        layer,
                        self._build_batch_summary(layer, matching),
                        org,
                    )
                )
        logger.info(
            "[feed-triage] Pre-filter: %d/%d (layer × org) pairs matched "
            "the orgs' tech_stack/keywords; skipped %d empty pairs. "
            "Dispatching %d LLM calls (was %d before pre-filter, "
            "concurrency=%d).",
            len(tasks), total_pairs, skipped_empty,
            len(tasks), total_pairs, sem._value,
        )
        if not tasks:
            logger.info(
                "[feed-triage] No (layer, org) batches survived pre-filter — "
                "no LLM calls dispatched. Either the org's tech_stack is "
                "empty or no high-severity entries mention it."
            )
            return 0
        results = await asyncio.gather(*tasks, return_exceptions=False)

        alert_count = 0
        deduped_into_existing = 0
        ioc_links = 0
        # Same-day dedup horizon. Triage runs hourly + on-demand; in
        # practice 5 successive runs in an hour all classified the
        # same exploited_cve batch as a threat and produced 5
        # near-identical alerts. The operator drowns in duplicates.
        # Window: 24h is wide enough to merge across a normal
        # workday's runs but narrow enough that genuinely new
        # exposure (e.g. a CVE landing tomorrow) re-fires.
        dedup_horizon = datetime.now(timezone.utc) - timedelta(hours=24)
        closed_statuses = [
            AlertStatus.RESOLVED.value,
            AlertStatus.FALSE_POSITIVE.value,
        ]
        for layer, org, triage_result in results:
            if not triage_result:
                continue
            category = triage_result.get("category", LAYER_TO_CATEGORY.get(layer, "dark_web_mention"))

            # Dedup: if there is already an OPEN alert for this org +
            # category within the dedup horizon, attach the batch's
            # IOCs to it instead of creating a new row. Operator sees
            # one alert whose evidence grows, not 5 alerts that say
            # the same thing.
            existing_q = await self.db.execute(
                select(Alert)
                .where(
                    Alert.organization_id == org.id,
                    Alert.category == category,
                    Alert.created_at >= dedup_horizon,
                    Alert.status.notin_(closed_statuses),
                )
                .order_by(Alert.created_at.desc())
                .limit(1)
            )
            alert = existing_q.scalar_one_or_none()
            is_new = alert is None

            if is_new:
                alert = Alert(
                    organization_id=org.id,
                    category=category,
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
                await self.db.flush()  # populate alert.id for the IOC link below
                alert_count += 1
            else:
                # Existing alert: bump it so the operator knows the
                # evidence list grew. Don't overwrite the original
                # title/severity/reasoning — those were set when the
                # alert first fired and are part of its identity.
                alert.updated_at = datetime.now(timezone.utc)
                deduped_into_existing += 1

            # Carry the batch's indicators with the alert.
            #
            # The dashboard's "Tracked IOCs" tile counts IOCs whose
            # ``source_alert_id`` points to an alert in the org. The
            # bulk IOC-promotion path (``_create_iocs_from_feeds``)
            # is FIFO over a 500-row window dominated by honeypot /
            # IP-reputation entries, so CVE / advisory entries — the
            # ones that actually trigger alerts — almost never get
            # promoted there. Result: alerts fire but the tile reads
            # zero indefinitely.
            #
            # Fix: when an alert fires, upsert IOCs for the EXACT
            # entries the LLM reasoned about, then link them. This
            # also matches the right mental model — an alert's IOCs
            # ARE its evidence; create them with it.
            #
            # First-claim-wins on ``source_alert_id`` so we never
            # overwrite existing provenance. The IOC row itself is
            # idempotent via ``uq_ioc_type_value``.
            batch_entries = per_org_batches.get((layer, org.id), [])
            now_link = datetime.now(timezone.utc)
            inserted_with_alert = 0
            for entry in batch_entries:
                ioc_type = ENTRY_TYPE_TO_IOC.get(entry.entry_type)
                if not ioc_type or not entry.value:
                    continue
                stmt = pg_insert(IOC).values(
                    id=_uuid.uuid4(),
                    created_at=now_link,
                    updated_at=now_link,
                    ioc_type=ioc_type,
                    value=entry.value,
                    confidence=entry.confidence,
                    first_seen=entry.first_seen or now_link,
                    last_seen=now_link,
                    sighting_count=1,
                    tags=[entry.feed_name, entry.layer, "alert_evidence"],
                    context={
                        "feed": entry.feed_name,
                        "layer": entry.layer,
                        "severity": entry.severity,
                        "label": entry.label,
                    },
                    source_alert_id=alert.id,
                ).on_conflict_do_update(
                    constraint="uq_ioc_type_value",
                    set_={
                        "sighting_count": IOC.sighting_count + 1,
                        "last_seen": now_link,
                        "confidence": func.greatest(IOC.confidence, entry.confidence),
                    },
                ).returning(IOC.created_at)
                row = (await self.db.execute(stmt)).one()
                if (now_link - row.created_at).total_seconds() < 2:
                    inserted_with_alert += 1

            # Now claim every IOC for the batch's values that is
            # still unowned. ``ON CONFLICT DO UPDATE`` above does not
            # set ``source_alert_id`` on the conflicting row (postgres
            # excluded() handling) — the explicit UPDATE below is what
            # lets pre-existing IOCs (created earlier by the bulk
            # path) get linked to a freshly-fired alert.
            entry_values = [e.value for e in batch_entries if e.value]
            if entry_values:
                upd = await self.db.execute(
                    update(IOC)
                    .where(
                        IOC.value.in_(entry_values),
                        IOC.source_alert_id.is_(None),
                    )
                    .values(source_alert_id=alert.id)
                )
                ioc_links += (upd.rowcount or 0) + inserted_with_alert

        if alert_count > 0:
            await self.db.flush()

        logger.info(
            f"[feed-triage] Generated {alert_count} new alerts "
            f"(plus {deduped_into_existing} re-fires merged into existing open alerts) "
            f"from {len(entries)} high-severity entries; {ioc_links} IOCs linked."
        )
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

        # Count active entries per layer.
        #
        # ``c2_infrastructure`` (TLS hashes / JA3 fingerprints from
        # AbuseCH SSLBL) is included alongside ``botnet_c2`` (C2
        # endpoint IPs from Feodo / GreyNoise) because the dashboard
        # surfaces a single "C2 Indicators" tile — operators care
        # about total C2 detection coverage, not the implementation
        # split between IP feeds and TLS-artifact feeds. Showing
        # ``botnet_c2`` alone produced "1 C2 server" while a 9.7k-row
        # SSL feed of C2 detection sigs sat ignored.
        layer_counts = {}
        for layer_name in [
            "ransomware",
            "botnet_c2",
            "c2_infrastructure",
            "phishing",
            "exploited_cve",
            "tor_exit",
            "malware",
            "ip_reputation",
        ]:
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
            # C2 indicators = endpoint IPs + TLS detection sigs.
            "active_c2_servers": (
                layer_counts.get("botnet_c2", 0)
                + layer_counts.get("c2_infrastructure", 0)
            ),
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
