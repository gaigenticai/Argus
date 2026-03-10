"""CISA Known Exploited Vulnerabilities (KEV) feed."""

import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVFeed(BaseFeed):
    """CISA Known Exploited Vulnerabilities — authoritative catalog of actively exploited CVEs."""

    name = "cisa_kev"
    layer = "exploited_cve"
    default_interval_seconds = 86400  # 24 hours

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        data = await self._fetch_json(KEV_URL)
        if not data or not isinstance(data, dict):
            logger.warning("[%s] KEV catalog returned no data", self.name)
            return

        vulnerabilities = data.get("vulnerabilities")
        if not vulnerabilities:
            logger.warning("[%s] KEV catalog has no vulnerabilities array", self.name)
            return

        now = datetime.now(timezone.utc)
        thirty_days_ago = now.timestamp() - (30 * 86400)

        emitted = 0
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "")
            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            vuln_name = vuln.get("vulnerabilityName", "")
            date_added_str = vuln.get("dateAdded", "")
            short_desc = vuln.get("shortDescription", "")
            required_action = vuln.get("requiredAction", "")
            due_date = vuln.get("dueDate", "")
            ransomware_use = vuln.get("knownRansomwareCampaignUse", "Unknown")
            notes = vuln.get("notes", "")

            if not cve_id:
                continue

            # Parse dateAdded
            first_seen = None
            date_added_ts = 0.0
            if date_added_str:
                try:
                    first_seen = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    date_added_ts = first_seen.timestamp()
                except ValueError:
                    pass

            # Severity classification
            if ransomware_use == "Known":
                severity = "critical"
            elif date_added_ts >= thirty_days_ago:
                severity = "high"
            else:
                severity = "medium"

            # Build description
            desc_parts = []
            if short_desc:
                desc_parts.append(short_desc)
            if required_action:
                desc_parts.append(f"Required action: {required_action}")
            description = " | ".join(desc_parts) if desc_parts else vuln_name

            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="cve",
                value=cve_id,
                label=f"{cve_id}: {vendor} {product}",
                description=description,
                severity=severity,
                confidence=1.0,
                feed_metadata={
                    "vendor": vendor,
                    "product": product,
                    "ransomware_use": ransomware_use,
                    "due_date": due_date,
                    "date_added": date_added_str,
                },
                first_seen=first_seen,
                expires_hours=2160,  # 90 days
            )
            emitted += 1

        logger.info("[%s] Ingested %d known exploited vulnerabilities", self.name, emitted)
