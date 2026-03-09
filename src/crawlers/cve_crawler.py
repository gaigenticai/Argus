"""CVE/Vulnerability feed crawler."""

import json
import logging
from datetime import datetime, timezone
from typing import AsyncIterator

from src.models.threat import SourceType
from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


class CVECrawler(BaseCrawler):
    """Monitors NVD, GitHub advisories, and exploit databases for new vulnerabilities."""

    name = "cve_crawler"
    source_type = SourceType.CVE_FEED

    NVD_RECENT = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"
    GITHUB_ADVISORIES = "https://api.github.com/advisories?per_page=50"
    EXPLOITDB_SEARCH = "https://exploits.shodan.io/api/search"

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        async for result in self._crawl_nvd():
            yield result

        async for result in self._crawl_github_advisories():
            yield result

    async def _crawl_nvd(self) -> AsyncIterator[CrawlResult]:
        raw = await self._fetch(self.NVD_RECENT)
        if not raw:
            return

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.error(f"[{self.name}] Failed to parse NVD response")
            return

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descriptions = cve.get("descriptions", [])
            en_desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description",
            )

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = None
            for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if version in metrics:
                    cvss_data = metrics[version]
                    if cvss_data:
                        cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore")
                        break

            published = cve.get("published")
            published_at = None
            if published:
                try:
                    published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except ValueError:
                    pass

            content = f"CVE: {cve_id}\nCVSS: {cvss_score or 'N/A'}\n\n{en_desc}"

            yield CrawlResult(
                source_type=self.source_type,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                source_name="NVD",
                title=cve_id,
                content=content,
                published_at=published_at,
                raw_data={
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "references": [
                        ref.get("url") for ref in cve.get("references", [])
                    ],
                    "weaknesses": [
                        w.get("description", [{}])[0].get("value")
                        for w in cve.get("weaknesses", [])
                        if w.get("description")
                    ],
                },
            )

    async def _crawl_github_advisories(self) -> AsyncIterator[CrawlResult]:
        raw = await self._fetch(self.GITHUB_ADVISORIES)
        if not raw:
            return

        try:
            advisories = json.loads(raw)
        except json.JSONDecodeError:
            logger.error(f"[{self.name}] Failed to parse GitHub advisories")
            return

        if not isinstance(advisories, list):
            return

        for adv in advisories:
            summary = adv.get("summary", "")
            description = adv.get("description", "")
            cve_id = adv.get("cve_id", "")
            severity = adv.get("severity", "unknown")
            published = adv.get("published_at")

            published_at = None
            if published:
                try:
                    published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except ValueError:
                    pass

            content = f"Advisory: {summary}\nCVE: {cve_id or 'N/A'}\nSeverity: {severity}\n\n{description}"

            yield CrawlResult(
                source_type=self.source_type,
                source_url=adv.get("html_url", ""),
                source_name="GitHub Advisory",
                title=summary,
                content=content,
                published_at=published_at,
                raw_data={
                    "cve_id": cve_id,
                    "severity": severity,
                    "ghsa_id": adv.get("ghsa_id"),
                    "vulnerabilities": adv.get("vulnerabilities", []),
                },
            )
