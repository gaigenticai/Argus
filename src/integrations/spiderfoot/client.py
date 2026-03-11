"""SpiderFoot OSINT integration client."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)


class SpiderFootIntegration(BaseIntegration):
    """Connects to a SpiderFoot instance for automated OSINT collection.

    SpiderFoot scans targets (domains, IPs, emails, etc.) across hundreds
    of data sources and returns structured intelligence.
    """

    name = "spiderfoot"
    display_name = "SpiderFoot"
    description = "Automated OSINT reconnaissance and intelligence gathering"
    category = "OSINT"

    async def test_connection(self) -> dict:
        """Ping the SpiderFoot API to verify connectivity."""
        result = await self._request("GET", "/api?query=ping")
        if result is not None:
            return {
                "connected": True,
                "message": "SpiderFoot API is reachable",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return {
            "connected": False,
            "message": "Failed to reach SpiderFoot API",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def sync(self) -> dict:
        """List recent scans and return a summary."""
        scans = await self._request("GET", "/api?query=scanlist")
        if scans is None:
            return {"synced": False, "message": "Failed to fetch scan list"}

        scan_list = scans if isinstance(scans, list) else []
        return {
            "synced": True,
            "total_scans": len(scan_list),
            "scans": [
                {
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "status": s.get("status"),
                    "target": s.get("target"),
                    "started": s.get("started"),
                }
                for s in scan_list
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def start_scan(
        self,
        target: str,
        modules: list[str] | None = None,
    ) -> str | None:
        """Start a new SpiderFoot scan against the given target.

        Args:
            target: The scan target (domain, IP, email, etc.).
            modules: Optional list of module names to enable. When *None*,
                SpiderFoot runs its default module set.

        Returns:
            The scan ID string on success, or *None* on failure.
        """
        payload: dict = {
            "scanname": f"argus-{target}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "scantarget": target,
        }
        if modules:
            payload["usemodules"] = ",".join(modules)

        result = await self._request("POST", "/api?query=startscan", json=payload)
        if result is None:
            logger.error("[spiderfoot] Failed to start scan for target %s", target)
            return None

        scan_id: str | None = None
        if isinstance(result, dict):
            scan_id = result.get("id") or result.get("scanId") or result.get("scan_id")
        elif isinstance(result, list) and len(result) > 0:
            scan_id = result[0] if isinstance(result[0], str) else str(result[0])

        logger.info("[spiderfoot] Started scan %s for target %s", scan_id, target)
        return scan_id

    async def get_scan_results(self, scan_id: str) -> list[dict]:
        """Retrieve results for a completed SpiderFoot scan.

        Args:
            scan_id: The scan identifier returned by :meth:`start_scan`.

        Returns:
            A list of result dictionaries. Empty list on failure.
        """
        result = await self._request(
            "GET",
            "/api",
            params={"query": "scandata", "id": scan_id},
        )
        if result is None:
            logger.error("[spiderfoot] Failed to fetch results for scan %s", scan_id)
            return []

        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("results", []))
        return []
