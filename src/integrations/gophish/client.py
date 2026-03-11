"""GoPhish phishing simulation integration client."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)


class GoPhishIntegration(BaseIntegration):
    """Connects to a GoPhish instance for phishing simulation management.

    GoPhish uses a flat API key in the ``Authorization`` header (no Bearer
    prefix), so :meth:`_build_headers` is overridden accordingly.
    """

    name = "gophish"
    display_name = "GoPhish"
    description = "Phishing simulation campaign management and reporting"
    category = "Phishing Simulation"

    # ------------------------------------------------------------------
    # Auth override — GoPhish expects `Authorization: <api_key>` (no Bearer)
    # ------------------------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Argus Threat Intelligence Platform",
        }
        if self.api_key:
            headers["Authorization"] = self.api_key
        return headers

    # ------------------------------------------------------------------
    # Required abstract methods
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Verify connectivity by listing campaigns (GoPhish has no /ping)."""
        result = await self._request(
            "GET",
            "/api/campaigns/",
            params={"api_key": self.api_key} if self.api_key else None,
        )
        if result is not None:
            return {
                "connected": True,
                "message": "GoPhish API is reachable",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return {
            "connected": False,
            "message": "Failed to reach GoPhish API",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def sync(self) -> dict:
        """List campaigns and return a summary."""
        campaigns = await self.get_campaigns()
        return {
            "synced": True,
            "total_campaigns": len(campaigns),
            "campaigns": [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "status": c.get("status"),
                    "created_date": c.get("created_date"),
                    "launch_date": c.get("launch_date"),
                }
                for c in campaigns
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # GoPhish-specific methods
    # ------------------------------------------------------------------

    async def get_campaigns(self) -> list[dict]:
        """Retrieve all phishing campaigns.

        Returns:
            A list of campaign dicts. Empty list on failure.
        """
        result = await self._request(
            "GET",
            "/api/campaigns/",
            params={"api_key": self.api_key} if self.api_key else None,
        )
        if result is None:
            logger.error("[gophish] Failed to fetch campaigns")
            return []

        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("campaigns", [])
        return []

    async def create_campaign(
        self,
        name: str,
        template_id: int,
        group_id: int,
        smtp_id: int,
        url: str,
    ) -> dict | None:
        """Create a new phishing simulation campaign.

        Args:
            name: Campaign display name.
            template_id: ID of the email template to use.
            group_id: ID of the target user group.
            smtp_id: ID of the sending SMTP profile.
            url: The phishing URL that recipients will be directed to.

        Returns:
            The created campaign dict, or *None* on failure.
        """
        payload = {
            "name": name,
            "template": {"id": template_id},
            "groups": [{"id": group_id}],
            "smtp": {"id": smtp_id},
            "url": url,
        }

        result = await self._request(
            "POST",
            "/api/campaigns/",
            json=payload,
            params={"api_key": self.api_key} if self.api_key else None,
        )
        if result is None:
            logger.error("[gophish] Failed to create campaign %s", name)
            return None

        logger.info(
            "[gophish] Created campaign %s (id=%s)",
            name,
            result.get("id") if isinstance(result, dict) else "unknown",
        )
        return result  # type: ignore[return-value]
