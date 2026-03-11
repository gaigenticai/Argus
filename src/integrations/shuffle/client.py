"""Shuffle SOAR integration client."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)


class ShuffleIntegration(BaseIntegration):
    """Connects to Shuffle SOAR for workflow orchestration and automated response.

    Shuffle workflows can be triggered by Argus alerts to automate
    incident-response playbooks, enrichment, and notification pipelines.
    """

    name = "shuffle"
    display_name = "Shuffle SOAR"
    description = "Security orchestration, automation, and response"
    category = "SOAR"

    async def test_connection(self) -> dict:
        """Check Shuffle API health."""
        result = await self._request("GET", "/api/v1/health")
        if result is not None:
            return {
                "connected": True,
                "message": "Shuffle SOAR API is reachable",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return {
            "connected": False,
            "message": "Failed to reach Shuffle SOAR API",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def sync(self) -> dict:
        """List all workflows and return a summary."""
        workflows = await self.list_workflows()
        return {
            "synced": True,
            "total_workflows": len(workflows),
            "workflows": [
                {
                    "id": w.get("id"),
                    "name": w.get("name"),
                    "status": w.get("status"),
                    "is_valid": w.get("is_valid"),
                }
                for w in workflows
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def trigger_workflow(
        self,
        workflow_id: str,
        alert_data: dict,
    ) -> dict | None:
        """Trigger a Shuffle workflow with the supplied alert payload.

        Args:
            workflow_id: The target workflow's identifier.
            alert_data: Arbitrary alert/event data forwarded as the
                workflow's execution body.

        Returns:
            The Shuffle execution response dict, or *None* on failure.
        """
        result = await self._request(
            "POST",
            f"/api/v1/workflows/{workflow_id}/execute",
            json={"execution_argument": alert_data},
        )
        if result is None:
            logger.error(
                "[shuffle] Failed to trigger workflow %s",
                workflow_id,
            )
            return None

        logger.info(
            "[shuffle] Triggered workflow %s — execution: %s",
            workflow_id,
            result.get("execution_id", "unknown"),
        )
        return result  # type: ignore[return-value]

    async def list_workflows(self) -> list[dict]:
        """Retrieve all workflows from the Shuffle instance.

        Returns:
            A list of workflow dicts. Empty list on failure.
        """
        result = await self._request("GET", "/api/v1/workflows")
        if result is None:
            logger.error("[shuffle] Failed to fetch workflows")
            return []

        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("workflows", []))
        return []
