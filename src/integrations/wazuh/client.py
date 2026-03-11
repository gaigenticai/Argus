"""Wazuh Manager REST API client for the Argus threat intelligence platform.

Connects to Wazuh's RESTful API to pull alerts, agent status, and
vulnerability data for correlation with Argus threat intelligence.
"""

import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

from src.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)


class WazuhClient(BaseIntegration):
    """Wazuh Manager REST API integration.

    Wazuh uses JWT authentication: the client first authenticates with
    basic auth credentials to obtain a short-lived token, then includes
    that token in subsequent requests.

    The ``api_key`` parameter is expected in ``user:password`` format.
    """

    name = "wazuh"
    display_name = "Wazuh"
    description = "SIEM and EDR platform for threat detection and compliance"
    category = "SIEM / EDR"

    def __init__(self, api_url: str, api_key: str | None = None, **kwargs):
        super().__init__(api_url, api_key, **kwargs)
        self._jwt_token: str | None = None

    # -----------------------------------------------------------------
    # Auth — JWT-based, NOT static Bearer
    # -----------------------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        """Build request headers.

        On the very first call (before JWT is obtained) we return headers
        without Authorization.  After ``_authenticate()`` succeeds, the
        JWT is injected into every subsequent request via
        ``_ensure_authenticated``.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Argus Threat Intelligence Platform",
        }
        if self._jwt_token:
            headers["Authorization"] = f"Bearer {self._jwt_token}"
        return headers

    def _parse_credentials(self) -> tuple[str, str]:
        """Extract (username, password) from ``api_key`` ('user:password')."""
        if not self.api_key or ":" not in self.api_key:
            raise ValueError(
                "Wazuh api_key must be in 'username:password' format"
            )
        user, _, password = self.api_key.partition(":")
        return user, password

    async def _authenticate(self) -> bool:
        """Authenticate against Wazuh and store the JWT token.

        POST /security/user/authenticate with HTTP Basic Auth.
        Returns True on success, False on failure.
        """
        user, password = self._parse_credentials()
        basic = base64.b64encode(f"{user}:{password}".encode()).decode()

        url = f"{self.api_url}/security/user/authenticate"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Basic {basic}",
            "User-Agent": "Argus Threat Intelligence Platform",
        }

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.post(url, headers=headers) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(
                            "[%s] Authentication failed (%d): %s",
                            self.name,
                            resp.status,
                            body[:200],
                        )
                        self._jwt_token = None
                        return False

                    data = await resp.json()
                    token = data.get("data", {}).get("token")
                    if not token:
                        logger.error("[%s] No token in auth response", self.name)
                        self._jwt_token = None
                        return False

                    self._jwt_token = token
                    logger.info("[%s] Authenticated successfully", self.name)
                    return True

        except Exception as exc:
            logger.error("[%s] Authentication error: %s", self.name, exc)
            self._jwt_token = None
            return False

    async def _ensure_authenticated(self) -> bool:
        """Authenticate if no JWT is cached, then refresh the session headers."""
        if self._jwt_token is None:
            ok = await self._authenticate()
            if not ok:
                return False

        # Rebuild session with updated JWT headers so _request picks them up.
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

        return True

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    async def _authed_request(
        self,
        method: str,
        path: str,
        json: dict | list | None = None,
        params: dict | None = None,
    ) -> dict | list | None:
        """Wrapper around ``_request`` that ensures valid JWT first."""
        if not await self._ensure_authenticated():
            return None
        return await self._request(method, path, json=json, params=params)

    # -----------------------------------------------------------------
    # Public API — connection test
    # -----------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Authenticate and fetch manager info to verify connectivity."""
        data = await self._authed_request("GET", "/manager/info")

        if data is None:
            return {
                "connected": False,
                "message": "Failed to connect to Wazuh Manager API",
            }

        info = data.get("data", {}).get("affected_items", [{}])[0] if isinstance(data, dict) else {}
        version = info.get("version", "unknown")
        manager_name = info.get("name", "unknown")

        logger.info(
            "[%s] Connected — Wazuh %s (manager: %s)",
            self.name,
            version,
            manager_name,
        )
        return {
            "connected": True,
            "message": f"Wazuh {version} — manager '{manager_name}'",
            "version": version,
            "manager_name": manager_name,
        }

    # -----------------------------------------------------------------
    # Public API — sync (alerts + agents)
    # -----------------------------------------------------------------

    async def sync(self) -> dict:
        """Pull recent alerts (last 1 hour) and all agents.

        Returns a summary dict with counts and raw data.
        """
        alerts_result = await self.get_alerts(limit=500)
        agents_result = await self.get_agents(limit=500)

        alerts = self._extract_items(alerts_result)
        agents = self._extract_items(agents_result)

        logger.info(
            "[%s] Sync complete — %d alerts, %d agents",
            self.name,
            len(alerts),
            len(agents),
        )
        return {
            "synced": True,
            "alert_count": len(alerts),
            "agent_count": len(agents),
            "alerts": alerts,
            "agents": agents,
        }

    # -----------------------------------------------------------------
    # Public API — agents
    # -----------------------------------------------------------------

    async def get_agents(self, limit: int = 500) -> dict | None:
        """List agents sorted by most-recently-seen first.

        Args:
            limit: Maximum number of agents to return.

        Returns:
            Raw Wazuh API response dict or *None* on error.
        """
        params: dict[str, Any] = {
            "limit": min(limit, 500),
            "sort": "-lastKeepAlive",
        }
        return await self._authed_request("GET", "/agents", params=params)

    # -----------------------------------------------------------------
    # Public API — alerts
    # -----------------------------------------------------------------

    async def get_alerts(
        self,
        limit: int = 500,
        offset: int = 0,
    ) -> dict | None:
        """Fetch recent alerts.

        Args:
            limit: Maximum alerts per request.
            offset: Pagination offset.

        Returns:
            Raw Wazuh API response dict or *None* on error.
        """
        params: dict[str, Any] = {
            "limit": min(limit, 500),
            "offset": offset,
            "sort": "-timestamp",
        }
        return await self._authed_request("GET", "/alerts", params=params)

    # -----------------------------------------------------------------
    # Public API — vulnerabilities
    # -----------------------------------------------------------------

    async def get_vulnerabilities(self, agent_id: str) -> dict | None:
        """Fetch known vulnerabilities for a specific agent.

        Args:
            agent_id: The Wazuh agent ID (e.g. ``"001"``).

        Returns:
            Raw Wazuh API response dict or *None* on error.
        """
        if not agent_id:
            raise ValueError("agent_id is required")

        return await self._authed_request("GET", f"/vulnerability/{agent_id}")

    # -----------------------------------------------------------------
    # Normalization helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _extract_items(response: dict | list | None) -> list[dict]:
        """Safely pull ``data.affected_items`` from a Wazuh API response."""
        if response is None or not isinstance(response, dict):
            return []
        return response.get("data", {}).get("affected_items", [])
