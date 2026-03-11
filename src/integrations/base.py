"""Base integration class — all external tool connectors inherit from this."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import aiohttp

logger = logging.getLogger(__name__)


class BaseIntegration(ABC):
    """Abstract base for all external tool integrations.

    Each integration connects to an external security tool's API
    and syncs data bidirectionally with Argus.
    """

    name: str = "unknown"
    display_name: str = "Unknown"
    description: str = ""
    category: str = "other"

    def __init__(self, api_url: str, api_key: str | None = None, **kwargs):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._session: aiohttp.ClientSession | None = None
        self._config = kwargs

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = self._build_headers()
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60),
                headers=headers,
            )
        return self._session

    def _build_headers(self) -> dict[str, str]:
        """Build default headers. Override in subclasses for custom auth."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Argus Threat Intelligence Platform",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        json: dict | list | None = None,
        params: dict | None = None,
    ) -> dict | list | None:
        """Make an HTTP request to the integration's API."""
        session = await self._get_session()
        url = f"{self.api_url}{path}"

        try:
            async with session.request(method, url, json=json, params=params) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    logger.error("[%s] %s %s → %d: %s", self.name, method, path, resp.status, body[:200])
                    return None
                if resp.status == 204:
                    return {}
                return await resp.json()
        except Exception as e:
            logger.error("[%s] Request failed %s %s: %s", self.name, method, path, e)
            return None

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test connectivity to the external tool.

        Returns dict with at least: {"connected": bool, "message": str}
        """
        ...

    @abstractmethod
    async def sync(self) -> dict:
        """Run a full sync cycle. Returns summary dict."""
        ...

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
