"""Attack surface discovery — subdomain enumeration and service detection.

Uses passive techniques (DNS, certificate transparency logs) to discover
an organization's public-facing assets without active scanning.
"""

import asyncio
import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any

import aiohttp

from src.models.threat import SourceType
from src.crawlers.base import CrawlResult

from src.core.activity import ActivityType, emit as activity_emit

logger = logging.getLogger(__name__)


class SurfaceScanner:
    """Discovers public-facing assets for an organization."""

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session

    async def discover_subdomains(self, domain: str) -> list[dict[str, Any]]:
        """Discover subdomains using passive sources."""
        await activity_emit(
            ActivityType.SCAN_START,
            "surface_scanner",
            f"Starting subdomain discovery for {domain}",
            {"domain": domain, "scan_type": "subdomain_enum"},
        )

        subdomains = set()

        # Certificate Transparency logs via crt.sh
        ct_subs = await self._crtsh_lookup(domain)
        subdomains.update(ct_subs)

        results = []
        for sub in sorted(subdomains):
            ip = await self._resolve_dns(sub)
            results.append({
                "subdomain": sub,
                "ip": ip,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            })
            await activity_emit(
                ActivityType.SCAN_SUBDOMAIN,
                "surface_scanner",
                f"Found subdomain: {sub}" + (f" → {ip}" if ip else ""),
                {"subdomain": sub, "ip": ip, "domain": domain},
            )

        await activity_emit(
            ActivityType.SCAN_COMPLETE,
            "surface_scanner",
            f"Subdomain scan complete for {domain} — {len(results)} found",
            {"domain": domain, "count": len(results)},
        )

        logger.info(f"[surface] Discovered {len(results)} subdomains for {domain}")
        return results

    async def _crtsh_lookup(self, domain: str) -> set[str]:
        """Query crt.sh certificate transparency logs."""
        subdomains = set()
        session = await self._get_session()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return subdomains

                data = await resp.json(content_type=None)
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.endswith(f".{domain}") or name == domain:
                            # Skip wildcards
                            if not name.startswith("*"):
                                subdomains.add(name)
        except Exception as e:
            logger.error(f"[surface] crt.sh lookup failed for {domain}: {e}")

        return subdomains

    async def _resolve_dns(self, hostname: str) -> str | None:
        """Resolve a hostname to IP."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(hostname, None, socket.AF_INET)
            if result:
                return result[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return None

    async def check_common_exposures(self, domain: str) -> list[CrawlResult]:
        """Check for common misconfigurations on a domain."""
        await activity_emit(
            ActivityType.SCAN_START,
            "surface_scanner",
            f"Starting exposure check on {domain}",
            {"domain": domain, "scan_type": "exposure_check"},
        )

        results = []
        session = await self._get_session()

        checks = [
            ("/.env", "Environment file exposed"),
            ("/.git/config", "Git repository exposed"),
            ("/robots.txt", None),  # Just collect, not necessarily an exposure
            ("/.well-known/security.txt", None),
            ("/wp-admin/", "WordPress admin panel exposed"),
            ("/phpinfo.php", "PHP info page exposed"),
            ("/server-status", "Apache server-status exposed"),
            ("/debug", "Debug endpoint exposed"),
            ("/.aws/credentials", "AWS credentials file exposed"),
            ("/api/swagger.json", "API documentation exposed"),
            ("/graphql", "GraphQL endpoint exposed"),
        ]

        for path, issue_desc in checks:
            try:
                url = f"https://{domain}{path}"
                async with session.get(url, allow_redirects=False, ssl=False) as resp:
                    if resp.status == 200 and issue_desc:
                        body = await resp.text()
                        # Verify it's not a generic 404/error page
                        if len(body) > 50 and "not found" not in body.lower()[:200]:
                            results.append(CrawlResult(
                                source_type=SourceType.SURFACE_WEB,
                                source_url=url,
                                source_name="surface_scanner",
                                title=issue_desc,
                                content=f"Exposure found: {issue_desc}\nURL: {url}\nResponse size: {len(body)} bytes",
                                raw_data={
                                    "check": path,
                                    "issue": issue_desc,
                                    "status_code": resp.status,
                                    "response_size": len(body),
                                },
                            ))
                            logger.warning(f"[surface] {issue_desc} at {url}")
                            await activity_emit(
                                ActivityType.SCAN_EXPOSURE,
                                "surface_scanner",
                                f"Exposure found: {issue_desc} at {url}",
                                {"url": url, "issue": issue_desc, "status": resp.status, "size": len(body)},
                                severity="warning",
                            )
            except Exception:
                pass  # Connection errors are expected for most checks

        await activity_emit(
            ActivityType.SCAN_COMPLETE,
            "surface_scanner",
            f"Exposure check complete for {domain} — {len(results)} issues found",
            {"domain": domain, "exposures": len(results)},
        )

        return results

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
