"""Attack surface discovery — subdomain enumeration and service detection.

Uses passive techniques (DNS, certificate transparency logs) to discover
an organization's public-facing assets without active scanning.
"""

from __future__ import annotations


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
        # Per-run error trail. Caller resets via :meth:`reset_errors`
        # before each scan and reads the list afterwards so the API
        # can return ``scan_status="partial"`` instead of pretending
        # an empty result was a clean scan. Each entry is a short
        # human-readable string suitable for surfacing in the UI.
        self.last_errors: list[str] = []

    def reset_errors(self) -> None:
        self.last_errors = []

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
        """Query crt.sh certificate transparency logs.

        Failures are appended to ``self.last_errors`` so the caller can
        distinguish "crt.sh ran clean and saw nothing" from "crt.sh was
        unreachable / rate-limited" and surface that to the analyst.

        Adversarial audit D-17 — wrap in the shared per-host circuit
        breaker so a crt.sh outage doesn't keep stalling subdomain
        discovery; while the breaker is open we record the error and
        return empty.
        """
        from src.core.http_circuit import CircuitBreakerOpenError, get_breaker

        subdomains = set()
        breaker = get_breaker("enrich:crtsh")
        try:
            async with breaker:
                pass
        except CircuitBreakerOpenError:
            self.last_errors.append("crt.sh circuit OPEN — skipping lookup")
            return subdomains

        session = await self._get_session()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url) as resp:
                if resp.status != 200:
                    self.last_errors.append(
                        f"crt.sh returned HTTP {resp.status} for {domain}"
                    )
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
            self.last_errors.append(
                f"crt.sh unreachable for {domain}: {type(e).__name__}: {e}"[:300]
            )

        return subdomains

    async def _resolve_dns(self, hostname: str) -> str | None:
        """Resolve a hostname to IP."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(hostname, None, socket.AF_INET)
            if result:
                return result[0][4][0]
        except (socket.gaierror, OSError) as exc:
            logger.debug(
                "DNS resolve failed for %s: %s: %s",
                hostname, type(exc).__name__, exc,
            )
        return None

    async def check_common_exposures(self, domain: str) -> list[CrawlResult]:
        """Check for common misconfigurations on a domain.

        Returns a CrawlResult for every probe — whether it found an
        exposure, came back clean, or was unreachable. The Gemini
        audit (G3) called out the silent ``pass`` on connection
        errors as a deal-killer: an analyst staring at "0 exposures"
        had no way to tell the scanner ran clean from "the target
        was down". Now an unreachable target produces a
        ``surface.unreachable`` finding with the exact failure mode
        attached, so the dashboard can render "scan attempted, target
        offline" instead of pretending nothing happened.
        """
        await activity_emit(
            ActivityType.SCAN_START,
            "surface_scanner",
            f"Starting exposure check on {domain}",
            {"domain": domain, "scan_type": "exposure_check"},
        )

        results = []
        unreachable_count = 0
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
            url = f"https://{domain}{path}"
            try:
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
                                content=(
                                    f"Exposure found: {issue_desc}\n"
                                    f"URL: {url}\n"
                                    f"Response size: {len(body)} bytes"
                                ),
                                raw_data={
                                    "check": path,
                                    "issue": issue_desc,
                                    "status_code": resp.status,
                                    "response_size": len(body),
                                    "outcome": "exposed",
                                },
                            ))
                            logger.warning("[surface] %s at %s", issue_desc, url)
                            await activity_emit(
                                ActivityType.SCAN_EXPOSURE,
                                "surface_scanner",
                                f"Exposure found: {issue_desc} at {url}",
                                {
                                    "url": url, "issue": issue_desc,
                                    "status": resp.status, "size": len(body),
                                },
                                severity="warning",
                            )
            except (
                aiohttp.ClientConnectorError,
                aiohttp.ClientConnectionError,
                aiohttp.ServerDisconnectedError,
                aiohttp.ServerTimeoutError,
                asyncio.TimeoutError,
                OSError,
            ) as exc:
                # G3 fix: surface unreachable targets as findings rather
                # than silently passing. We tag them ``outcome="unreachable"``
                # so the analyst can distinguish "we checked /.env and the
                # site is down" from "we checked /.env and it's not
                # exposed". The first probe that fails records the
                # finding; subsequent fails for the same domain just
                # increment the count to avoid spamming the SOC.
                unreachable_count += 1
                if unreachable_count == 1:
                    results.append(CrawlResult(
                        source_type=SourceType.SURFACE_WEB,
                        source_url=url,
                        source_name="surface_scanner",
                        title=f"Surface scan target unreachable: {domain}",
                        content=(
                            f"Surface scanner could not reach {domain}.\n"
                            f"First failed probe: {url}\n"
                            f"Failure mode: {type(exc).__name__}: {exc}\n\n"
                            f"This may be a transient network issue, a "
                            f"firewall blocking the scanner, or a real "
                            f"outage. Re-run the scan to confirm."
                        ),
                        raw_data={
                            "check": path,
                            "issue": "target_unreachable",
                            "exception_type": type(exc).__name__,
                            "exception_message": str(exc)[:500],
                            "outcome": "unreachable",
                        },
                    ))
                    await activity_emit(
                        ActivityType.SCAN_EXPOSURE,
                        "surface_scanner",
                        f"Target unreachable during scan: {domain}",
                        {
                            "url": url,
                            "exception": type(exc).__name__,
                            "message": str(exc)[:200],
                            "outcome": "unreachable",
                        },
                        severity="warning",
                    )
                logger.info(
                    "[surface] unreachable %s: %s: %s",
                    url, type(exc).__name__, exc,
                )

        await activity_emit(
            ActivityType.SCAN_COMPLETE,
            "surface_scanner",
            (
                f"Exposure check complete for {domain} — "
                f"{len(results)} finding(s), {unreachable_count} unreachable probe(s)"
            ),
            {
                "domain": domain,
                "exposures": len(results),
                "unreachable_probes": unreachable_count,
                "checks_attempted": len(checks),
            },
        )

        return results

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
