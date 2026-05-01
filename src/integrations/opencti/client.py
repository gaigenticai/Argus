"""OpenCTI GraphQL API client for the Argus threat intelligence platform.

Connects to OpenCTI's GraphQL endpoint to pull/push STIX 2.1 indicators,
sightings, and other threat intelligence objects.
"""

from __future__ import annotations


import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from src.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GraphQL query / mutation fragments
# ---------------------------------------------------------------------------

_ABOUT_QUERY = """\
query {
  about {
    version
  }
}
"""

_INDICATORS_QUERY = """\
query Indicators($first: Int!, $after: ID, $filters: FilterGroup) {
  indicators(first: $first, after: $after, filters: $filters, orderBy: created_at, orderMode: desc) {
    pageInfo {
      hasNextPage
      endCursor
      globalCount
    }
    edges {
      node {
        id
        name
        description
        pattern
        pattern_type
        valid_from
        valid_until
        confidence
        created_at
        updated_at
        x_opencti_score
        indicator_types
        objectLabel {
          id
          value
          color
        }
        createdBy {
          id
          name
          entity_type
        }
      }
    }
  }
}
"""

_CREATE_INDICATOR_MUTATION = """\
mutation CreateIndicator($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) {
    id
    name
    pattern
    pattern_type
    confidence
    created_at
  }
}
"""

_CREATE_SIGHTING_MUTATION = """\
mutation CreateSighting($input: StixSightingRelationshipAddInput!) {
  stixSightingRelationshipAdd(input: $input) {
    id
    first_seen
    last_seen
    confidence
  }
}
"""

# ---------------------------------------------------------------------------
# STIX pattern helpers
# ---------------------------------------------------------------------------

_IOC_TYPE_TO_STIX_PATTERN: dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "filename": "[file:name = '{value}']",
}


def _build_stix_pattern(ioc_type: str, value: str) -> str:
    """Build a STIX 2.1 pattern string from an IOC type and value."""
    template = _IOC_TYPE_TO_STIX_PATTERN.get(ioc_type.lower())
    if template is None:
        raise ValueError(
            f"Unsupported IOC type '{ioc_type}'. "
            f"Supported: {', '.join(sorted(_IOC_TYPE_TO_STIX_PATTERN))}"
        )
    return template.format(value=value)


class OpenCTIClient(BaseIntegration):
    """OpenCTI GraphQL API integration.

    Provides bidirectional sync between Argus and an OpenCTI instance:
    - Pull STIX indicators, enrich Argus knowledge base
    - Push sightings and new indicators discovered by Argus detections
    """

    name = "opencti"
    display_name = "OpenCTI"
    description = "STIX 2.1 threat intelligence knowledge graph"
    category = "Threat Intelligence"

    # -----------------------------------------------------------------
    # Auth
    # -----------------------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        """OpenCTI authenticates via Bearer token."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Argus Threat Intelligence Platform",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    async def _graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict | None:
        """Execute a GraphQL request against OpenCTI.

        Returns the ``data`` dict on success, or *None* on transport /
        application error (errors are logged).
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        result = await self._request("POST", "/graphql", json=payload)

        if result is None:
            return None

        # GraphQL-level errors
        if isinstance(result, dict) and result.get("errors"):
            for err in result["errors"]:
                logger.error("[%s] GraphQL error: %s", self.name, err.get("message", err))
            return None

        return result.get("data") if isinstance(result, dict) else result

    # -----------------------------------------------------------------
    # Public API — connection test
    # -----------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Verify connectivity by querying the OpenCTI version."""
        data = await self._graphql(_ABOUT_QUERY)

        if data is None:
            return {"connected": False, "message": "Failed to reach OpenCTI GraphQL API"}

        version = data.get("about", {}).get("version", "unknown")
        logger.info("[%s] Connected — OpenCTI v%s", self.name, version)
        return {
            "connected": True,
            "message": f"OpenCTI v{version}",
            "version": version,
        }

    # -----------------------------------------------------------------
    # Public API — sync (pull recent indicators)
    # -----------------------------------------------------------------

    async def sync(self) -> dict:
        """Pull indicators created/updated in the last 24 hours.

        Returns a summary dict with counts and the raw indicator list.
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )

        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "created_at",
                    "values": [since],
                    "operator": "gte",
                    "mode": "or",
                }
            ],
            "filterGroups": [],
        }

        indicators: list[dict] = []
        after: str | None = None
        page = 0
        max_pages = 20  # safety cap

        while page < max_pages:
            variables: dict[str, Any] = {"first": 100, "filters": filters}
            if after:
                variables["after"] = after

            data = await self._graphql(_INDICATORS_QUERY, variables)
            if data is None:
                logger.warning("[%s] Sync interrupted at page %d", self.name, page)
                break

            container = data.get("indicators", {})
            edges = container.get("edges", [])
            page_info = container.get("pageInfo", {})

            for edge in edges:
                node = edge.get("node", {})
                indicators.append(self._normalize_indicator(node))

            if not page_info.get("hasNextPage"):
                break

            after = page_info.get("endCursor")
            page += 1

        total = len(indicators)
        logger.info("[%s] Sync complete — %d indicators pulled (last 24h)", self.name, total)
        return {
            "synced": True,
            "indicator_count": total,
            "indicators": indicators,
            "since": since,
        }

    # -----------------------------------------------------------------
    # Public API — push indicator
    # -----------------------------------------------------------------

    async def push_indicator(
        self,
        ioc_type: str,
        value: str,
        description: str = "",
        confidence: int = 50,
    ) -> dict | None:
        """Create a STIX Indicator in OpenCTI.

        Args:
            ioc_type: One of ipv4, ipv6, domain, url, email, md5, sha1, sha256, filename.
            value: The observable value (e.g. ``1.2.3.4``).
            description: Human-readable description.
            confidence: 0-100, default 50.

        Returns:
            Created indicator dict or *None* on failure.
        """
        pattern = _build_stix_pattern(ioc_type, value)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        variables = {
            "input": {
                "name": f"{ioc_type.upper()}: {value}",
                "description": description or f"Indicator pushed by Argus — {ioc_type}={value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "confidence": max(0, min(100, confidence)),
                "x_opencti_score": max(0, min(100, confidence)),
                "indicator_types": ["malicious-activity"],
            }
        }

        data = await self._graphql(_CREATE_INDICATOR_MUTATION, variables)
        if data is None:
            logger.error("[%s] Failed to push indicator %s=%s", self.name, ioc_type, value)
            return None

        created = data.get("indicatorAdd", {})
        logger.info("[%s] Pushed indicator id=%s pattern=%s", self.name, created.get("id"), pattern)
        return created

    # -----------------------------------------------------------------
    # Public API — push sighting
    # -----------------------------------------------------------------

    async def push_sighting(
        self,
        indicator_id: str,
        organization_name: str,
        confidence: int = 80,
    ) -> dict | None:
        """Create a Sighting linking an indicator to an organization.

        Args:
            indicator_id: OpenCTI internal id of the indicator.
            organization_name: Display name of the observing org.
            confidence: Sighting confidence 0-100.

        Returns:
            Created sighting dict or *None* on failure.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        variables = {
            "input": {
                "fromId": indicator_id,
                "toId": organization_name,  # can be org STIX id or name
                "first_seen": now,
                "last_seen": now,
                "confidence": max(0, min(100, confidence)),
                "description": f"Sighting reported by Argus at {organization_name}",
            }
        }

        data = await self._graphql(_CREATE_SIGHTING_MUTATION, variables)
        if data is None:
            logger.error(
                "[%s] Failed to push sighting for indicator=%s org=%s",
                self.name,
                indicator_id,
                organization_name,
            )
            return None

        sighting = data.get("stixSightingRelationshipAdd", {})
        logger.info("[%s] Pushed sighting id=%s", self.name, sighting.get("id"))
        return sighting

    # -----------------------------------------------------------------
    # Public API — paginated indicator query
    # -----------------------------------------------------------------

    async def query_indicators(
        self,
        limit: int = 50,
        after: str | None = None,
    ) -> dict | None:
        """Fetch a page of indicators.

        Args:
            limit: Number of indicators per page (max 500).
            after: Cursor for the next page.

        Returns:
            Dict with ``indicators`` list, ``page_info``, or *None* on error.
        """
        variables: dict[str, Any] = {"first": min(limit, 500)}
        if after:
            variables["after"] = after

        data = await self._graphql(_INDICATORS_QUERY, variables)
        if data is None:
            return None

        container = data.get("indicators", {})
        edges = container.get("edges", [])
        page_info = container.get("pageInfo", {})

        indicators = [self._normalize_indicator(e.get("node", {})) for e in edges]

        return {
            "indicators": indicators,
            "page_info": {
                "has_next_page": page_info.get("hasNextPage", False),
                "end_cursor": page_info.get("endCursor"),
                "total_count": page_info.get("globalCount"),
            },
        }

    # -----------------------------------------------------------------
    # Normalization
    # -----------------------------------------------------------------

    @staticmethod
    def _normalize_indicator(node: dict) -> dict:
        """Map an OpenCTI indicator node into a flat Argus-friendly dict."""
        return {
            "id": node.get("id"),
            "name": node.get("name"),
            "description": node.get("description"),
            "pattern": node.get("pattern"),
            "pattern_type": node.get("pattern_type"),
            "valid_from": node.get("valid_from"),
            "valid_until": node.get("valid_until"),
            "confidence": node.get("confidence"),
            "score": node.get("x_opencti_score"),
            "indicator_types": node.get("indicator_types", []),
            "labels": [
                lbl.get("value") for lbl in (node.get("objectLabel") or [])
            ],
            "created_by": (node.get("createdBy") or {}).get("name"),
            "created_at": node.get("created_at"),
            "updated_at": node.get("updated_at"),
            "source": "opencti",
        }
