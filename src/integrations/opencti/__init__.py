"""OpenCTI integration — STIX 2.1 knowledge graph.

The legacy ``client.py`` is the original GraphQL stub. P2 #2.1 lives
in ``projection.py`` and is re-exported here so callers can write
``from src.integrations.opencti import project_ioc`` regardless of
where the function physically sits.
"""

from __future__ import annotations

from .projection import (
    GraphEdge,
    GraphNode,
    Neighbourhood,
    ProjectionResult,
    _stix_pattern_for,
    fetch_neighbourhood,
    get_client,
    is_configured,
    project_actor,
    project_alert,
    project_case,
    project_ioc,
    reset_client,
)

__all__ = [
    "GraphEdge",
    "GraphNode",
    "Neighbourhood",
    "ProjectionResult",
    "_stix_pattern_for",
    "fetch_neighbourhood",
    "get_client",
    "is_configured",
    "project_actor",
    "project_alert",
    "project_case",
    "project_ioc",
    "reset_client",
]
