"""TAXII 2.1 compatible endpoints for STIX object exchange."""

from __future__ import annotations


import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser
from src.models.intel import IOC, ThreatActor, ActorSighting
from src.models.threat import Alert
from src.storage.database import get_session

router = APIRouter(prefix="/taxii", tags=["Threat Intelligence"])

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ARGUS_IDENTITY_ID = "identity--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"

_COLLECTIONS = {
    "indicators": {
        "id": "collection--01",
        "title": "Argus Indicators",
        "description": "IOC-derived STIX Indicator objects",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "threat-actors": {
        "id": "collection--02",
        "title": "Argus Threat Actors",
        "description": "Tracked threat actor SDOs",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    "alerts": {
        "id": "collection--03",
        "title": "Argus Alerts",
        "description": "Alert-derived STIX Indicator objects",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
}

_COLLECTION_IDS = {v["id"]: k for k, v in _COLLECTIONS.items()}


# ---------------------------------------------------------------------------
# STIX object builders
# ---------------------------------------------------------------------------


def _stix_identity() -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _ARGUS_IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Argus Threat Intelligence Platform",
        "identity_class": "system",
    }


def _ts(dt: datetime | None) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ioc_to_stix_pattern(ioc_type: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    mapping = {
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "ipv6": f"[ipv6-addr:value = '{escaped}']",
        "cidr": f"[ipv4-addr:value = '{escaped}']",
        "domain": f"[domain-name:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
        "email": f"[email-addr:value = '{escaped}']",
        "md5": f"[file:hashes.MD5 = '{escaped}']",
        "sha1": f"[file:hashes.'SHA-1' = '{escaped}']",
        "sha256": f"[file:hashes.'SHA-256' = '{escaped}']",
        "btc_address": f"[artifact:payload_bin = '{escaped}']",
        "xmr_address": f"[artifact:payload_bin = '{escaped}']",
        "cve": f"[vulnerability:name = '{escaped}']",
        "ja3": f"[network-traffic:extensions.'http-request-ext'.request_header.'JA3' = '{escaped}']",
        "filename": f"[file:name = '{escaped}']",
        "registry_key": f"[windows-registry-key:key = '{escaped}']",
        "mutex": f"[mutex:name = '{escaped}']",
        "user_agent": f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{escaped}']",
        "asn": f"[autonomous-system:number = {value}]",
    }
    return mapping.get(ioc_type, f"[artifact:payload_bin = '{escaped}']")


def _ioc_to_stix(ioc: IOC) -> dict:
    pattern = _ioc_to_stix_pattern(ioc.ioc_type, ioc.value)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{ioc.id}",
        "created": _ts(ioc.created_at),
        "modified": _ts(ioc.updated_at),
        "name": f"{ioc.ioc_type}: {ioc.value}",
        "description": f"IOC observed {ioc.sighting_count} time(s). Confidence: {ioc.confidence}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _ts(ioc.first_seen),
        "indicator_types": ["malicious-activity"],
        "confidence": int(ioc.confidence * 100),
        "created_by_ref": _ARGUS_IDENTITY_ID,
    }


def _actor_to_stix(actor: ThreatActor) -> dict:
    """Convert a ThreatActor model to a STIX 2.1 threat-actor SDO."""
    sophistication = "none"
    if actor.risk_score >= 75:
        sophistication = "expert"
    elif actor.risk_score >= 50:
        sophistication = "advanced"
    elif actor.risk_score >= 25:
        sophistication = "intermediate"
    elif actor.risk_score >= 10:
        sophistication = "minimal"

    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": f"threat-actor--{actor.id}",
        "created": _ts(actor.created_at),
        "modified": _ts(actor.updated_at),
        "name": actor.primary_alias,
        "description": actor.description or f"Threat actor tracked as {actor.primary_alias}",
        "aliases": actor.aliases or [],
        "first_seen": _ts(actor.first_seen),
        "last_seen": _ts(actor.last_seen),
        "sophistication": sophistication,
        "threat_actor_types": ["criminal"],
        "created_by_ref": _ARGUS_IDENTITY_ID,
    }


def _actor_ioc_relationship(actor_id: uuid.UUID, ioc_id: uuid.UUID) -> dict:
    """Create a STIX relationship SRO linking a threat-actor to an indicator."""
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "created": _ts(datetime.now(timezone.utc)),
        "modified": _ts(datetime.now(timezone.utc)),
        "relationship_type": "indicates",
        "source_ref": f"indicator--{ioc_id}",
        "target_ref": f"threat-actor--{actor_id}",
        "created_by_ref": _ARGUS_IDENTITY_ID,
    }


def _alert_to_stix(alert: Alert) -> dict:
    """Convert an Alert to a STIX 2.1 indicator SDO."""
    # Build a pattern from matched entities if available
    pattern = "[artifact:payload_bin = 'alert']"
    if alert.matched_entities:
        entities = alert.matched_entities
        if isinstance(entities, dict):
            for key, val in entities.items():
                if key == "domain" and val:
                    pattern = f"[domain-name:value = '{val}']"
                    break
                if key == "ip" and val:
                    pattern = f"[ipv4-addr:value = '{val}']"
                    break

    severity_to_confidence = {
        "critical": 95,
        "high": 80,
        "medium": 60,
        "low": 40,
        "info": 20,
    }

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{alert.id}",
        "created": _ts(alert.created_at),
        "modified": _ts(alert.updated_at),
        "name": alert.title,
        "description": alert.summary,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _ts(alert.created_at),
        "indicator_types": [_category_to_indicator_type(alert.category)],
        "confidence": severity_to_confidence.get(alert.severity, 50),
        "labels": [alert.category, alert.severity],
        "created_by_ref": _ARGUS_IDENTITY_ID,
    }


def _category_to_indicator_type(category: str) -> str:
    mapping = {
        "credential_leak": "compromised",
        "data_breach": "compromised",
        "stealer_log": "compromised",
        "ransomware": "malicious-activity",
        "ransomware_victim": "malicious-activity",
        "access_sale": "malicious-activity",
        "exploit": "malicious-activity",
        "phishing": "malicious-activity",
        "impersonation": "anomalous-activity",
        "doxxing": "anomalous-activity",
        "insider_threat": "anomalous-activity",
        "brand_abuse": "anomalous-activity",
        "dark_web_mention": "benign",
        "underground_chatter": "benign",
        "initial_access": "malicious-activity",
    }
    return mapping.get(category, "unknown")


def _taxii_response(content: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(
        content=content,
        status_code=status,
        media_type="application/taxii+json;version=2.1",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/")
async def taxii_discovery():
    """TAXII 2.1 discovery endpoint."""
    return _taxii_response({
        "title": "Argus TAXII Server",
        "description": "TAXII 2.1 interface for Argus Threat Intelligence Platform",
        "default": "/api/v1/taxii/",
        "api_roots": ["/api/v1/taxii/"],
    })


@router.get("/collections/")
async def list_collections():
    """List all available STIX collections."""
    collections = []
    for key, col in _COLLECTIONS.items():
        collections.append(col)
    return _taxii_response({"collections": collections})


@router.get("/collections/{collection_id}/objects")
async def get_collection_objects(
    collection_id: str,
    analyst: AnalystUser,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    added_after: datetime | None = None,
    db: AsyncSession = Depends(get_session),
):
    """Get STIX objects from a collection with pagination."""
    collection_key = _COLLECTION_IDS.get(collection_id)
    if not collection_key:
        raise HTTPException(404, f"Collection {collection_id} not found")

    objects = [_stix_identity()]

    if collection_key == "indicators":
        query = select(IOC).order_by(desc(IOC.created_at))
        if added_after:
            query = query.where(IOC.created_at > added_after)
        query = query.offset(offset).limit(limit)
        result = await db.execute(query)
        iocs = result.scalars().all()

        for ioc in iocs:
            objects.append(_ioc_to_stix(ioc))
            # Add relationship if IOC is linked to an actor
            if ioc.threat_actor_id:
                objects.append(_actor_ioc_relationship(ioc.threat_actor_id, ioc.id))

    elif collection_key == "threat-actors":
        query = select(ThreatActor).order_by(desc(ThreatActor.created_at))
        if added_after:
            query = query.where(ThreatActor.created_at > added_after)
        query = query.offset(offset).limit(limit)
        result = await db.execute(query)
        actors = result.scalars().all()

        for actor in actors:
            objects.append(_actor_to_stix(actor))

            # Add linked IOCs as indicators + relationships
            ioc_result = await db.execute(
                select(IOC).where(IOC.threat_actor_id == actor.id)
            )
            for ioc in ioc_result.scalars().all():
                objects.append(_ioc_to_stix(ioc))
                objects.append(_actor_ioc_relationship(actor.id, ioc.id))

    elif collection_key == "alerts":
        query = select(Alert).order_by(desc(Alert.created_at))
        if added_after:
            query = query.where(Alert.created_at > added_after)
        query = query.offset(offset).limit(limit)
        result = await db.execute(query)
        alerts = result.scalars().all()

        for alert in alerts:
            objects.append(_alert_to_stix(alert))

    # Count total for this collection
    total = len(objects) - 1  # exclude identity

    envelope = {
        "more": total >= limit,
        "objects": objects,
    }

    return _taxii_response(envelope)


@router.get("/collections/{collection_id}/objects/{object_id}")
async def get_collection_object(
    collection_id: str,
    object_id: str,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Get a single STIX object by its ID."""
    collection_key = _COLLECTION_IDS.get(collection_id)
    if not collection_key:
        raise HTTPException(404, f"Collection {collection_id} not found")

    # Parse the STIX ID to extract type and UUID
    parts = object_id.split("--", 1)
    if len(parts) != 2:
        raise HTTPException(400, f"Invalid STIX ID format: {object_id}")

    stix_type, raw_uuid = parts
    try:
        obj_uuid = uuid.UUID(raw_uuid)
    except ValueError:
        raise HTTPException(400, f"Invalid UUID in STIX ID: {object_id}")

    stix_object = None

    if stix_type == "indicator":
        if collection_key == "indicators":
            ioc = await db.get(IOC, obj_uuid)
            if ioc:
                stix_object = _ioc_to_stix(ioc)
        elif collection_key == "alerts":
            alert = await db.get(Alert, obj_uuid)
            if alert:
                stix_object = _alert_to_stix(alert)

    elif stix_type == "threat-actor":
        if collection_key == "threat-actors":
            actor = await db.get(ThreatActor, obj_uuid)
            if actor:
                stix_object = _actor_to_stix(actor)

    elif stix_type == "identity" and raw_uuid == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d":
        stix_object = _stix_identity()

    if not stix_object:
        raise HTTPException(404, f"Object {object_id} not found in collection {collection_id}")

    return _taxii_response(stix_object)
