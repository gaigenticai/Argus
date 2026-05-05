"""Tamper-evident Merkle audit chain for the Evidence Vault.

Each :class:`EvidenceAuditChain` row carries a ``payload_hash`` (SHA-256
over the canonical JSON event) and a ``chain_hash``
(SHA-256(prev_chain_hash || payload_hash)). Verification walks the
chain in ``sequence`` order and re-derives every hash; a single
mutated row breaks the chain at that sequence and forwards.

Why a per-org chain rather than a single global chain?
    Tenants must be able to export *their* evidence trail without
    leaking another tenant's hash sequence. Each org keeps its own
    head, so cross-tenant reads never need to traverse other orgs'
    rows.

The helper here is deliberately small: it owns hashing + persistence
and nothing else. The route layer decides *what* to log; the agent
layer decides *when* to verify.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.evidence_audit import EvidenceAuditChain

_logger = logging.getLogger(__name__)


def _canonical_json(payload: dict[str, Any]) -> str:
    """Stable JSON encoding used for hashing.

    UUIDs / datetimes are coerced to their ``str`` form so the hash is
    reproducible across Python versions. ``sort_keys`` guarantees that
    payloads with reordered keys still hash identically.
    """

    def _default(o: Any) -> Any:
        if isinstance(o, (uuid.UUID,)):
            return str(o)
        if isinstance(o, datetime):
            # Always serialise UTC ISO-8601 to remove tzinfo ambiguity.
            return o.astimezone(timezone.utc).isoformat()
        if isinstance(o, bytes):
            return o.hex()
        raise TypeError(f"unhashable type for audit payload: {type(o).__name__}")

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=_default,
        ensure_ascii=False,
    )


def _hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _chain(prev: str | None, payload_hash: str) -> str:
    seed = (prev or "") + payload_hash
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


async def record_audit(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    evidence_blob_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    action: str,
    payload: dict[str, Any],
) -> EvidenceAuditChain:
    """Append a tamper-evident audit row for *organization_id*.

    Reads the previous chain head for the same org under the caller's
    transaction. The dispatcher locks the row via ``with_for_update``
    on the chain head when this is called from a concurrent context;
    for the single-writer API path that's not required because the
    enclosing endpoint runs in serial.
    """
    # Find the previous head for this org (highest sequence). NULL org
    # rows form their own chain — unusual, but we tolerate it.
    head_stmt = (
        select(EvidenceAuditChain)
        .where(EvidenceAuditChain.organization_id == organization_id)
        .order_by(desc(EvidenceAuditChain.sequence))
        .limit(1)
    )
    head = (await db.execute(head_stmt)).scalar_one_or_none()
    prev_chain_hash = head.chain_hash if head is not None else None

    payload_hash = _hash_payload(payload)
    chain_hash = _chain(prev_chain_hash, payload_hash)

    row = EvidenceAuditChain(
        organization_id=organization_id,
        evidence_blob_id=evidence_blob_id,
        actor_user_id=actor_user_id,
        action=action,
        payload=payload,
        payload_hash=payload_hash,
        prev_chain_hash=prev_chain_hash,
        chain_hash=chain_hash,
    )
    db.add(row)
    await db.flush()
    return row


async def verify_chain(
    db: AsyncSession, *, organization_id: uuid.UUID
) -> dict[str, Any]:
    """Walk the org's chain in sequence order and re-derive every hash.

    Returns a structured verdict::

        {
            "valid": bool,
            "broken_at_sequence": int | None,
            "total_rows": int,
            "head_chain_hash": str | None,
        }

    On the first hash mismatch, ``broken_at_sequence`` carries the row's
    ``sequence`` and ``valid`` flips to False. Subsequent rows are not
    inspected — once the chain is broken the rest is by definition
    untrusted.
    """
    rows_stmt = (
        select(EvidenceAuditChain)
        .where(EvidenceAuditChain.organization_id == organization_id)
        .order_by(EvidenceAuditChain.sequence.asc())
    )
    rows = (await db.execute(rows_stmt)).scalars().all()
    prev: str | None = None
    for row in rows:
        expected_payload_hash = _hash_payload(row.payload or {})
        expected_chain_hash = _chain(prev, expected_payload_hash)
        if (
            row.payload_hash != expected_payload_hash
            or row.chain_hash != expected_chain_hash
            or (row.prev_chain_hash or None) != prev
        ):
            return {
                "valid": False,
                "broken_at_sequence": int(row.sequence),
                "total_rows": len(rows),
                "head_chain_hash": rows[-1].chain_hash if rows else None,
            }
        prev = row.chain_hash
    return {
        "valid": True,
        "broken_at_sequence": None,
        "total_rows": len(rows),
        "head_chain_hash": rows[-1].chain_hash if rows else None,
    }


__all__ = ["record_audit", "verify_chain"]
