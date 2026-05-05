"""Evidence Vault — agentic Bridge-LLM handlers.

Four agents power the vault:

    1. ``evidence_summarise`` (Artefact Summariser)
       Triggered by upload. Pulls the blob bytes from MinIO, extracts
       text where possible (PDF / HTML / image-OCR / plain), then asks
       the Bridge LLM for a 5-bullet summary, IOC list, PII categories,
       and classification. Persists into ``EvidenceBlob.agent_summary``.

    2. ``evidence_iocs`` (IOC Auto-extractor)
       Chained from the summariser. Re-scans extracted text + the
       summariser's IOC list with regex; upserts each unique IOC into
       the ``iocs`` table; persists linked IOC IDs back into
       ``agent_summary``.

    3. Chain-of-custody narrator
       Triggered on demand by ``POST /evidence/{id}/narrate-coc``.
       Reads the audit chain, blob metadata, uploader, and asks Bridge
       for a court-ready Markdown narrative. The route layer caches
       the result on the blob row.

    4. ``evidence_similar`` (Similar-Artefact Finder)
       Triggered by ``GET /evidence/{id}/similar``. Computes the
       perceptual / ssdeep digest if the lib is installed; finds
       Hamming-distance / prefix-distance neighbours; optionally asks
       Bridge to summarise how the cluster relates.

External libs are best-effort imports — when ``imagehash``,
``pytesseract``, ``ssdeep``, or ``pypdf`` aren't installed we degrade
gracefully (text from BeautifulSoup / latin-1 fallback). No agent ever
fails an upload.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.llm.agent_queue import call_bridge, enqueue, register_handler
from src.models.agent_task import AgentTask
from src.models.evidence import EvidenceBlob
from src.models.evidence_audit import EvidenceAuditChain
from src.models.intel import IOC, IOCType
from src.storage import evidence_store

_logger = logging.getLogger(__name__)

# How much extracted text we keep on the row. Storing more than this
# bloats Postgres and rarely helps the LLM (the prompt is bounded too).
_MAX_EXTRACTED_TEXT = 200 * 1024  # 200 KiB
# How much we hand to Bridge. Beyond ~32k tokens Claude truncates and
# the response degrades.
_MAX_BRIDGE_INPUT_CHARS = 60_000


# ----------------------------------------------------------------- helpers


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n\n[...truncated...]"


def _decode_lenient(data: bytes) -> str:
    """Best-effort decode for plain / log / unknown text bodies."""
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _extract_text(blob: EvidenceBlob, data: bytes) -> str | None:
    """Pull text out of a binary blob using whatever libs are available.

    Returns ``None`` when extraction is not feasible (e.g. a video
    stream or encrypted archive). The summariser still runs in that
    case — it just operates on the metadata alone.
    """
    ct = (blob.content_type or "").lower().split(";", 1)[0].strip()

    # PDFs — pypdf is preferred; we never raise on a malformed PDF.
    if ct == "application/pdf" or (blob.original_filename or "").lower().endswith(
        ".pdf"
    ):
        try:
            import io as _io

            from pypdf import PdfReader  # type: ignore

            reader = PdfReader(_io.BytesIO(data))
            pieces = []
            for page in reader.pages[:80]:  # cap pages — court PDFs are huge
                try:
                    pieces.append(page.extract_text() or "")
                except Exception:  # noqa: BLE001
                    continue
            return "\n\n".join(p for p in pieces if p).strip() or None
        except Exception:  # noqa: BLE001 — pypdf missing or corrupt PDF
            _logger.debug("evidence_summarise: pypdf failed", exc_info=True)

    # HTML
    if ct in ("text/html", "application/xhtml+xml") or (
        blob.original_filename or ""
    ).lower().endswith((".html", ".htm")):
        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(data, "html.parser")
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            return soup.get_text("\n", strip=True) or None
        except Exception:  # noqa: BLE001
            _logger.debug("evidence_summarise: bs4 failed", exc_info=True)

    # Plain text / logs / JSON / XML
    if ct.startswith("text/") or ct in (
        "application/json",
        "application/xml",
    ):
        try:
            return _decode_lenient(data)
        except Exception:  # noqa: BLE001
            return None

    # Images — try Tesseract OCR if installed
    if ct.startswith("image/"):
        try:
            import io as _io

            from PIL import Image  # type: ignore
            import pytesseract  # type: ignore

            img = Image.open(_io.BytesIO(data))
            return pytesseract.image_to_string(img) or None
        except Exception:  # noqa: BLE001 — Tesseract missing or unreadable image
            _logger.debug(
                "evidence_summarise: pytesseract not available or failed",
                exc_info=True,
            )
            return None

    # Unknown — nothing useful we can do.
    return None


def _coerce_json(text: str) -> dict[str, Any] | None:
    """Try hard to recover JSON from a Bridge response.

    Bridge replies often embed the JSON in a Markdown code block or
    add a leading explanation. We strip code fences and locate the
    first balanced ``{...}`` substring.
    """
    import json

    s = text.strip()
    # Strip Markdown code fences.
    if s.startswith("```"):
        # ```json ... ``` or ``` ... ```
        s = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", s)
        if s.endswith("```"):
            s = s[: -3]
        s = s.strip()
    # Try direct parse first.
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else None
    except Exception:  # noqa: BLE001
        pass
    # Find the first balanced JSON object in the response.
    depth = 0
    start = -1
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                snippet = s[start : i + 1]
                try:
                    v = json.loads(snippet)
                    return v if isinstance(v, dict) else None
                except Exception:  # noqa: BLE001
                    start = -1
                    continue
    return None


# -------------------------------------------------------- IOC extraction

_RE_URL = re.compile(
    r"\bhttps?://[^\s<>\"'`]+", re.IGNORECASE
)
_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_RE_IPV6 = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"
)
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_BTC = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
)


def _extract_iocs_from_text(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {
        "url": set(),
        "email": set(),
        "ipv4": set(),
        "ipv6": set(),
        "sha256": set(),
        "md5": set(),
        "btc_address": set(),
    }
    if not text:
        return out
    out["url"].update(m.group(0).rstrip(".,);:'\"") for m in _RE_URL.finditer(text))
    out["email"].update(m.group(0).lower() for m in _RE_EMAIL.finditer(text))
    out["ipv4"].update(_RE_IPV4.findall(text))
    out["ipv6"].update(_RE_IPV6.findall(text))
    sha256s = set(_RE_SHA256.findall(text))
    out["sha256"].update(s.lower() for s in sha256s)
    # MD5 regex also matches inside SHA-256 strings — strip those out.
    md5s = {m.lower() for m in _RE_MD5.findall(text)}
    md5s = {m for m in md5s if not any(m in s for s in sha256s)}
    out["md5"].update(md5s)
    out["btc_address"].update(_RE_BTC.findall(text))
    return out


_IOC_TYPE_MAP = {
    "url": IOCType.URL,
    "email": IOCType.EMAIL,
    "ipv4": IOCType.IPV4,
    "ipv6": IOCType.IPV6,
    "sha256": IOCType.SHA256,
    "md5": IOCType.MD5,
    "btc_address": IOCType.BTC_ADDRESS,
}


# ------------------------------------------------------- AGENT 1: summariser


_SUMMARISE_SYSTEM = """\
You are an evidence triage analyst inside Argus, a brand- and
threat-intelligence platform. You will receive an artefact (text or
metadata) recovered from an investigation. Produce a strictly-JSON
response with this shape:

{
  "summary_bullets": [string, string, string, string, string],
  "iocs": {
    "urls": [string], "emails": [string], "ipv4": [string],
    "ipv6": [string], "sha256": [string], "md5": [string],
    "btc": [string]
  },
  "pii_categories": [string],
  "classification": "phish" | "leak" | "takedown_proof"
                     | "malware_sample" | "other",
  "confidence": 0..1,
  "rationale": string
}

Rules:
- Output JSON only. No prose, no Markdown fence.
- 5 bullets of summary_bullets, one short sentence each.
- pii_categories ⊆ {"email","name","phone","address","national_id",
  "credit_card","credentials","health","financial_account","other"}.
- If you can't tell, classification="other" and confidence ≤ 0.5.
- Never invent IOCs — only echo ones present in the text.
"""


async def _handle_summarise(db: AsyncSession, task: AgentTask) -> dict:
    blob_id = uuid.UUID(task.payload["blob_id"])
    blob = await db.get(EvidenceBlob, blob_id)
    if blob is None:
        return {"skipped": True, "reason": "blob not found"}
    if blob.is_deleted:
        return {"skipped": True, "reason": "blob soft-deleted"}

    # Pull bytes from MinIO. Storage outage → fail-soft so the queue
    # can retry on the next backoff.
    try:
        data = evidence_store.get(blob.s3_bucket, blob.s3_key)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("evidence_summarise: storage get failed: %s", exc)
        raise

    text = _extract_text(blob, data) or ""
    text = text.strip()

    if text:
        blob.extracted_text = text[:_MAX_EXTRACTED_TEXT]

    user_prompt_parts = [
        f"Artefact metadata:",
        f"  filename: {blob.original_filename or '(unnamed)'}",
        f"  content_type: {blob.content_type}",
        f"  size_bytes: {blob.size_bytes}",
        f"  kind: {blob.kind}",
        f"  sha256: {blob.sha256}",
    ]
    if blob.description:
        user_prompt_parts.append(f"  description: {blob.description}")
    if text:
        user_prompt_parts.append(
            "\nExtracted text:\n" + _truncate(text, _MAX_BRIDGE_INPUT_CHARS)
        )
    else:
        user_prompt_parts.append(
            "\nNo text could be extracted from this artefact. "
            "Summarise based on metadata alone."
        )
    user_prompt = "\n".join(user_prompt_parts)

    bridge_text, model_id = await call_bridge(_SUMMARISE_SYSTEM, user_prompt)
    parsed = _coerce_json(bridge_text)

    summary_payload: dict[str, Any]
    if parsed is None:
        summary_payload = {
            "raw": bridge_text[:8000],
            "model_id": model_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "parse_failed": True,
        }
    else:
        summary_payload = {
            **parsed,
            "model_id": model_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    existing = dict(blob.agent_summary or {})
    existing.update(summary_payload)
    blob.agent_summary = existing
    await db.commit()

    # Chain to IOC extractor.
    try:
        await enqueue(
            db,
            kind="evidence_iocs",
            organization_id=blob.organization_id,
            dedup_key=f"iocs:{blob.id}",
            payload={"blob_id": str(blob.id)},
            priority=6,
        )
    except Exception:  # noqa: BLE001
        _logger.exception(
            "evidence_summarise: failed to enqueue IOC extractor for %s", blob.id
        )

    return {
        "blob_id": str(blob.id),
        "model_id": model_id,
        "extracted_text_chars": len(blob.extracted_text or ""),
        "parse_failed": parsed is None,
    }


register_handler("evidence_summarise", _handle_summarise)


# ------------------------------------------------------- AGENT 2: IOC pipeline


async def _upsert_ioc(
    db: AsyncSession,
    *,
    ioc_type: IOCType,
    value: str,
    source: str,
) -> uuid.UUID | None:
    """Upsert an IOC by (type, value). Returns the IOC id."""
    value = value.strip()
    if not value or len(value) > 2048:
        return None
    existing = (
        await db.execute(
            select(IOC).where(IOC.ioc_type == ioc_type.value, IOC.value == value)
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if existing is not None:
        existing.last_seen = now
        existing.sighting_count = (existing.sighting_count or 0) + 1
        return existing.id
    ioc = IOC(
        ioc_type=ioc_type.value,
        value=value,
        confidence=0.55,
        first_seen=now,
        last_seen=now,
        sighting_count=1,
        tags=["evidence_vault", source],
        context={"source": source},
        source_feed="evidence_vault",
    )
    db.add(ioc)
    try:
        await db.flush()
    except Exception:  # noqa: BLE001 — race on uq_ioc_type_value
        await db.rollback()
        existing = (
            await db.execute(
                select(IOC).where(IOC.ioc_type == ioc_type.value, IOC.value == value)
            )
        ).scalar_one_or_none()
        return existing.id if existing else None
    return ioc.id


async def _handle_iocs(db: AsyncSession, task: AgentTask) -> dict:
    blob_id = uuid.UUID(task.payload["blob_id"])
    blob = await db.get(EvidenceBlob, blob_id)
    if blob is None:
        return {"skipped": True, "reason": "blob not found"}
    if blob.is_deleted:
        return {"skipped": True, "reason": "blob soft-deleted"}

    summary = dict(blob.agent_summary or {})
    candidates: dict[str, set[str]] = {k: set() for k in _IOC_TYPE_MAP}

    # 1. Anything the summariser already collected (LLM output).
    llm_iocs = summary.get("iocs") if isinstance(summary.get("iocs"), dict) else {}
    if isinstance(llm_iocs, dict):
        for src_key, dst_key in (
            ("urls", "url"),
            ("emails", "email"),
            ("ipv4", "ipv4"),
            ("ipv6", "ipv6"),
            ("sha256", "sha256"),
            ("md5", "md5"),
            ("btc", "btc_address"),
        ):
            vals = llm_iocs.get(src_key) or []
            if isinstance(vals, list):
                for v in vals:
                    if isinstance(v, str) and v.strip():
                        candidates[dst_key].add(v.strip())

    # 2. Regex sweep over the extracted text — catches anything the
    #    LLM missed.
    regex_hits = _extract_iocs_from_text(blob.extracted_text or "")
    for k, vals in regex_hits.items():
        candidates[k].update(vals)

    linked: list[str] = []
    by_type: dict[str, int] = {}
    for ioc_kind, values in candidates.items():
        ioc_type = _IOC_TYPE_MAP[ioc_kind]
        for v in values:
            ioc_id = await _upsert_ioc(
                db, ioc_type=ioc_type, value=v, source=f"evidence:{blob.id}"
            )
            if ioc_id is not None:
                linked.append(str(ioc_id))
                by_type[ioc_kind] = by_type.get(ioc_kind, 0) + 1

    summary["linked_ioc_ids"] = sorted(set(linked))
    summary["ioc_counts_by_type"] = by_type
    summary["iocs_extracted_at"] = datetime.now(timezone.utc).isoformat()
    blob.agent_summary = summary
    await db.commit()

    return {
        "blob_id": str(blob.id),
        "ioc_count": len(linked),
        "by_type": by_type,
    }


register_handler("evidence_iocs", _handle_iocs)


# --------------------------------------------------- AGENT 3: COC narrator


_COC_SYSTEM = """\
You draft court-ready chain-of-custody narratives for digital evidence
maintained by Argus. Output Markdown only, suitable for inclusion in a
forensic exhibit. Required sections, in this order:

1. ## Artefact identity   — filename, kind, MIME, size, hashes
2. ## Capture             — uploader, timestamp (UTC), source/IP
3. ## Hash verification   — SHA-256, MD5, SHA-1 (note legacy use)
4. ## Access history      — every download / view / restore, in UTC
5. ## Lifecycle events    — soft-deletes, restores, legal holds
6. ## Tamper-evident chain — describe the Merkle audit chain, prev/curr hash
7. ## Legal posture       — legal hold status now, retention status

Style:
- Concise, factual, no speculation.
- Always render timestamps as ``YYYY-MM-DD HH:MM:SS UTC``.
- If a field is missing, say "Not recorded" rather than inventing it.
"""


async def render_coc_narrative(
    db: AsyncSession, blob: EvidenceBlob
) -> tuple[str, str | None]:
    """Run the COC narrator agent inline. Returns (markdown, model_id).

    Used by both the on-demand endpoint and any future scheduled
    re-rendering.
    """
    rows = (
        await db.execute(
            select(EvidenceAuditChain)
            .where(EvidenceAuditChain.evidence_blob_id == blob.id)
            .order_by(EvidenceAuditChain.sequence.asc())
        )
    ).scalars().all()

    audit_lines = []
    for r in rows:
        ts = r.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        actor = str(r.actor_user_id) if r.actor_user_id else "system"
        audit_lines.append(
            f"- seq={r.sequence} | {ts} | {r.action} | actor={actor} | "
            f"chain={r.chain_hash[:16]}…"
        )
    audit_block = "\n".join(audit_lines) if audit_lines else "(no chain rows)"

    user_prompt = (
        f"### Artefact metadata\n"
        f"- id: {blob.id}\n"
        f"- filename: {blob.original_filename or '(unnamed)'}\n"
        f"- kind: {blob.kind}\n"
        f"- content_type: {blob.content_type}\n"
        f"- size_bytes: {blob.size_bytes}\n"
        f"- sha256: {blob.sha256}\n"
        f"- md5: {blob.md5 or 'Not recorded'}\n"
        f"- sha1: {blob.sha1 or 'Not recorded'}\n"
        f"- captured_at: {blob.captured_at.isoformat() if blob.captured_at else 'Not recorded'}\n"
        f"- captured_by_user_id: {blob.captured_by_user_id or 'Not recorded'}\n"
        f"- capture_source: {blob.capture_source or 'Not recorded'}\n"
        f"- description: {blob.description or 'Not recorded'}\n"
        f"- legal_hold: {bool(blob.legal_hold)}\n"
        f"- is_deleted: {bool(blob.is_deleted)}\n"
        f"- delete_reason: {blob.delete_reason or 'n/a'}\n"
        f"\n### Audit chain\n{audit_block}\n"
    )

    text, model_id = await call_bridge(_COC_SYSTEM, user_prompt)
    return text.strip(), model_id


# ------------------------------------------------------- AGENT 4: similar


async def ensure_similarity_hashes(
    db: AsyncSession, blob: EvidenceBlob
) -> None:
    """Compute perceptual_hash / ssdeep on demand if missing."""
    needs_phash = (blob.content_type or "").startswith("image/") and not blob.perceptual_hash
    needs_ssdeep = not blob.ssdeep

    if not needs_phash and not needs_ssdeep:
        return

    try:
        data = evidence_store.get(blob.s3_bucket, blob.s3_key)
    except Exception:  # noqa: BLE001
        _logger.debug("evidence_similar: storage get failed", exc_info=True)
        return

    if needs_phash:
        try:
            import io as _io

            from PIL import Image  # type: ignore
            import imagehash  # type: ignore

            img = Image.open(_io.BytesIO(data))
            blob.perceptual_hash = str(imagehash.phash(img))
        except Exception:  # noqa: BLE001 — image is corrupt or PIL/imagehash missing
            _logger.debug(
                "evidence_similar: phash unavailable for %s", blob.id, exc_info=True
            )

    if needs_ssdeep:
        try:
            import ssdeep  # type: ignore

            blob.ssdeep = ssdeep.hash(data)
        except Exception:  # noqa: BLE001 — ssdeep is optional (libfuzzy native dep)
            _logger.debug(
                "evidence_similar: ssdeep unavailable for %s", blob.id, exc_info=True
            )


def _hamming(a: str, b: str) -> int | None:
    """Hamming distance between two equal-length perceptual hashes."""
    try:
        ai = int(a, 16)
        bi = int(b, 16)
        return bin(ai ^ bi).count("1")
    except (ValueError, TypeError):
        return None


_SIMILAR_SYSTEM = (
    "You analyse clusters of related digital artefacts in an "
    "investigation. Given a target artefact and N near-duplicates, "
    "produce a short paragraph (≤120 words) describing how they relate "
    "(re-uploads, screenshot variants, near-duplicate phish kits, etc.) "
    "and what the analyst should do next. Plain text, no Markdown."
)


async def find_similar_blobs(
    db: AsyncSession,
    blob: EvidenceBlob,
    *,
    limit: int = 10,
) -> tuple[str, list[dict[str, Any]], str | None, str | None]:
    """Return (method, hits, summary, model_id).

    *hits* is a list of dicts shaped like ``SimilarHit`` — the route
    layer wraps it in a Pydantic model.
    """
    org_id = blob.organization_id

    method = "sha256_prefix"
    hits: list[dict[str, Any]] = []

    # 1. perceptual hash (image-to-image)
    if blob.perceptual_hash:
        method = "phash_hamming"
        rows = (
            await db.execute(
                select(EvidenceBlob)
                .where(
                    EvidenceBlob.organization_id == org_id,
                    EvidenceBlob.id != blob.id,
                    EvidenceBlob.is_deleted == False,  # noqa: E712
                    EvidenceBlob.perceptual_hash.is_not(None),
                )
                .limit(2000)
            )
        ).scalars().all()
        scored = []
        for cand in rows:
            d = _hamming(blob.perceptual_hash, cand.perceptual_hash or "")
            if d is None:
                continue
            scored.append((d, cand))
        scored.sort(key=lambda t: t[0])
        for d, cand in scored[:limit]:
            if d > 24:  # noisier than this isn't a meaningful hit
                continue
            hits.append(_hit_dict(cand, distance=d, method=method))

    # 2. ssdeep fallback for binaries
    if not hits and blob.ssdeep:
        method = "ssdeep"
        try:
            import ssdeep  # type: ignore

            rows = (
                await db.execute(
                    select(EvidenceBlob)
                    .where(
                        EvidenceBlob.organization_id == org_id,
                        EvidenceBlob.id != blob.id,
                        EvidenceBlob.is_deleted == False,  # noqa: E712
                        EvidenceBlob.ssdeep.is_not(None),
                    )
                    .limit(2000)
                )
            ).scalars().all()
            scored = []
            for cand in rows:
                try:
                    score = ssdeep.compare(blob.ssdeep, cand.ssdeep or "")
                except Exception:  # noqa: BLE001
                    continue
                if score >= 50:
                    # Higher score = more similar; convert to "distance"
                    # so the schema stays consistent (lower = closer).
                    scored.append((100 - score, cand))
            scored.sort(key=lambda t: t[0])
            for d, cand in scored[:limit]:
                hits.append(_hit_dict(cand, distance=d, method=method))
        except Exception:  # noqa: BLE001
            _logger.debug("evidence_similar: ssdeep compare failed", exc_info=True)

    # 3. SHA-256 prefix fallback (always works, even with no extra libs)
    if not hits:
        method = "sha256_prefix"
        prefix = blob.sha256[:8]
        rows = (
            await db.execute(
                select(EvidenceBlob)
                .where(
                    EvidenceBlob.organization_id == org_id,
                    EvidenceBlob.id != blob.id,
                    EvidenceBlob.is_deleted == False,  # noqa: E712
                    EvidenceBlob.sha256.like(f"{prefix}%"),
                )
                .limit(limit)
            )
        ).scalars().all()
        for cand in rows:
            hits.append(_hit_dict(cand, distance=None, method=method))

    summary = None
    model_id = None
    if len(hits) >= 2:
        try:
            cluster_lines = []
            for h in hits[:8]:
                cluster_lines.append(
                    f"- {h['original_filename'] or '(unnamed)'} "
                    f"({h['content_type']}, {h['size_bytes']}B, "
                    f"sha256={h['sha256'][:12]}…, "
                    f"distance={h['distance']})"
                )
            user_prompt = (
                f"Target artefact: {blob.original_filename or '(unnamed)'} "
                f"({blob.content_type}, {blob.size_bytes}B, "
                f"sha256={blob.sha256[:12]}…)\n\n"
                f"Method: {method}\n"
                f"Neighbours:\n" + "\n".join(cluster_lines)
            )
            text, model_id = await call_bridge(_SIMILAR_SYSTEM, user_prompt)
            summary = text.strip() or None
        except Exception:  # noqa: BLE001 — bridge unreachable; skip narration
            _logger.debug(
                "evidence_similar: bridge call failed; returning hits only",
                exc_info=True,
            )

    return method, hits, summary, model_id


def _hit_dict(
    cand: EvidenceBlob, *, distance: int | None, method: str
) -> dict[str, Any]:
    return {
        "id": cand.id,
        "sha256": cand.sha256,
        "md5": cand.md5,
        "perceptual_hash": cand.perceptual_hash,
        "ssdeep": cand.ssdeep,
        "original_filename": cand.original_filename,
        "content_type": cand.content_type,
        "size_bytes": cand.size_bytes,
        "distance": distance,
        "method": method,
        "captured_at": cand.captured_at,
    }


# Worker-pull variant — lets a future scheduler re-run similarity
# scans without an HTTP request.
async def _handle_similar(db: AsyncSession, task: AgentTask) -> dict:
    blob_id = uuid.UUID(task.payload["blob_id"])
    blob = await db.get(EvidenceBlob, blob_id)
    if blob is None:
        return {"skipped": True, "reason": "blob not found"}
    await ensure_similarity_hashes(db, blob)
    await db.commit()
    await db.refresh(blob)
    method, hits, _summary, _model_id = await find_similar_blobs(db, blob)
    return {
        "blob_id": str(blob.id),
        "method": method,
        "neighbour_count": len(hits),
    }


register_handler("evidence_similar", _handle_similar)


# COC narration also gets a queue handler for the rare "regenerate
# every blob's narrative" admin op. The HTTP path uses the function
# directly (it's faster — single Bridge round-trip).


async def _handle_coc_narrate(db: AsyncSession, task: AgentTask) -> dict:
    blob_id = uuid.UUID(task.payload["blob_id"])
    blob = await db.get(EvidenceBlob, blob_id)
    if blob is None:
        return {"skipped": True, "reason": "blob not found"}
    text, model_id = await render_coc_narrative(db, blob)
    summary = dict(blob.agent_summary or {})
    summary["coc_narrative"] = text
    summary["coc_narrative_at"] = datetime.now(timezone.utc).isoformat()
    summary["coc_model_id"] = model_id
    blob.agent_summary = summary
    await db.commit()
    return {"blob_id": str(blob.id), "model_id": model_id, "chars": len(text)}


register_handler("evidence_coc_narrate", _handle_coc_narrate)


__all__ = [
    "render_coc_narrative",
    "ensure_similarity_hashes",
    "find_similar_blobs",
]
