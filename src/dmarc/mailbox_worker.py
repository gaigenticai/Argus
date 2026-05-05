"""IMAP poller that drains DMARC reporter mailboxes.

Each :class:`~src.models.dmarc_forensic.DmarcMailboxConfig` row points
to one IMAP mailbox (Office365, Gmail, Fastmail, custom) where the
operator has configured ``rua@dmarc-report...`` mail to land.

Per tick (driven by the worker runner's ``_dmarc_mailbox_tick_once``):

    1. Walk every enabled config row.
    2. For each: connect over IMAPS, ``UID FETCH`` everything with
       UID > ``last_seen_uid``.
    3. For each message: extract ``.gz`` / ``.zip`` / ``.xml`` /
       ``.eml`` attachments; route each through the RUA or RUF parser
       based on a fast magic-byte detect.
    4. Persist via ``ingest_aggregate`` / ``ingest_forensic`` (both
       idempotent).
    5. Update ``last_seen_uid`` / ``last_polled_at`` / ``last_error``.

We use stdlib ``imaplib`` in a thread (``asyncio.to_thread``) — that's
deliberate. ``aioimaplib`` is occasionally maintained but breaks on
several common providers (the M365 IDLE handshake notably). Threaded
imaplib is rock-solid and our concurrency need is low (a few mailboxes,
one tick a minute).
"""
from __future__ import annotations

import asyncio
import email
import email.policy
import imaplib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto import CryptoError, decrypt
from src.dmarc.ingest import ingest_aggregate, ingest_forensic
from src.dmarc.parser import detect_kind
from src.models.dmarc_forensic import DmarcMailboxConfig

_logger = logging.getLogger(__name__)

# Cap per-tick volume so a single bad mailbox can't starve the worker.
_MAX_MESSAGES_PER_MAILBOX = 500


def _connect(host: str, port: int, username: str, password: str, folder: str) -> imaplib.IMAP4_SSL:
    cli = imaplib.IMAP4_SSL(host, port, timeout=30)
    cli.login(username, password)
    cli.select(folder, readonly=False)
    return cli


def _fetch_new_uids(cli: imaplib.IMAP4_SSL, last_seen_uid: int | None) -> list[int]:
    crit = f"UID {(last_seen_uid or 0) + 1}:*"
    typ, data = cli.uid("search", None, crit)
    if typ != "OK" or not data or not data[0]:
        return []
    raw = data[0]
    if isinstance(raw, bytes):
        raw = raw.decode("ascii", errors="ignore")
    return [int(x) for x in raw.split() if x.isdigit() and int(x) > (last_seen_uid or 0)]


def _fetch_message(cli: imaplib.IMAP4_SSL, uid: int) -> bytes | None:
    typ, data = cli.uid("fetch", str(uid).encode("ascii"), b"(RFC822)")
    if typ != "OK" or not data:
        return None
    for item in data:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
            return bytes(item[1])
    return None


def _iter_attachments(raw: bytes) -> Iterable[tuple[str, bytes]]:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = (part.get_filename() or "").strip()
        ctype = (part.get_content_type() or "").lower()
        try:
            payload = part.get_payload(decode=True)
        except Exception:  # noqa: BLE001
            payload = None
        if not isinstance(payload, (bytes, bytearray)):
            continue

        # DMARC report attachments — accept .xml / .gz / .zip plus any
        # raw feedback-report part (RUF).
        name_low = filename.lower()
        if any(name_low.endswith(ext) for ext in (".xml", ".gz", ".zip")):
            yield filename, bytes(payload)
        elif ctype in {
            "application/gzip",
            "application/x-gzip",
            "application/zip",
            "application/x-zip-compressed",
            "text/xml",
            "application/xml",
            "message/feedback-report",
            "message/rfc822",
        }:
            yield filename or ctype, bytes(payload)


async def _ingest_one(db: AsyncSession, organization_id: uuid.UUID, blob: bytes) -> str:
    """Route the blob to the right ingester. Returns 'rua' / 'ruf' / 'skip'."""
    try:
        kind = detect_kind(blob)
    except Exception:  # noqa: BLE001
        kind = "unknown"
    try:
        if kind == "rua":
            await ingest_aggregate(db, organization_id, blob)
            return "rua"
        if kind in {"ruf_xml", "ruf_email"}:
            await ingest_forensic(db, organization_id, blob)
            return "ruf"
    except Exception as exc:  # noqa: BLE001
        _logger.warning("dmarc mailbox ingest failed (%s): %s", kind, exc)
        return "skip"
    return "skip"


async def _poll_one(
    db: AsyncSession,
    cfg: DmarcMailboxConfig,
) -> dict[str, Any]:
    summary: dict[str, Any] = {"mailbox_id": str(cfg.id), "host": cfg.host, "rua": 0, "ruf": 0, "skipped": 0}
    try:
        password = decrypt(cfg.password_encrypted)
    except CryptoError as exc:
        cfg.last_error = f"decrypt: {exc}"[:8000]
        cfg.last_polled_at = datetime.now(timezone.utc)
        await db.flush()
        summary["error"] = cfg.last_error
        return summary

    def _do_imap_work() -> tuple[list[tuple[int, bytes]], str | None]:
        """Sync block — runs on a worker thread."""
        try:
            cli = _connect(cfg.host, cfg.port, cfg.username, password, cfg.folder)
        except Exception as exc:  # noqa: BLE001
            return [], f"connect: {exc}"
        try:
            uids = _fetch_new_uids(cli, cfg.last_seen_uid)
            uids = uids[:_MAX_MESSAGES_PER_MAILBOX]
            out: list[tuple[int, bytes]] = []
            for uid in uids:
                raw = _fetch_message(cli, uid)
                if raw:
                    out.append((uid, raw))
            return out, None
        except Exception as exc:  # noqa: BLE001
            return [], f"fetch: {exc}"
        finally:
            try:
                cli.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                cli.logout()
            except Exception:  # noqa: BLE001
                pass

    msgs, err = await asyncio.to_thread(_do_imap_work)
    if err:
        cfg.last_error = err[:8000]
        cfg.last_polled_at = datetime.now(timezone.utc)
        await db.flush()
        summary["error"] = err
        return summary

    max_uid = cfg.last_seen_uid or 0
    for uid, raw in msgs:
        max_uid = max(max_uid, uid)
        for _name, blob in _iter_attachments(raw):
            verdict = await _ingest_one(db, cfg.organization_id, blob)
            if verdict in summary:
                summary[verdict] += 1
            else:
                summary["skipped"] += 1

    cfg.last_seen_uid = max_uid
    cfg.last_polled_at = datetime.now(timezone.utc)
    cfg.last_error = None
    await db.flush()
    return summary


async def poll_all_mailboxes(db: AsyncSession) -> None:
    """Drain every enabled mailbox once. Called by the worker tick."""
    rows = (
        await db.execute(
            select(DmarcMailboxConfig).where(DmarcMailboxConfig.enabled.is_(True))
        )
    ).scalars().all()
    if not rows:
        return
    for cfg in rows:
        try:
            summary = await _poll_one(db, cfg)
            await db.commit()
            _logger.info("dmarc mailbox poll: %s", summary)
        except Exception:  # noqa: BLE001
            _logger.exception("dmarc mailbox poll errored for %s", cfg.host)
            await db.rollback()


__all__ = ["poll_all_mailboxes"]
