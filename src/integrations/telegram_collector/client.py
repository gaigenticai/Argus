"""Telethon transport (P3 #3.10).

The MTProto client is opt-in (see module docstring of
``src/integrations/telegram_collector/__init__.py``). When opt-in is
not satisfied, every entry point returns
``TelegramCollectorResult(success=False, note=...)`` so the dashboard
can surface a clear "configure ARGUS_TELEGRAM_*" call-to-action.

We import Telethon **lazily** inside the entry points — the package
isn't a hard dependency in ``requirements.txt`` (it pulls in pyaes,
pyasn1, pillow, rsa) and we don't want to inflate every Argus build
that doesn't enable Telegram. Operators who flip the gate also install
``telethon>=1.34`` in their venv / image.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TelegramCollectorResult:
    success: bool
    messages: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    note: str | None = None
    raw: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "messages": list(self.messages),
            "error": self.error,
            "note": self.note,
        }


def _enabled() -> bool:
    return (os.environ.get("ARGUS_TELEGRAM_ENABLED") or "") \
        .strip().lower() in {"true", "1", "yes", "on"}


def _api_id() -> str:
    return (os.environ.get("ARGUS_TELEGRAM_API_ID") or "").strip()


def _api_hash() -> str:
    return (os.environ.get("ARGUS_TELEGRAM_API_HASH") or "").strip()


def _session_path() -> str:
    return (os.environ.get("ARGUS_TELEGRAM_SESSION_PATH") or "").strip()


def _check_session_path_safe(path: str) -> str | None:
    """Return a user-facing warning string if the session-DB parent
    directory is world-readable, or ``None`` if it's safe.

    Telethon stores the user's full session blob (including the
    auth-key derived from the SMS challenge) on disk. World-readable
    parent dirs let any other process / container on the host hijack
    the session — see audit P3.10. We don't refuse to run, but we
    surface the warning loud and clear via the unconfigured-note path
    and the health-check note.
    """
    if not path:
        return None
    parent = os.path.dirname(os.path.abspath(path)) or "/"
    try:
        st = os.stat(parent)
    except OSError:
        # Parent doesn't exist yet — Telethon will create the file but
        # not the parent dir, so this is fatal in practice. Surface it.
        return f"session-path parent does not exist: {parent}"
    mode = st.st_mode & 0o777
    if mode & 0o077:
        return (
            f"session-path parent {parent!r} is mode {oct(mode)} — "
            "Telethon writes auth-key material here, so the parent "
            "directory MUST be 0700 (chmod 700 + chown to the api "
            "process uid)"
        )
    return None


def is_configured() -> bool:
    """Three env vars + the legal-acknowledgment gate."""
    if not _enabled():
        return False
    if not _api_id() or not _api_hash():
        return False
    if not _session_path():
        return False
    try:
        int(_api_id())
    except ValueError:
        return False
    return True


def _unconfigured_note() -> str:
    if not _enabled():
        return ("telegram collector disabled — set "
                "ARGUS_TELEGRAM_ENABLED=true after legal review")
    if not _api_id() or not _api_hash():
        return ("telegram collector not configured — set "
                "ARGUS_TELEGRAM_API_ID + ARGUS_TELEGRAM_API_HASH "
                "(from my.telegram.org)")
    if not _session_path():
        return ("telegram collector not configured — set "
                "ARGUS_TELEGRAM_SESSION_PATH for the session DB")
    return "telegram collector misconfigured"


async def fetch_recent_messages(
    channels: list[str],
    *,
    limit_per_channel: int = 50,
    since_message_id: int | None = None,
) -> TelegramCollectorResult:
    """Pull recent messages from each channel via Telethon's MTProto.

    On unconfigured deployments returns ``success=False`` with a note
    so the dashboard can render a setup CTA. On configured deployments
    we lazily import telethon — if the import fails (operator forgot
    to ``pip install telethon`` in the api/worker container) we surface
    that as the error string, again as ``success=False``.
    """
    if not is_configured():
        return TelegramCollectorResult(
            success=False, note=_unconfigured_note(),
        )
    try:
        from telethon import TelegramClient   # type: ignore
        from telethon.errors import (        # type: ignore
            ChannelPrivateError,
            FloodWaitError,
            UsernameInvalidError,
            UsernameNotOccupiedError,
        )
    except ImportError as exc:
        return TelegramCollectorResult(
            success=False,
            error=("telethon not installed in this container — "
                   f"{exc}"),
        )

    client = TelegramClient(
        _session_path(), int(_api_id()), _api_hash(),
    )
    out: list[dict[str, Any]] = []
    try:
        await client.connect()
        if not await client.is_user_authorized():
            return TelegramCollectorResult(
                success=False,
                error=("telegram session not authorised — run the "
                       "session-bootstrap CLI on the host once to "
                       "complete the SMS challenge"),
            )
        for handle in channels:
            try:
                async for msg in client.iter_messages(
                    handle, limit=limit_per_channel,
                    min_id=since_message_id or 0,
                ):
                    out.append({
                        "channel": handle,
                        "message_id": getattr(msg, "id", None),
                        "text": getattr(msg, "message", None) or "",
                        "sender_id": getattr(msg, "sender_id", None),
                        "posted_at": (msg.date.isoformat()
                                       if getattr(msg, "date", None) else None),
                        "raw": {
                            "fwd_from_channel": getattr(
                                getattr(msg, "fwd_from", None),
                                "from_id", None) and str(msg.fwd_from.from_id),
                            "has_media": bool(getattr(msg, "media", None)),
                            "reply_to": getattr(
                                getattr(msg, "reply_to", None),
                                "reply_to_msg_id", None),
                        },
                    })
            except (ChannelPrivateError, UsernameInvalidError,
                    UsernameNotOccupiedError) as exc:
                logger.warning(
                    "[telegram] channel %s unreachable: %s", handle, exc,
                )
            except FloodWaitError as exc:
                # Telegram rate-limited us — bail out of this run; the
                # next scheduled run will pick up where we left off.
                return TelegramCollectorResult(
                    success=False,
                    messages=out,
                    error=f"telegram FloodWait: wait {exc.seconds}s",
                )
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
    return TelegramCollectorResult(success=True, messages=out)


async def health_check() -> TelegramCollectorResult:
    """Light health check — ``is_configured`` + Telethon importable +
    session connect + session-DB permissions. Doesn't pull channels."""
    if not is_configured():
        return TelegramCollectorResult(
            success=False, note=_unconfigured_note(),
        )
    perm_warning = _check_session_path_safe(_session_path())
    try:
        from telethon import TelegramClient   # type: ignore
    except ImportError as exc:
        return TelegramCollectorResult(
            success=False,
            error=f"telethon not installed: {exc}",
        )
    client = TelegramClient(
        _session_path(), int(_api_id()), _api_hash(),
    )
    try:
        await client.connect()
        if not await client.is_user_authorized():
            return TelegramCollectorResult(
                success=False,
                error="telegram session not authorised",
            )
        note = "telegram session connected + authorised"
        if perm_warning:
            note = f"{note} (WARNING: {perm_warning})"
        return TelegramCollectorResult(
            success=True, note=note,
        )
    except Exception as exc:  # noqa: BLE001
        return TelegramCollectorResult(
            success=False,
            error=f"{type(exc).__name__}: {exc}"[:200],
        )
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
