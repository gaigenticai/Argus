"""Structured JSON logging (Audit C5).

Stdlib-only — no extra runtime dependency. Every log line is emitted
as a single JSON object on stdout. A request-scoped ``request_id``
contextvar is bound by the FastAPI request-id middleware and surfaces
on every log line emitted while serving that request, so a SOC analyst
can grep one trace across API + worker logs.

Usage::

    from src.core.logging import configure_logging, request_id_var
    configure_logging()                          # call once on boot
    request_id_var.set(rid)                      # done in middleware
    logger.info("did the thing", extra={"asset_id": str(aid)})

The formatter copies any non-stdlib LogRecord attribute (anything in
``record.__dict__`` that isn't a built-in field) into the JSON payload,
so ``logger.info(..., extra={...})`` keys appear top-level. This is the
contract Datadog / Loki / Splunk expect.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from contextvars import ContextVar
from typing import Any


request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


_BUILTIN_LOG_RECORD_FIELDS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        rid = request_id_var.get()
        if rid:
            payload["request_id"] = rid

        if record.exc_info:
            payload["exc_info"] = "".join(
                traceback.format_exception(*record.exc_info)
            )
        if record.stack_info:
            payload["stack_info"] = record.stack_info

        for key, value in record.__dict__.items():
            if key in _BUILTIN_LOG_RECORD_FIELDS:
                continue
            if key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)

        try:
            return json.dumps(payload, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            return json.dumps(
                {
                    "ts": payload["ts"],
                    "level": payload["level"],
                    "logger": payload["logger"],
                    "message": "log_format_error: " + repr(payload.get("message")),
                },
                separators=(",", ":"),
            )


_CONFIGURED = False


def configure_logging(*, level: str | None = None, force: bool = False) -> None:
    """Install the JSON formatter on the root logger. Idempotent."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    log_level = (level or os.environ.get("ARGUS_LOG_LEVEL") or "INFO").upper()

    root = logging.getLogger()
    root.setLevel(log_level)

    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)

    # Quiet noisy libraries.
    for noisy in ("urllib3", "botocore", "boto3", "asyncio", "httpcore"):
        logging.getLogger(noisy).setLevel(
            max(logging.getLevelName(log_level), logging.WARNING)
            if isinstance(log_level, int)
            else "WARNING"
        )
    _CONFIGURED = True


__all__ = ["configure_logging", "request_id_var", "JsonFormatter"]
