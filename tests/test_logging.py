"""Audit C5 — structured JSON logging smoke tests."""

from __future__ import annotations

import json
import logging

from src.core.logging import JsonFormatter, configure_logging, request_id_var


def test_json_formatter_emits_one_object_per_record():
    fmt = JsonFormatter()
    record = logging.LogRecord(
        name="argus.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    out = fmt.format(record)
    parsed = json.loads(out)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "argus.test"
    assert parsed["message"] == "hello world"
    assert "ts" in parsed


def test_request_id_appears_on_log_line():
    fmt = JsonFormatter()
    token = request_id_var.set("abc123")
    try:
        record = logging.LogRecord(
            name="argus.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="probe",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(fmt.format(record))
        assert parsed["request_id"] == "abc123"
    finally:
        request_id_var.reset(token)


def test_extra_keys_serialise_top_level():
    fmt = JsonFormatter()
    record = logging.LogRecord(
        name="argus.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="probe",
        args=(),
        exc_info=None,
    )
    record.__dict__["asset_id"] = "deadbeef"
    record.__dict__["count"] = 42
    parsed = json.loads(fmt.format(record))
    assert parsed["asset_id"] == "deadbeef"
    assert parsed["count"] == 42


def test_configure_logging_installs_json_handler_on_root():
    configure_logging(force=True)
    root = logging.getLogger()
    assert any(
        isinstance(h.formatter, JsonFormatter) for h in root.handlers
    ), "JsonFormatter not installed on root logger"
