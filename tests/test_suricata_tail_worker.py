"""Suricata eve.json tail worker — fixture tests for the parsers.

End-to-end tick_once is a Phase C smoke. Here we pin the pure
functions:

  * ``_parse_alert_lines`` — NDJSON → alert events filter.
  * ``_alert_row_from_event`` — eve.json alert → Alert row mapping
    (severity 1-4 → enum, category mapping, matched_entities shape).
  * ``_read_new_bytes`` — file-rotation handling, partial-line trim.
  * ``_offset_key`` — Redis key uniqueness per file path.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

import pytest

from src.models.common import Severity
from src.models.threat import AlertStatus, ThreatCategory
from src.workers.maintenance.suricata_tail import (
    _SURI_CATEGORY_TO_THREAT,
    _SURI_SEVERITY_TO_ENUM,
    _alert_row_from_event,
    _offset_key,
    _parse_alert_lines,
    _read_new_bytes,
)


# ── Realistic eve.json alert events ────────────────────────────────


_EVE_ALERT_TROJAN = {
    "timestamp": "2026-05-01T12:34:56.789012+0000",
    "flow_id": 1234567890,
    "in_iface": "eth0",
    "event_type": "alert",
    "src_ip": "10.0.0.5",
    "src_port": 49152,
    "dest_ip": "203.0.113.42",
    "dest_port": 443,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1, "signature_id": 2018959, "rev": 4,
        "signature": "ET TROJAN Suspicious User-Agent (likely Lumma Stealer)",
        "category": "trojan-activity",
        "severity": 1,
    },
}


_EVE_ALERT_BRUTE = {
    "timestamp": "2026-05-01T12:35:01.000+0000",
    "flow_id": 1234567891,
    "event_type": "alert",
    "src_ip": "203.0.113.99",
    "src_port": 50001,
    "dest_ip": "10.0.0.20",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "signature_id": 2200001, "rev": 1,
        "signature": "ET POLICY SSH brute-force attempt",
        "category": "attempted-admin",
        "severity": 2,
    },
}


_EVE_FLOW_NON_ALERT = {
    "timestamp": "2026-05-01T12:35:05+0000",
    "event_type": "flow",
    "src_ip": "1.2.3.4",
    "dest_ip": "5.6.7.8",
}


_EVE_DNS_NON_ALERT = {"event_type": "dns", "dns": {"rrname": "example.com"}}


# ── _parse_alert_lines ────────────────────────────────────────────


def test_parse_alert_lines_keeps_only_alerts():
    """Filter to event_type=='alert'; ignore flow / dns / netflow."""
    lines = [
        json.dumps(_EVE_FLOW_NON_ALERT),
        json.dumps(_EVE_ALERT_TROJAN),
        json.dumps(_EVE_DNS_NON_ALERT),
        json.dumps(_EVE_ALERT_BRUTE),
    ]
    raw = ("\n".join(lines) + "\n").encode()
    events = _parse_alert_lines(raw)
    assert len(events) == 2
    sigs = [e["alert"]["signature_id"] for e in events]
    assert 2018959 in sigs
    assert 2200001 in sigs


def test_parse_alert_lines_skips_blank_and_malformed():
    """Empty lines + malformed JSON must not crash the tick."""
    raw = (
        b"\n\n"
        + json.dumps(_EVE_ALERT_TROJAN).encode()
        + b"\n"
        + b"this is not json\n"
        + json.dumps(_EVE_ALERT_BRUTE).encode()
        + b"\n"
    )
    events = _parse_alert_lines(raw)
    assert len(events) == 2


def test_parse_alert_lines_empty_input():
    assert _parse_alert_lines(b"") == []


# ── _alert_row_from_event ─────────────────────────────────────────


def _fake_org_id():
    return uuid.uuid4()


def test_alert_row_severity_mapping():
    """Pin the Suricata severity → Argus enum mapping. Suricata
    uses 1=high, 2=high-ish, 3=medium, 4=low."""
    assert _SURI_SEVERITY_TO_ENUM == {
        1: Severity.CRITICAL.value,
        2: Severity.HIGH.value,
        3: Severity.MEDIUM.value,
        4: Severity.LOW.value,
    }


def test_alert_row_category_mapping_known():
    """Pin the strongly-mapped Suricata categories."""
    assert _SURI_CATEGORY_TO_THREAT["trojan-activity"] == ThreatCategory.EXPLOIT.value
    assert _SURI_CATEGORY_TO_THREAT["malware-cnc"] == ThreatCategory.EXPLOIT.value
    assert _SURI_CATEGORY_TO_THREAT["attempted-admin"] == ThreatCategory.INITIAL_ACCESS.value
    assert _SURI_CATEGORY_TO_THREAT["credential-theft"] == ThreatCategory.CREDENTIAL_LEAK.value
    assert _SURI_CATEGORY_TO_THREAT["phishing"] == ThreatCategory.PHISHING.value
    assert _SURI_CATEGORY_TO_THREAT["data-theft"] == ThreatCategory.DATA_BREACH.value


def test_alert_row_unknown_category_falls_back_to_exploit():
    """Categories not in the explicit map fall back to EXPLOIT —
    network-IDS hits without categorical context still need a bucket."""
    org_id = _fake_org_id()
    ev = {
        "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "proto": "TCP",
        "alert": {
            "signature": "Custom rule fired",
            "category": "totally-bespoke-category-not-in-map",
            "severity": 3,
        },
    }
    row = _alert_row_from_event(ev, org_id)
    assert row.category == ThreatCategory.EXPLOIT.value


def test_alert_row_full_population():
    """End-to-end: realistic eve event → fully-populated Alert row."""
    org_id = _fake_org_id()
    row = _alert_row_from_event(_EVE_ALERT_TROJAN, org_id)

    assert row.organization_id == org_id
    assert row.severity == Severity.CRITICAL.value
    assert row.category == ThreatCategory.EXPLOIT.value  # trojan-activity
    assert row.status == AlertStatus.NEW.value
    assert "Suricata signature 2018959" in row.summary
    assert "tcp 10.0.0.5:49152" in row.summary.lower()
    assert "203.0.113.42:443" in row.summary
    assert row.title.startswith("Suricata: ET TROJAN")
    assert row.confidence == 0.7

    # matched_entities shape
    me = row.matched_entities
    assert me["src_ip"] == "10.0.0.5"
    assert me["dest_ip"] == "203.0.113.42"
    assert me["src_port"] == 49152
    assert me["dest_port"] == 443
    assert me["proto"] == "TCP"
    assert me["signature_id"] == 2018959
    assert me["flow_id"] == 1234567890

    # details shape
    d = row.details
    assert d["source"] == "suricata"
    assert d["timestamp"] == "2026-05-01T12:34:56.789012+0000"
    assert d["in_iface"] == "eth0"
    assert d["action"] == "allowed"
    assert d["raw_alert"]["signature"] == _EVE_ALERT_TROJAN["alert"]["signature"]


def test_alert_row_handles_missing_severity():
    """If severity is absent or non-int, default to MEDIUM (3)."""
    org_id = _fake_org_id()
    ev = {
        "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "proto": "TCP",
        "alert": {"signature": "x", "category": "trojan-activity"},
    }
    row = _alert_row_from_event(ev, org_id)
    assert row.severity == Severity.MEDIUM.value


def test_alert_row_handles_missing_alert_metadata():
    """Defensive — eve event missing alert{} should still produce
    a row with the placeholder signature."""
    org_id = _fake_org_id()
    ev = {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "proto": "TCP"}
    row = _alert_row_from_event(ev, org_id)
    assert "Suricata alert" in row.title


def test_alert_row_truncates_oversized_fields():
    """Argus's Alert.title and .summary are bounded VARCHAR(500); the
    helper must truncate to keep within column limits."""
    org_id = _fake_org_id()
    ev = {
        "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "proto": "TCP",
        "alert": {
            "signature": "X" * 2000,
            "category": "trojan-activity",
            "severity": 1,
        },
    }
    row = _alert_row_from_event(ev, org_id)
    assert len(row.title) <= 500


# ── _read_new_bytes (file rotation + partial line) ────────────────


def test_read_new_bytes_first_call_from_zero():
    """Fresh file, offset=0 → reads everything up to last newline."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"line1\nline2\nline3\n")
        path = f.name
    try:
        data, new_offset = _read_new_bytes(path, 0, max_bytes=1024)
        assert data == b"line1\nline2\nline3\n"
        assert new_offset == 18
    finally:
        Path(path).unlink()


def test_read_new_bytes_resumes_from_offset():
    """Second call should pick up where the first left off."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"line1\nline2\nline3\n")
        path = f.name
    try:
        data, new_offset = _read_new_bytes(path, 6, max_bytes=1024)
        assert data == b"line2\nline3\n"
        assert new_offset == 18
    finally:
        Path(path).unlink()


def test_read_new_bytes_file_rotation_resets_to_zero():
    """If saved offset > current file size (file rotated/truncated),
    we re-read from the start rather than miss everything."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"after-rotation\n")
        path = f.name
    try:
        # Saved offset (1000) > file size (15) → reset to 0
        data, new_offset = _read_new_bytes(path, 1000, max_bytes=1024)
        assert data == b"after-rotation\n"
        assert new_offset == 15
    finally:
        Path(path).unlink()


def test_read_new_bytes_partial_line_trimmed():
    """If max_bytes cuts mid-line, we must defer the partial line
    to the next tick — never split a JSON record."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"complete-line\nthis-line-is-incomplete-because")
        path = f.name
    try:
        data, new_offset = _read_new_bytes(path, 0, max_bytes=1024)
        # The partial second line is deferred; offset stops at the
        # last newline of the first complete line.
        assert data == b"complete-line\n"
        assert new_offset == 14
    finally:
        Path(path).unlink()


def test_read_new_bytes_no_newline_in_chunk():
    """Pathological case — no newline in the entire window → return
    nothing and keep offset, wait for upstream to flush."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # No trailing newline
        f.write(b"x" * 1000)
        path = f.name
    try:
        data, new_offset = _read_new_bytes(path, 0, max_bytes=2048)
        assert data == b""
        assert new_offset == 0
    finally:
        Path(path).unlink()


def test_read_new_bytes_caps_at_max_bytes():
    """Ensure _MAX_BYTES_PER_TICK is honoured — a busy sensor that
    wrote 100 MB while we slept can't OOM the worker."""
    big_content = b"line\n" * 10_000  # 50_000 bytes
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(big_content)
        path = f.name
    try:
        data, new_offset = _read_new_bytes(path, 0, max_bytes=1024)
        # We read AT MOST max_bytes, then trim back to the last newline.
        assert len(data) <= 1024
        assert new_offset <= 1024
        # Last byte read must be a newline (no partial line)
        assert data.endswith(b"\n")
    finally:
        Path(path).unlink()


# ── _offset_key ───────────────────────────────────────────────────


def test_offset_key_distinguishes_paths():
    """Different eve.json paths must get different Redis keys —
    operators with multiple sensors need independent offsets."""
    k1 = _offset_key("/var/log/suricata/eve.json")
    k2 = _offset_key("/var/log/suricata-dmz/eve.json")
    assert k1 != k2
    assert k1.startswith("argus:suricata:tail_offset:")


def test_offset_key_deterministic():
    """Same path → same key across calls (would be useless if random)."""
    assert _offset_key("/x/eve.json") == _offset_key("/x/eve.json")
