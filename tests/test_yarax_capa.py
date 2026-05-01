"""yara-x + capa wrapper (P2 #2.10) — tests.

The yara-x path uses the EICAR test string so we exercise a real
compile + scan round-trip without any binary fixtures. The capa path
is heavyweight (binary analysis) — we only exercise the
unavailable / size-cap / API-contract surface here; real-binary E2E
testing belongs in a separate slow-suite.
"""

from __future__ import annotations

import base64

import pytest

from src.intel.yarax_capa import (
    CapaResult,
    YaraMatch,
    extract_capabilities,
    is_available,
    scan_bytes,
)

pytestmark = pytest.mark.asyncio


# ── Availability ─────────────────────────────────────────────────────


def test_is_available_shape():
    info = is_available()
    assert set(info.keys()) == {"yara_x", "capa"}
    assert info["yara_x"] is True   # both libs installed in the CI venv
    assert info["capa"] is True


# ── yara-x scanning ─────────────────────────────────────────────────


_EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
_EICAR_RULE = '''
rule TestEicar {
  meta:
    description = "EICAR test pattern"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $eicar
}
'''


def test_yara_scan_eicar_match():
    matches = scan_bytes(_EICAR, rules_text=_EICAR_RULE)
    assert len(matches) == 1
    m = matches[0]
    assert isinstance(m, YaraMatch)
    assert m.rule == "TestEicar"
    # matched_strings shape: identifier@offset+length
    assert m.matched_strings, "expected at least one matched string"
    assert all("@" in s and "+" in s for s in m.matched_strings)


def test_yara_scan_no_match_on_clean_bytes():
    assert scan_bytes(b"hello world", rules_text=_EICAR_RULE) == []


def test_yara_scan_compiles_multiple_rules():
    rules = '''
    rule R1 { strings: $a = "alpha" condition: $a }
    rule R2 { strings: $b = "beta"  condition: $b }
    '''
    m = scan_bytes(b"alpha and beta together", rules_text=rules)
    rule_names = {x.rule for x in m}
    assert rule_names == {"R1", "R2"}


def test_to_dict_shape():
    matches = scan_bytes(_EICAR, rules_text=_EICAR_RULE)
    d = matches[0].to_dict()
    assert set(d.keys()) == {"rule", "namespace", "tags", "matched_strings"}


# ── capa availability + size cap ────────────────────────────────────


def test_capa_size_cap_rejects_oversized_input():
    """A 60 MB blob exceeds the configured 50 MB ceiling — return early
    with an error rather than spending minutes inside capa."""
    big = b"\x00" * (60 * 1024 * 1024)
    result = extract_capabilities(big)
    assert isinstance(result, CapaResult)
    assert result.error is not None and "ceiling" in result.error
    assert result.capabilities == []


def test_capa_handles_non_binary_input_gracefully():
    """Plain text isn't a PE/ELF/Mach-O. capa should fail-soft —
    return a CapaResult with an error string rather than raising."""
    result = extract_capabilities(b"this is not a binary file")
    assert isinstance(result, CapaResult)
    # Either available + capabilities empty + error set, or
    # the error path produced no capabilities.
    assert result.capabilities == []
    assert result.sample_sha256 is not None and len(result.sample_sha256) == 64


def test_capa_to_dict_shape():
    result = extract_capabilities(b"x")
    d = result.to_dict()
    assert set(d.keys()) >= {
        "available", "sample_sha256", "capabilities", "note", "error",
    }


# ── HTTP routes ──────────────────────────────────────────────────────


async def test_yara_availability_route(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/yara/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"yara_x": True, "capa": True}


async def test_yara_scan_route(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/yara/scan",
        json={
            "rules_text": _EICAR_RULE,
            "sample_b64": base64.b64encode(_EICAR).decode("ascii"),
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    matches = r.json()["matches"]
    assert any(m["rule"] == "TestEicar" for m in matches)


async def test_yara_scan_route_rejects_invalid_base64(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/yara/scan",
        json={"rules_text": _EICAR_RULE, "sample_b64": "%%%not-base64%%%"},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 400


async def test_capa_extract_route_handles_non_binary(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/capa/extract",
        json={"sample_b64": base64.b64encode(b"plain text").decode("ascii")},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sample_sha256"] is not None
    # Either an error from capa (non-binary input) or an empty
    # capabilities list — both are valid.
    assert body["capabilities"] == [] or body["error"] is not None


async def test_yara_route_requires_auth(client):
    r = await client.get("/api/v1/intel/yara/availability")
    assert r.status_code in (401, 403)
