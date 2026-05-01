"""Tests for the RFC 9562 UUIDv7 generator."""

from __future__ import annotations

import time
import uuid

from src.core.uuidv7 import extract_timestamp_ms, uuid7


def test_uuid7_returns_uuid_with_version_7():
    value = uuid7()
    assert isinstance(value, uuid.UUID)
    assert value.version == 7


def test_uuid7_variant_is_rfc4122():
    # RFC 9562 reuses the RFC 4122 variant bits (0b10).
    value = uuid7()
    # uuid.UUID.variant returns the string 'specified in RFC 4122' for 0b10.
    assert value.variant == uuid.RFC_4122


def test_uuid7_timestamp_round_trip():
    before_ms = int(time.time() * 1000)
    value = uuid7()
    after_ms = int(time.time() * 1000)

    extracted = extract_timestamp_ms(value)
    assert extracted is not None
    assert before_ms <= extracted <= after_ms


def test_uuid7_uniqueness_in_a_tight_loop():
    # 100k generations: every value must be unique.
    seen: set[uuid.UUID] = set()
    for _ in range(100_000):
        v = uuid7()
        assert v not in seen
        seen.add(v)
    assert len(seen) == 100_000


def test_uuid7_timestamp_prefix_is_monotonic_across_ms_boundaries():
    """When two UUIDs are generated > 1ms apart, the second one's
    string representation MUST sort lexicographically after the first.
    This is the property that gives UUIDv7 its B-tree locality
    advantage over UUIDv4.
    """
    a = uuid7()
    time.sleep(0.005)
    b = uuid7()
    assert str(a) < str(b)


def test_extract_timestamp_returns_none_for_uuid4():
    v4 = uuid.uuid4()
    assert extract_timestamp_ms(v4) is None


def test_extract_timestamp_returns_none_for_uuid1():
    v1 = uuid.uuid1()
    assert extract_timestamp_ms(v1) is None
