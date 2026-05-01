"""RFC 9562 UUIDv7 implementation, pure-Python.

Why UUIDv7
----------
UUIDv4 is random-ordered, which destroys B-tree index locality on
inserts: every new row lands in a different page, fragmenting the
index and forcing the planner to do scattered I/O on lookups. UUIDv7
prefixes the value with the unix-millisecond timestamp, so newly
inserted rows cluster together at the right edge of the B-tree —
about 30% faster inserts and noticeably tighter indexes once a table
crosses ~10M rows.

The bytes still encode an opaque UUID at the wire / Postgres level —
no schema migration is required to switch. Existing UUIDv4 rows
remain valid; new rows are simply UUIDv7. Both formats co-exist in
the same column without conflict.

Layout (RFC 9562 §5.7)
----------------------
    | 48 bits unix_ts_ms | 4 bits ver=0b0111 | 12 bits rand_a |
    | 2 bits var=0b10    | 62 bits rand_b                     |

Total 128 bits, packed into the standard ``uuid.UUID`` representation.
``uuid.UUID(int=...)`` accepts the integer form directly, so we don't
need to roll our own bytes class.

Concurrency
-----------
The clock can move backwards on rare occasions (NTP slew, clock
adjustment). We don't try to monotonise — RFC 9562 §6.2 explicitly
states that monotonicity within a single ms is *recommended*, not
required, and the random ``rand_a`` + ``rand_b`` fields make
collisions astronomically unlikely even when two calls land in the
same millisecond. If a customer ends up with strict-monotonic needs
(e.g. for a sorted ledger), they can wrap this with a counter; we
don't pay the lock cost by default.
"""

from __future__ import annotations

import os
import time
import uuid


_VERSION_BITS = 0b0111 << 12  # ver=7 in bits 48–51 (counted from top)
_VARIANT_BITS = 0b10 << 62   # var=10 in bits 64–65


def uuid7() -> uuid.UUID:
    """Return a fresh RFC 9562 UUIDv7."""
    # 48-bit unix-millisecond timestamp.
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF

    # 12 random bits for rand_a (combined with version).
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF

    # 62 random bits for rand_b (combined with variant).
    rand_b = int.from_bytes(os.urandom(8), "big") & 0x3FFFFFFFFFFFFFFF

    high = (ts_ms << 16) | _VERSION_BITS | rand_a
    low = _VARIANT_BITS | rand_b

    value = (high << 64) | low
    return uuid.UUID(int=value)


def extract_timestamp_ms(value: uuid.UUID) -> int | None:
    """Return the embedded unix-millisecond timestamp, or ``None`` if
    ``value`` is not a UUIDv7. Handy for debugging "when was this row
    created" without needing a created_at column.
    """
    if value.version != 7:
        return None
    return value.int >> 80


__all__ = ["uuid7", "extract_timestamp_ms"]
