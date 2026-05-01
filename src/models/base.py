"""SQLAlchemy base and shared model utilities."""

from __future__ import annotations


import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from src.core.uuidv7 import uuid7


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class UUIDMixin:
    """Primary-key mixin.

    Defaults to RFC 9562 UUIDv7 — timestamp-prefixed, so inserts cluster
    on the right edge of the B-tree instead of fragmenting the index
    the way UUIDv4 does. The wire format is identical to v4 (both are
    opaque 128-bit UUIDs), so existing v4 rows in the database stay
    valid — no migration needed. New rows simply land as v7.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid7,
    )
