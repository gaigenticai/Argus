"""Per-user feed subscriptions (P3 #3.4).

User-self-service subscriptions on top of the alert stream. Each row
is owned by a single user (the JWT subject), scoped to that user's
organization. The existing org-scoped notification_rules system is
unchanged — this is a thinner SDK-friendly layer for individual
analysts who want their own webhooks / email forwards.

Routes:
  POST   /api/v1/feed-subscriptions              create
  GET    /api/v1/feed-subscriptions              list (current user only)
  GET    /api/v1/feed-subscriptions/{id}         fetch (must own)
  PATCH  /api/v1/feed-subscriptions/{id}         update (must own)
  DELETE /api/v1/feed-subscriptions/{id}         delete (must own)
  POST   /api/v1/feed-subscriptions/{id}/test    dry-run match against
                                                  a sample alert payload

The matcher (``src.core.feed_subscription_match``) is the canonical
filter evaluator and is shared with the SDK / dispatch path.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import CurrentUser
from src.core.feed_subscription_match import match_alert
from src.core.tenant import get_system_org_id
from src.models.feed_subscription import FeedSubscription
from src.storage.database import get_session

router = APIRouter(prefix="/feed-subscriptions", tags=["Operations"])


# ── Pydantic schemas ────────────────────────────────────────────────


_ALLOWED_CHANNEL_TYPES = {"webhook", "email", "slack"}


class FeedSubscriptionChannel(BaseModel):
    """A delivery channel attached to a subscription."""
    type: str = Field(..., description=(
        "One of 'webhook', 'email', 'slack'."
    ))
    url: str | None = None        # webhook / slack
    address: str | None = None    # email
    secret: str | None = None     # webhook HMAC shared key


class FeedSubscriptionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = None
    filter: dict[str, Any] = Field(default_factory=dict)
    channels: list[FeedSubscriptionChannel] = Field(default_factory=list)
    active: bool = True


class FeedSubscriptionUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    filter: dict[str, Any] | None = None
    channels: list[FeedSubscriptionChannel] | None = None
    active: bool | None = None


class FeedSubscriptionResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    filter: dict[str, Any]
    channels: list[dict[str, Any]]
    active: bool
    last_dispatched_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FeedSubscriptionTestRequest(BaseModel):
    alert: dict[str, Any]


class FeedSubscriptionTestResponse(BaseModel):
    matches: bool


# ── Helpers ─────────────────────────────────────────────────────────


def _validate_channels(
    channels: list[FeedSubscriptionChannel],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ch in channels:
        if ch.type not in _ALLOWED_CHANNEL_TYPES:
            raise HTTPException(
                422,
                f"channel type {ch.type!r} not allowed; pick one of "
                f"{sorted(_ALLOWED_CHANNEL_TYPES)}",
            )
        if ch.type in {"webhook", "slack"} and not ch.url:
            raise HTTPException(
                422,
                f"channel type {ch.type!r} requires url",
            )
        if ch.type == "email" and not ch.address:
            raise HTTPException(422, "email channel requires address")
        out.append(ch.model_dump(exclude_none=True))
    return out


async def _load_owned(
    sub_id: uuid.UUID, user_id: uuid.UUID, db: AsyncSession,
) -> FeedSubscription:
    sub = await db.get(FeedSubscription, sub_id)
    if sub is None or sub.user_id != user_id:
        raise HTTPException(404, "feed subscription not found")
    return sub


# ── Routes ──────────────────────────────────────────────────────────


@router.post("", response_model=FeedSubscriptionResponse, status_code=201)
async def create_subscription(
    body: FeedSubscriptionCreate,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    org_id = await get_system_org_id(db)
    sub = FeedSubscription(
        user_id=user.id,
        organization_id=org_id,
        name=body.name.strip(),
        description=body.description,
        filter=body.filter or {},
        channels=_validate_channels(body.channels or []),
        active=body.active,
    )
    db.add(sub)
    await db.commit()
    await db.refresh(sub)
    return sub


@router.get("", response_model=list[FeedSubscriptionResponse])
async def list_subscriptions(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    rows = (await db.execute(
        select(FeedSubscription)
        .where(FeedSubscription.user_id == user.id)
        .order_by(FeedSubscription.created_at.desc())
    )).scalars().all()
    return list(rows)


@router.get("/{sub_id}", response_model=FeedSubscriptionResponse)
async def get_subscription(
    sub_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    return await _load_owned(sub_id, user.id, db)


@router.patch("/{sub_id}", response_model=FeedSubscriptionResponse)
async def update_subscription(
    sub_id: uuid.UUID,
    body: FeedSubscriptionUpdate,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    sub = await _load_owned(sub_id, user.id, db)
    if body.name is not None:
        sub.name = body.name.strip()
    if body.description is not None:
        sub.description = body.description
    if body.filter is not None:
        sub.filter = body.filter
    if body.channels is not None:
        sub.channels = _validate_channels(body.channels)
    if body.active is not None:
        sub.active = body.active
    await db.commit()
    await db.refresh(sub)
    return sub


@router.delete("/{sub_id}", status_code=204)
async def delete_subscription(
    sub_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    sub = await _load_owned(sub_id, user.id, db)
    await db.delete(sub)
    await db.commit()
    return None


@router.post(
    "/{sub_id}/test", response_model=FeedSubscriptionTestResponse,
)
async def test_subscription(
    sub_id: uuid.UUID,
    body: FeedSubscriptionTestRequest,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Dry-run a sample alert payload against this subscription's filter.
    No dispatch happens — just tells the SDK whether the filter would
    have matched."""
    sub = await _load_owned(sub_id, user.id, db)
    return FeedSubscriptionTestResponse(
        matches=match_alert(body.alert or {}, sub.filter or {}),
    )
