"""Pagination helper (Audit B6).

Returns ``X-Total-Count`` header and applies `limit / offset` clauses
consistently across list endpoints. Routes that accept SIEM exports or
UI pagination should use ``paginated_response`` rather than returning
raw lists.

Usage::

    from src.core.pagination import paginated_response, parse_paging
    paging = parse_paging(limit=limit, offset=offset)
    rows, total = await paginated_select(db, base_query, paging)
    return paginated_response(rows, total, paging, response)

The helper sets ``X-Total-Count`` and ``X-Page-Limit`` /
``X-Page-Offset`` headers so clients can paginate without an extra
``COUNT(*)`` round-trip.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from fastapi import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class Paging:
    limit: int
    offset: int


def parse_paging(*, limit: int, offset: int, max_limit: int = 500) -> Paging:
    return Paging(
        limit=max(1, min(int(limit), max_limit)),
        offset=max(0, int(offset)),
    )


async def paginated_select(
    db: AsyncSession, query, paging: Paging
) -> tuple[list, int]:
    """Run ``query`` paged + a separate COUNT for total. Returns (rows, total).

    The count query uses the same WHERE clause but selects ``count(*)``.
    """
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()
    rows = (
        await db.execute(query.limit(paging.limit).offset(paging.offset))
    ).scalars().all()
    return list(rows), int(total)


def paginated_response(
    rows: Sequence[Any],
    total: int,
    paging: Paging,
    response: Response,
) -> list[Any]:
    """Inject pagination headers and return the row list unchanged.

    Clients can read ``X-Total-Count`` to know the unpaged size.
    """
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Page-Limit"] = str(paging.limit)
    response.headers["X-Page-Offset"] = str(paging.offset)
    return list(rows)


__all__ = ["Paging", "parse_paging", "paginated_select", "paginated_response"]
