"""GET /api/v1/alerts — list alerts (Phase 3 real implementation).

Supports cursor pagination by `created_at` (descending — newest
first) and filters: `host_id`, `detector`, `since`, `until`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ...db import get_session_factory
from ...models.alert import Alert
from ...security import require_api_key

router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_api_key)],
)


@router.get("")
async def list_alerts(
    host_id: uuid.UUID | None = None,
    detector: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> dict:
    """List alerts, newest first.

    Returns a dict with `items` and `next_before` cursor. If
    `next_before` is null, the caller has reached the end.
    """
    factory = get_session_factory()
    async with factory() as session:
        stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit + 1)
        if host_id is not None:
            stmt = stmt.where(Alert.host_id == host_id)
        if detector is not None:
            stmt = stmt.where(Alert.detector == detector)
        if since is not None:
            stmt = stmt.where(Alert.created_at >= since)
        if until is not None:
            stmt = stmt.where(Alert.created_at < until)
        result = await session.execute(stmt)
        rows = list(result.scalars().all())

    has_more = len(rows) > limit
    page = rows[:limit]
    next_before = page[-1].created_at.isoformat() if has_more and page else None
    return {
        "items": [
            {
                "id": str(a.id),
                "host_id": str(a.host_id) if a.host_id else None,
                "detector": a.detector,
                "severity": a.severity,
                "summary": a.summary,
                "detail": a.detail,
                "created_at": a.created_at.isoformat(),
                "acknowledged_at": (
                    a.acknowledged_at.isoformat() if a.acknowledged_at else None
                ),
            }
            for a in page
        ],
        "next_before": next_before,
    }
