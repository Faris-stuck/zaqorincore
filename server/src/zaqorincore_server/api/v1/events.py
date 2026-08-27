"""GET /api/v1/events."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_session
from ...service import event_service

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.get("")
async def list_events(
    host: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    rows = await event_service.list_events(
        session,
        host_id=host,
        since=since,
        limit=limit,
        offset=offset,
    )
    return [
        {
            "id": str(r.id),
            "host_id": str(r.host_id),
            "schema": r.schema,
            "occurred_at": r.occurred_at.isoformat(),
            "received_at": r.received_at.isoformat(),
            "source": r.source,
            "raw": r.raw,
            "metadata": r.metadata_,
        }
        for r in rows
    ]
