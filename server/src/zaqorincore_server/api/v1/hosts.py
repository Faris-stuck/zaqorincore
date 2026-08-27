"""GET /api/v1/hosts and /api/v1/hosts/{id}."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import func, select as sa_select

from ...db import get_session
from ...models import Event, Host
from ...service import host_service

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.get("")
async def list_hosts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    rows = await host_service.list_hosts(
        session, limit=limit, offset=offset
    )
    return [
        {
            "id": str(h.id),
            "first_seen_at": h.first_seen_at.isoformat(),
            "last_seen_at": h.last_seen_at.isoformat(),
            "last_version": h.last_version,
            "hostname": h.hostname,
        }
        for h in rows
    ]


@router.get("/{host_id}")
async def get_host(
    host_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict:
    host = await host_service.get_host(session, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    count = await session.scalar(
        sa_select(func.count(Event.id)).where(Event.host_id == host_id)
    )
    last_event = await session.scalar(
        sa_select(func.max(Event.occurred_at)).where(Event.host_id == host_id)
    )
    return {
        "id": str(host.id),
        "first_seen_at": host.first_seen_at.isoformat(),
        "last_seen_at": host.last_seen_at.isoformat(),
        "last_version": host.last_version,
        "hostname": host.hostname,
        "event_count": count or 0,
        "last_event_at": last_event.isoformat() if last_event else None,
    }
