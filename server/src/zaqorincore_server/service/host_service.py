"""Service layer: business logic for the host table."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Host

log = get_logger(__name__)


async def upsert_on_hello(
    session: AsyncSession,
    *,
    agent_id: uuid.UUID,
    version: str,
) -> Host:
    """Look up an already-provisioned host without mutating it.

    This function name is kept for API compatibility, but authentication
    must happen before any host metadata is changed. A malformed or forged
    HELLO therefore cannot refresh ``last_seen_at`` or overwrite the
    advertised version of a real host.
    """
    del version
    result = await session.execute(select(Host).where(Host.id == agent_id))
    host = result.scalar_one_or_none()
    if host is None:
        raise ValueError("unknown agent")
    return host


async def mark_authenticated_hello(
    session: AsyncSession,
    host: Host,
    *,
    version: str,
) -> Host:
    """Record host liveness only after successful WebSocket authentication."""
    host.last_seen_at = datetime.now(timezone.utc)
    host.last_version = version
    await session.flush()
    log.info(
        "authenticated host hello updated",
        host_id=str(host.id),
        version=host.last_version,
        secret_present=bool(host.secret),
    )
    return host


async def get_host(session: AsyncSession, agent_id: uuid.UUID) -> Host | None:
    stmt = select(Host).where(Host.id == agent_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_hosts(session: AsyncSession, *, limit: int, offset: int) -> list[Host]:
    stmt = (
        select(Host)
        .order_by(Host.last_seen_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())
