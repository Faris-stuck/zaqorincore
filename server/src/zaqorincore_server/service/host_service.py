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
    """Update an already-provisioned host after authentication.

    Hosts are intentionally NOT created during an unauthenticated
    WebSocket handshake. This prevents an attacker from spraying
    random UUIDs into the hosts table and obtaining a durable DB row.
    Provisioning must create the host first and establish its secret.
    """
    now = datetime.now(timezone.utc)
    result = await session.execute(select(Host).where(Host.id == agent_id))
    host = result.scalar_one_or_none()
    if host is None:
        raise ValueError("unknown agent")

    host.last_seen_at = now
    host.last_version = version
    await session.flush()
    await session.refresh(host)
    log.info(
        "host hello updated",
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
