"""Service layer: business logic for the host table."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..crypto import new_host_secret
from ..logging import get_logger
from ..models import Host

log = get_logger(__name__)


async def upsert_on_hello(
    session: AsyncSession,
    *,
    agent_id: uuid.UUID,
    version: str,
) -> Host:
    """Insert the host if missing, otherwise bump last_seen_at and
    last_version. Returns the (possibly newly created) Host row.

    On first insert, generates a per-host `secret` used by the
    dispatcher to HMAC-sign COMMAND frames. The agent bootstraps
    this secret out-of-band (the WS handler sends it back in a
    `X-Zaqorin-Secret` response header on the WebSocket upgrade).
    """
    now = datetime.now(timezone.utc)
    # Build a single INSERT that fills `secret` on the new branch
    # (NULL on conflict via DO NOTHING semantics) and bumps the
    # existing row's last_seen_at/last_version.
    new_secret = new_host_secret()
    stmt = (
        pg_insert(Host)
        .values(
            id=agent_id,
            first_seen_at=now,
            last_seen_at=now,
            last_version=version,
            secret=new_secret,
            auto_block=False,
        )
        .on_conflict_do_update(
            index_elements=[Host.id],
            set_={"last_seen_at": now, "last_version": version},
        )
        .returning(Host)
    )
    result = await session.execute(stmt)
    host = result.scalar_one()
    # pg_insert().returning() returns a freshly-built Host instance;
    # its column values reflect the UPDATE branch when there was a
    # conflict. SQLAlchemy may or may not expire the cached state of
    # the previous Host in the same session, so refresh explicitly.
    await session.refresh(host)
    log.info(
        "host upserted",
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
