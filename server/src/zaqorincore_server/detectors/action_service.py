"""Action persistence helpers.

Action lifecycle:
  pending   — inserted by the detector runner after write_alert
  dispatched — dispatcher has sent the COMMAND frame to the agent
  applied   — agent sent command_ack(status=applied)
  failed    — agent sent command_ack(status=failed) OR dispatcher
              gave up after max attempts (Phase 4 doesn't retry yet
              so "failed" today is just the agent reporting failure)

`write_action` returns the new Action id. The caller (the
detector runner) is expected to persist the Alert first and
only then call write_action so the FK to alerts is real.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models.action import Action


async def write_action(
    factory: async_sessionmaker[AsyncSession],
    *,
    host_id: uuid.UUID,
    alert_id: uuid.UUID | None,
    kind: str,
    target: str,
    ttl_sec: int | None,
) -> uuid.UUID:
    """Insert one action row in 'pending' state. Returns the new id."""
    new_id = uuid.uuid4()
    async with factory() as session:
        action = Action(
            id=new_id,
            host_id=host_id,
            alert_id=alert_id,
            kind=kind,
            target=target,
            ttl_sec=ttl_sec,
            status="pending",
        )
        session.add(action)
        await session.commit()
    return new_id


async def mark_dispatched(
    factory: async_sessionmaker[AsyncSession],
    action_id: uuid.UUID,
) -> bool:
    """Flip pending -> dispatched. Returns True if a row was updated."""
    async with factory() as session:
        stmt = (
            update(Action)
            .where(Action.id == action_id, Action.status == "pending")
            .values(
                status="dispatched",
                sent_at=datetime.now(timezone.utc),
            )
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount > 0


async def mark_applied(
    factory: async_sessionmaker[AsyncSession],
    action_id: uuid.UUID,
) -> bool:
    async with factory() as session:
        stmt = (
            update(Action)
            .where(Action.id == action_id, Action.status == "dispatched")
            .values(
                status="applied",
                acked_at=datetime.now(timezone.utc),
            )
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount > 0


async def mark_failed(
    factory: async_sessionmaker[AsyncSession],
    action_id: uuid.UUID,
    reason: str | None = None,
) -> bool:
    async with factory() as session:
        stmt = (
            update(Action)
            .where(Action.id == action_id, Action.status == "dispatched")
            .values(
                status="failed",
                acked_at=datetime.now(timezone.utc),
            )
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount > 0


async def get_action(
    factory: async_sessionmaker[AsyncSession],
    action_id: uuid.UUID,
) -> Action | None:
    async with factory() as session:
        stmt = select(Action).where(Action.id == action_id)
        return (await session.execute(stmt)).scalar_one_or_none()
