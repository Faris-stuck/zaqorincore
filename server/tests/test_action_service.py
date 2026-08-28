"""Tests for action_service write/mark_* helpers."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from zaqorincore_server.detectors import action_service
from zaqorincore_server.models import Action, Alert, Host

pytestmark = pytest.mark.asyncio


async def test_write_action_inserts_pending_row(engine) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    # We need a host for the FK.
    host_id = uuid.uuid4()
    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=__import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ),
                last_seen_at=__import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ),
                secret="test-secret",
            )
        )
        await session.commit()
    action_id = await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=None,
        kind="block_ip",
        target="1.2.3.4",
        ttl_sec=3600,
    )
    async with factory() as session:
        row = (
            await session.execute(select(Action).where(Action.id == action_id))
        ).scalar_one()
        assert row.status == "pending"
        assert row.target == "1.2.3.4"
        assert row.ttl_sec == 3600


async def test_mark_dispatched_then_applied(engine) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()
    import datetime as _dt

    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret="s",
            )
        )
        await session.commit()
    action_id = await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=None,
        kind="block_ip",
        target="2.2.2.2",
        ttl_sec=60,
    )
    assert await action_service.mark_dispatched(factory, action_id)
    # Second call is a no-op (status is no longer pending).
    assert not await action_service.mark_dispatched(factory, action_id)
    assert await action_service.mark_applied(factory, action_id)
    async with factory() as session:
        row = (
            await session.execute(select(Action).where(Action.id == action_id))
        ).scalar_one()
        assert row.status == "applied"
        assert row.acked_at is not None
        assert row.sent_at is not None


async def test_mark_failed(engine) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()
    import datetime as _dt

    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret="s",
            )
        )
        await session.commit()
    action_id = await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=None,
        kind="block_ip",
        target="3.3.3.3",
        ttl_sec=60,
    )
    await action_service.mark_dispatched(factory, action_id)
    assert await action_service.mark_failed(factory, action_id, "iptables: permission denied")
    async with factory() as session:
        row = (
            await session.execute(select(Action).where(Action.id == action_id))
        ).scalar_one()
        assert row.status == "failed"
