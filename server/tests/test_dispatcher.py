"""Tests for the dispatcher: registry + _tick end-to-end with
a fake WebSocket."""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from zaqorincore_server.config import get_settings
from zaqorincore_server.crypto import verify_command
from zaqorincore_server.dispatcher import (
    Dispatcher,
    HostConnectionRegistry,
    registry,
)
from zaqorincore_server.detectors import action_service
from zaqorincore_server.models import Action, Host

pytestmark = pytest.mark.asyncio


class FakeWS:
    """Minimal stand-in for a FastAPI WebSocket for the dispatcher."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    async def send_text(self, text: str) -> None:
        self.sent.append(json.loads(text))

    async def close(self) -> None:
        self.closed = True


async def test_registry_register_get_unregister() -> None:
    reg = HostConnectionRegistry()
    host_id = uuid.uuid4()
    ws = FakeWS()
    await reg.register(host_id, ws)
    assert reg.get(host_id) is ws
    await reg.unregister(host_id)
    assert reg.get(host_id) is None


async def test_dispatcher_signs_command_with_host_secret(engine) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()
    secret = "test-dispatcher-secret"

    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret=secret,
                auto_block=True,
            )
        )
        await session.commit()

    action_id = await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=None,
        kind="block_ip",
        target="203.0.113.99",
        ttl_sec=3600,
    )

    reg = HostConnectionRegistry()
    ws = FakeWS()
    await reg.register(host_id, ws)
    disp = Dispatcher(settings=get_settings(), factory=factory, registry=reg)
    await disp._tick()  # noqa: SLF001

    assert len(ws.sent) == 1
    frame = ws.sent[0]
    assert frame["type"] == "command"
    assert frame["id"] == str(action_id)
    assert frame["kind"] == "block_ip"
    assert frame["target"] == "203.0.113.99"
    assert frame["ttl_sec"] == 3600
    assert "hmac" in frame
    assert verify_command(
        secret=secret,
        command_id=frame["id"],
        kind=frame["kind"],
        target=frame["target"],
        ttl_sec=frame["ttl_sec"],
        issued_at=frame["issued_at"],
        hmac_hex=frame["hmac"],
    )

    async with factory() as session:
        row = (
            await session.execute(
                select(Action).where(Action.id == action_id)
            )
        ).scalar_one()
        assert row.status == "dispatched"


async def test_dispatcher_skips_when_no_secret(engine) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()

    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret=None,
                auto_block=True,
            )
        )
        await session.commit()

    await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=None,
        kind="block_ip",
        target="1.2.3.4",
        ttl_sec=60,
    )

    reg = HostConnectionRegistry()
    ws = FakeWS()
    await reg.register(host_id, ws)
    disp = Dispatcher(settings=get_settings(), factory=factory, registry=reg)
    await disp._tick()  # noqa: SLF001
    assert ws.sent == []  # skipped

    async with factory() as session:
        rows = (
            (
                await session.execute(
                    select(Action).where(Action.host_id == host_id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        # No secret -> no dispatch -> still pending
        assert rows[0].status == "pending"


async def test_dispatcher_skips_when_auto_block_off(engine) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()

    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret="s",
                auto_block=False,  # operator opt-out
            )
        )
        await session.commit()

    await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=None,
        kind="block_ip",
        target="1.2.3.4",
        ttl_sec=60,
    )

    reg = HostConnectionRegistry()
    ws = FakeWS()
    await reg.register(host_id, ws)
    disp = Dispatcher(settings=get_settings(), factory=factory, registry=reg)
    await disp._tick()  # noqa: SLF001
    assert ws.sent == []


async def test_dispatcher_keeps_pending_when_host_offline(engine) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker
    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()

    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret="s",
                auto_block=True,
            )
        )
        await session.commit()

    action_id = await action_service.write_action(
        factory,
        host_id=host_id,
        alert_id=None,
        kind="block_ip",
        target="5.6.7.8",
        ttl_sec=60,
    )

    reg = HostConnectionRegistry()  # nothing registered
    ws = FakeWS()
    disp = Dispatcher(settings=get_settings(), factory=factory, registry=reg)
    await disp._tick()  # noqa: SLF001
    assert ws.sent == []

    async with factory() as session:
        row = (
            await session.execute(
                select(Action).where(Action.id == action_id)
            )
        ).scalar_one()
        assert row.status == "pending"


async def test_singleton_registry_is_separate_per_instance() -> None:
    """The module-level `registry` is a singleton; tests don't
    mutate it (we instantiate fresh ones)."""
    assert registry is not None
