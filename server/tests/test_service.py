"""Unit tests for the service layer."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from zaqorincore_server.models import Event, Host
from zaqorincore_server.schemas.wire import EventFrame, EventInner
from zaqorincore_server.service import event_service, host_service
from zaqorincore_server.service.event_service import DuplicateEvent

pytestmark = pytest.mark.asyncio


async def test_upsert_on_hello_inserts(session) -> None:
    agent_id = uuid.uuid4()
    host = await host_service.upsert_on_hello(
        session, agent_id=agent_id, version="1.0"
    )
    await session.commit()
    assert host.id == agent_id
    assert host.last_version == "1.0"


async def test_upsert_on_hello_updates_existing(session) -> None:
    agent_id = uuid.uuid4()
    h1 = await host_service.upsert_on_hello(
        session, agent_id=agent_id, version="1.0"
    )
    await session.commit()
    h2 = await host_service.upsert_on_hello(
        session, agent_id=agent_id, version="1.1"
    )
    await session.commit()
    assert h1.id == h2.id
    assert h2.last_version == "1.1"
    # first_seen_at should not change; last_seen_at may advance.
    assert h2.first_seen_at == h1.first_seen_at


async def test_persist_event_inserts(session) -> None:
    agent_id = uuid.uuid4()
    await host_service.upsert_on_hello(
        session, agent_id=agent_id, version="1.0"
    )
    await session.commit()

    eid = uuid.uuid4()
    frame = EventFrame(
        type="event",
        event=EventInner(
            event_schema="1.0",
            id=eid,
            timestamp=datetime.now(timezone.utc),
            host_id=agent_id,
            source="auth",
            raw="Accepted publickey for foo",
        ),
    )
    row = await event_service.persist_event(session, frame)
    assert row.id == eid
    assert row.source == "auth"


async def test_persist_event_duplicate_raises(session) -> None:
    agent_id = uuid.uuid4()
    await host_service.upsert_on_hello(
        session, agent_id=agent_id, version="1.0"
    )
    await session.commit()

    eid = uuid.uuid4()
    frame = EventFrame(
        type="event",
        event=EventInner(
            event_schema="1.0",
            id=eid,
            timestamp=datetime.now(timezone.utc),
            host_id=agent_id,
            source="auth",
            raw="x",
        ),
    )
    await event_service.persist_event(session, frame)
    with pytest.raises(DuplicateEvent):
        await event_service.persist_event(session, frame)
