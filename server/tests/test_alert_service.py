"""Tests for the alert writer."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from zaqorincore_server.detectors.alert_service import write_alert
from zaqorincore_server.models.alert import Alert
from zaqorincore_server.models.host import Host

pytestmark = pytest.mark.asyncio


async def _ensure_host(factory, host_id: uuid.UUID) -> None:
    async with factory() as s:
        s.add(Host(id=host_id, first_seen_at=datetime.now(tz=timezone.utc),
                   last_seen_at=datetime.now(tz=timezone.utc),
                   last_version="1.0"))
        await s.commit()


async def test_write_alert_inserts_row(engine):
    """write_alert persists a row with the expected fields."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()
    await _ensure_host(factory, host_id)

    alert_id = await write_alert(
        factory,
        detector="ssh_bruteforce",
        severity="medium",
        summary="Test alert from 1.2.3.4",
        detail={"source_ip": "1.2.3.4", "window_sec": 60},
        host_id=host_id,
        dedup_key="1.2.3.4",
        cooldown_sec=300,
    )
    assert isinstance(alert_id, uuid.UUID)

    async with factory() as session:
        result = await session.execute(select(Alert))
        rows = list(result.scalars().all())
    assert len(rows) == 1
    a = rows[0]
    assert a.id == alert_id
    assert a.detector == "ssh_bruteforce"
    assert a.severity == "medium"
    assert a.host_id == host_id
    assert a.detail["dedup_key"] == "1.2.3.4"
    assert a.detail["cooldown_sec"] == 300
    assert a.detail["source_ip"] == "1.2.3.4"


async def test_write_alert_without_host_id(engine):
    """host_id is nullable; alert can be host-less (e.g. global rule)."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    alert_id = await write_alert(
        factory,
        detector="test_rule",
        severity="low",
        summary="no host",
        detail={},
        host_id=None,
    )
    assert isinstance(alert_id, uuid.UUID)
    async with factory() as session:
        result = await session.execute(select(Alert))
        rows = list(result.scalars().all())
    assert rows[0].host_id is None
