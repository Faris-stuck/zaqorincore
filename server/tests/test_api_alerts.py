"""Tests for /api/v1/alerts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from zaqorincore_server.detectors.alert_service import write_alert
from zaqorincore_server.models.host import Host

pytestmark = pytest.mark.asyncio


async def _ensure_host(engine, host_id: uuid.UUID) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        s.add(Host(id=host_id, first_seen_at=datetime.now(tz=timezone.utc),
                   last_seen_at=datetime.now(tz=timezone.utc),
                   last_version="1.0"))
        await s.commit()


async def test_list_alerts_empty(app_client):
    r = await app_client.get("/api/v1/alerts")
    assert r.status_code == 200
    body = r.json()
    assert body == {"items": [], "next_before": None}


async def test_list_alerts_returns_persisted_alerts(app_client, engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    host_id = uuid.uuid4()
    await _ensure_host(engine, host_id)
    for i in range(3):
        await write_alert(
            factory,
            detector="ssh_bruteforce",
            severity="medium",
            summary=f"alert {i}",
            detail={"k": i},
            host_id=host_id,
        )
    r = await app_client.get("/api/v1/alerts")
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 3
    # Newest first.
    assert body["items"][0]["summary"] == "alert 2"


async def test_list_alerts_filter_by_detector(app_client, engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    h1, h2 = uuid.uuid4(), uuid.uuid4()
    await _ensure_host(engine, h1)
    await _ensure_host(engine, h2)
    await write_alert(
        factory, detector="ssh_bruteforce", severity="medium",
        summary="a", detail={}, host_id=h1,
    )
    await write_alert(
        factory, detector="other_rule", severity="low",
        summary="b", detail={}, host_id=h2,
    )
    r = await app_client.get("/api/v1/alerts", params={"detector": "ssh_bruteforce"})
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["detector"] == "ssh_bruteforce"
