"""Phase 4: PATCH /api/v1/hosts/{id} to toggle auto_block."""

from __future__ import annotations

import datetime as _dt
import uuid

import pytest

from zaqorincore_server.models import Host

pytestmark = pytest.mark.asyncio


async def _make_host(engine) -> uuid.UUID:
    host_id = uuid.uuid4()
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add(
            Host(
                id=host_id,
                first_seen_at=_dt.datetime.now(_dt.timezone.utc),
                last_seen_at=_dt.datetime.now(_dt.timezone.utc),
                secret="s",
                auto_block=False,
            )
        )
        await session.commit()
    return host_id


async def test_patch_toggle_auto_block_on(app_client, engine) -> None:
    host_id = await _make_host(engine)
    r = await app_client.patch(
        f"/api/v1/hosts/{host_id}",
        json={"auto_block": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auto_block"] is True
    # Confirm DB.
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        row = (
            await session.execute(select(Host).where(Host.id == host_id))
        ).scalar_one()
        assert row.auto_block is True


async def test_patch_toggle_auto_block_off(app_client, engine) -> None:
    host_id = await _make_host(engine)
    r = await app_client.patch(
        f"/api/v1/hosts/{host_id}", json={"auto_block": False}
    )
    assert r.status_code == 200
    assert r.json()["auto_block"] is False


async def test_patch_404_for_unknown_host(app_client) -> None:
    r = await app_client.patch(
        f"/api/v1/hosts/{uuid.uuid4()}", json={"auto_block": True}
    )
    assert r.status_code == 404


async def test_patch_400_for_empty_body(app_client, engine) -> None:
    host_id = await _make_host(engine)
    r = await app_client.patch(f"/api/v1/hosts/{host_id}", json={})
    assert r.status_code == 400


async def test_get_host_includes_auto_block(app_client, engine) -> None:
    host_id = await _make_host(engine)
    r = await app_client.get(f"/api/v1/hosts/{host_id}")
    assert r.status_code == 200
    assert r.json()["auto_block"] is False


async def test_list_hosts_includes_auto_block(app_client, engine) -> None:
    host_id = await _make_host(engine)
    r = await app_client.get("/api/v1/hosts")
    assert r.status_code == 200
    rows = r.json()
    assert any(h["id"] == str(host_id) for h in rows)
    for h in rows:
        assert "auto_block" in h
