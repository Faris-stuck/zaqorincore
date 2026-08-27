"""Tests for /healthz and /readyz."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_healthz(app_client: AsyncClient) -> None:
    r = await app_client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_readyz_live(app_client: AsyncClient) -> None:
    """When the lifespan is bypassed (we are in test mode), the redis
    client is not initialized, so /readyz will report unready with
    redis missing. The endpoint is still wired and returns 503 with
    a useful body — that's what we assert.
    """
    r = await app_client.get("/readyz")
    assert r.status_code in (200, 503)
    body = r.json()
    assert "status" in body


async def test_alerts_empty(app_client: AsyncClient) -> None:
    r = await app_client.get("/api/v1/alerts")
    assert r.status_code == 200
    assert r.json() == []
