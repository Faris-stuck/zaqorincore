"""Tests for /healthz, /readyz, and /healthz/deps."""

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


async def test_healthz_deps_returns_structured_body(app_client: AsyncClient) -> None:
    """/healthz/deps must always return a JSON body with a `deps` map,
    even when a dependency is unreachable. The HTTP status code may
    be 200 or 503 depending on probe results, but the body shape is
    stable so scrape tools never get an empty response.
    """
    r = await app_client.get("/healthz/deps")
    assert r.status_code in (200, 503)
    body = r.json()
    assert "status" in body
    assert "ok" in body
    assert isinstance(body["ok"], bool)
    assert "deps" in body
    assert isinstance(body["deps"], dict)
    # Postgres is wired through the engine fixture, so it should be ok.
    assert "postgres" in body["deps"]
    pg = body["deps"]["postgres"]
    assert "ok" in pg
    assert "latency_ms" in pg
    assert isinstance(pg["latency_ms"], (int, float))
    # Redis is not initialized in test mode, so it may be ok or not —
    # either way the entry must exist and have the latency_ms field.
    assert "redis" in body["deps"]
    redis = body["deps"]["redis"]
    assert "latency_ms" in redis
    if not redis["ok"]:
        assert "error" in redis


async def test_healthz_deps_body_consistency(app_client: AsyncClient) -> None:
    """The top-level `ok` field must agree with the per-dep `ok` values.
    A scrape tool should be able to trust `body.ok` without re-walking
    the deps map.
    """
    r = await app_client.get("/healthz/deps")
    body = r.json()
    dep_oks = [d["ok"] for d in body["deps"].values()]
    expected_ok = all(dep_oks)
    assert body["ok"] is expected_ok
    assert (body["status"] == "ok") is expected_ok


async def test_alerts_empty(app_client: AsyncClient) -> None:
    r = await app_client.get("/api/v1/alerts")
    assert r.status_code == 200
    assert r.json() == {"items": [], "next_before": None}
