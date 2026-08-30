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


async def test_api_v1_healthcheck_shape(app_client: AsyncClient) -> None:
    """GET /api/v1/healthcheck returns the ops-dashboard summary.

    Contract: {ok: bool, version: str, rules_loaded: int, agents_connected: int}.
    The endpoint is always 200 so scrape tools get a stable body shape.
    """
    r = await app_client.get("/api/v1/healthcheck")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"ok", "version", "rules_loaded", "agents_connected"}
    assert isinstance(body["ok"], bool)
    assert isinstance(body["version"], str)
    assert body["version"]  # non-empty
    assert isinstance(body["rules_loaded"], int)
    assert isinstance(body["agents_connected"], int)


async def test_api_v1_healthcheck_counts_real_rules(app_client: AsyncClient) -> None:
    """rules_loaded reflects the actual filesystem under server/rules/builtin/.

    The bundled pack ships a non-zero number of *.yml rules; the count
    must be positive and must agree with what the helper would compute
    by walking the same directory.
    """
    from zaqorincore_server.api.v1.healthcheck import _count_yml_files, _DEFAULT_RULES_DIR

    r = await app_client.get("/api/v1/healthcheck")
    body = r.json()
    assert body["rules_loaded"] == _count_yml_files(_DEFAULT_RULES_DIR)
    # Sanity: the bundled pack is non-empty in stock main.
    assert body["rules_loaded"] > 0


async def test_api_v1_healthcheck_no_agents_in_tests(app_client: AsyncClient) -> None:
    """agents_connected is 0 when no WebSocket has registered.

    The test harness does not spin up an agent, so the dispatcher
    registry stays empty. The endpoint must report 0, not -1 or
    a stale value from a previous test (the registry is module-
    level, but the engine fixture resets the app per-test).
    """
    r = await app_client.get("/api/v1/healthcheck")
    body = r.json()
    assert body["agents_connected"] == 0
    assert body["ok"] is True
