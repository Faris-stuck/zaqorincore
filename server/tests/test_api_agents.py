"""Tests for GET /api/v1/agents (cycle 31).

The endpoint returns a list of currently connected agents
(those with an open WebSocket on the dispatcher
``HostConnectionRegistry``) enriched with their Host row
metadata. Tests run in dev mode (``ZAQORIN_API_KEY`` unset,
``require_api_key`` is a no-op) so they exercise the route
end-to-end without any auth headers.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.asyncio


async def test_api_v1_agents_empty_when_no_agents_connected(
    app_client: AsyncClient,
) -> None:
    """Empty registry → empty agents list, count == 0.

    The test harness does not spin up a WebSocket; the
    dispatcher registry starts empty for every test.
    """
    r = await app_client.get("/api/v1/agents")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"agents", "count"}
    assert body["agents"] == []
    assert body["count"] == 0


async def test_api_v1_agents_enriches_with_host_row(
    app_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Connected agent surfaces its Host row metadata.

    We:
      1. Insert a Host row for a synthetic agent_id.
      2. Register a fake WebSocket on the dispatcher.
      3. Hit /api/v1/agents and assert the metadata round-
         trips through the endpoint.
    """
    from zaqorincore_server.dispatcher import registry as agent_registry
    from zaqorincore_server.models import Host
    from datetime import datetime, timezone

    agent_id = uuid.uuid4()
    # Insert a Host row directly via the test session.
    now = datetime.now(timezone.utc)
    host = Host(
        id=agent_id,
        first_seen_at=now,
        last_seen_at=now,
        last_version="0.42.0",
        hostname="edge-node-07",
        auto_block=False,
    )
    session.add(host)
    await session.commit()

    # Register a placeholder WebSocket. We use ``object()`` —
    # the endpoint only reads host_ids, never the socket
    # itself, so any sentinel works.
    sentinel = object()
    try:
        await agent_registry.register(agent_id, sentinel)
        try:
            r = await app_client.get("/api/v1/agents")
        finally:
            await agent_registry.unregister(agent_id)
    except Exception:
        # If registration raised, make sure we still clean up.
        raise

    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert len(body["agents"]) == 1
    entry = body["agents"][0]
    assert entry["host_id"] == str(agent_id)
    assert entry["connected"] is True
    assert entry["last_version"] == "0.42.0"
    assert entry["hostname"] == "edge-node-07"
    # ISO 8601 string with timezone marker.
    assert isinstance(entry["last_seen_at"], str)
    assert "T" in entry["last_seen_at"]


async def test_api_v1_agents_connected_without_host_row_degrades(
    app_client: AsyncClient,
) -> None:
    """Connected host with no DB row → metadata fields are null.

    Defends the contract: the endpoint never fails the whole
    list just because one host row is missing (e.g. DB hiccup
    or a race during HELLO). The host still appears with
    ``connected: true`` so operators know the WebSocket is up.
    """
    from zaqorincore_server.dispatcher import registry as agent_registry

    ghost_id = uuid.uuid4()
    sentinel = object()
    await agent_registry.register(ghost_id, sentinel)
    try:
        r = await app_client.get("/api/v1/agents")
    finally:
        await agent_registry.unregister(ghost_id)

    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    entry = body["agents"][0]
    assert entry["host_id"] == str(ghost_id)
    assert entry["connected"] is True
    assert entry["last_seen_at"] is None
    assert entry["last_version"] is None
    assert entry["hostname"] is None


async def test_api_v1_agents_count_matches_healthcheck(
    app_client: AsyncClient,
) -> None:
    """agents.count agrees with /api/v1/healthcheck.agents_connected.

    Two endpoints, two views of the same registry. They MUST
    agree on the live count so an operator alerting on one
    isn't blindsided by drift on the other.
    """
    from zaqorincore_server.dispatcher import registry as agent_registry

    a, b = uuid.uuid4(), uuid.uuid4()
    await agent_registry.register(a, object())
    await agent_registry.register(b, object())
    try:
        agents_r = await app_client.get("/api/v1/agents")
        health_r = await app_client.get("/api/v1/healthcheck")
    finally:
        await agent_registry.unregister(a)
        await agent_registry.unregister(b)

    agents_body = agents_r.json()
    health_body = health_r.json()
    assert agents_body["count"] == 2
    assert health_body["agents_connected"] == 2
    assert health_body["agents_connected"] == agents_body["count"]