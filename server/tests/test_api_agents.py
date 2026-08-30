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


# ---------------------------------------------------------------------------
# Cycle 48: GET /api/v1/agents/{agent_id}/health
# ---------------------------------------------------------------------------


async def test_api_v1_agent_health_unknown_id_returns_404(
    app_client: AsyncClient,
) -> None:
    """Random UUID with no Host row → 404 (not silent empty body).

    Operators mistyping an ID get a clear error rather than a
    payload that says ``connected: false`` and looks like a
    healthy response for a real-but-offline agent.
    """
    unknown = uuid.uuid4()
    r = await app_client.get(f"/api/v1/agents/{unknown}/health")
    assert r.status_code == 404
    body = r.json()
    # Standard cycle-28 error envelope is in play; the body is
    # not asserted strictly beyond carrying the requested UUID.
    assert str(unknown) in body.get("detail", "")


async def test_api_v1_agent_health_known_offline(
    app_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Known agent with no live WebSocket → status='offline'.

    The endpoint must not falsely report ``online`` just because
    the Host row exists. ``age_seconds`` is computed from
    ``last_seen_at`` and should be small for a freshly-inserted
    row.
    """
    from datetime import datetime, timezone

    from zaqorincore_server.models import Host

    agent_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    host = Host(
        id=agent_id,
        first_seen_at=now,
        last_seen_at=now,
        last_version="0.42.0",
        hostname="edge-node-09",
        auto_block=False,
    )
    session.add(host)
    await session.commit()

    r = await app_client.get(f"/api/v1/agents/{agent_id}/health")
    assert r.status_code == 200
    body = r.json()
    assert body["host_id"] == str(agent_id)
    assert body["connected"] is False
    assert body["status"] == "offline"
    assert body["last_version"] == "0.42.0"
    assert body["hostname"] == "edge-node-09"
    assert isinstance(body["last_seen_at"], str)
    assert "T" in body["last_seen_at"]
    # Just-inserted row: age must be a small non-negative integer.
    assert body["age_seconds"] is not None
    assert body["age_seconds"] >= 0
    assert body["age_seconds"] < 60


async def test_api_v1_agent_health_known_online(
    app_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Live WebSocket + fresh Host row → status='online'.

    We register a sentinel WebSocket so the registry returns
    truthy for this UUID, and the row's ``last_seen_at`` is
    ``now`` so ``age_seconds`` stays under the stale threshold.
    """
    from datetime import datetime, timedelta, timezone

    from zaqorincore_server.dispatcher import registry as agent_registry
    from zaqorincore_server.models import Host

    agent_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    # last_seen 5 seconds ago — well under the 300s threshold.
    host = Host(
        id=agent_id,
        first_seen_at=now - timedelta(minutes=10),
        last_seen_at=now - timedelta(seconds=5),
        last_version="0.42.0",
        hostname="edge-node-10",
        auto_block=False,
    )
    session.add(host)
    await session.commit()

    sentinel = object()
    await agent_registry.register(agent_id, sentinel)
    try:
        r = await app_client.get(f"/api/v1/agents/{agent_id}/health")
    finally:
        await agent_registry.unregister(agent_id)

    assert r.status_code == 200
    body = r.json()
    assert body["host_id"] == str(agent_id)
    assert body["connected"] is True
    assert body["status"] == "online"
    # age_seconds should be ~5, allow generous slack for CI jitter.
    assert body["age_seconds"] is not None
    assert 0 <= body["age_seconds"] < 60


async def test_api_v1_agent_health_stale_when_last_seen_too_old(
    app_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Live WebSocket but stale Host row → status='stale'.

    Models a wedged agent: the TCP socket is still up so the
    dispatcher still reports ``connected: true``, but HELLOs
    have not arrived in over 300 seconds so the row's
    ``last_seen_at`` is ancient.
    """
    from datetime import datetime, timedelta, timezone

    from zaqorincore_server.dispatcher import registry as agent_registry
    from zaqorincore_server.models import Host

    agent_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    # last_seen 1 hour ago — well past the 300s stale threshold.
    host = Host(
        id=agent_id,
        first_seen_at=now - timedelta(hours=2),
        last_seen_at=now - timedelta(hours=1),
        last_version="0.42.0",
        hostname="edge-node-11",
        auto_block=False,
    )
    session.add(host)
    await session.commit()

    sentinel = object()
    await agent_registry.register(agent_id, sentinel)
    try:
        r = await app_client.get(f"/api/v1/agents/{agent_id}/health")
    finally:
        await agent_registry.unregister(agent_id)

    assert r.status_code == 200
    body = r.json()
    assert body["connected"] is True
    # ``status`` flips to ``stale`` because age > _STALE_AFTER_SECONDS,
    # even though the socket is technically still up.
    assert body["status"] == "stale"
    assert body["age_seconds"] is not None
    assert body["age_seconds"] > 300