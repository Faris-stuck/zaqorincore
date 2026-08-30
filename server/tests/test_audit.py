"""Tests for ``/api/v1/audit`` (cycle 19).

The endpoint is read-only over the in-memory ``audit`` module.
These tests cover:
1. Empty buffer returns ``count: 0`` with empty items.
2. ``record()`` makes entries visible via the endpoint.
3. ``actor`` substring filter narrows the result set.
4. ``limit`` query parameter caps the response size.
5. ``since`` filter drops older entries.

Each test starts from a clean audit buffer via the
``_clean_audit`` fixture so tests don't leak state into each
other.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient

from zaqorincore_server import audit

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _clean_audit():
    """Wipe the audit buffer around every test.

    The ``audit`` module uses module-level state; without
    this fixture, one test's ``record()`` calls would leak
    into the next.
    """
    audit.reset()
    yield
    audit.reset()


async def test_audit_empty_returns_zero_count(app_client: AsyncClient) -> None:
    """No recorded entries → ``count: 0``, ``items: []``."""
    r = await app_client.get("/api/v1/audit")
    assert r.status_code == 200
    body = r.json()
    assert body == {"count": 0, "items": []}


async def test_audit_records_are_visible(app_client: AsyncClient) -> None:
    """``record()`` + ``GET /api/v1/audit`` round-trips."""
    audit.record(
        actor="write",
        action="create canary",
        target="canary-1",
        status=201,
    )
    audit.record(
        actor="read",
        action="GET /api/v1/events",
        target="-",
        status=200,
    )

    r = await app_client.get("/api/v1/audit")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    # Newest-first ordering.
    actors = [it["actor"] for it in body["items"]]
    assert actors == ["read", "write"]
    actions = [it["action"] for it in body["items"]]
    assert "create canary" in actions
    assert "GET /api/v1/events" in actions


async def test_audit_actor_filter(app_client: AsyncClient) -> None:
    """``?actor=write`` narrows to write-role entries only."""
    audit.record(actor="write", action="PATCH host", target="h1")
    audit.record(actor="read", action="GET events", target="-")
    audit.record(actor="write", action="POST canary", target="c2")

    r = await app_client.get("/api/v1/audit?actor=write")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert {it["actor"] for it in body["items"]} == {"write"}


async def test_audit_limit_caps_response(app_client: AsyncClient) -> None:
    """``?limit=N`` returns at most N items."""
    for i in range(5):
        audit.record(actor="read", action=f"call-{i}", target=f"t-{i}")

    r = await app_client.get("/api/v1/audit?limit=2")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert len(body["items"]) == 2
    # Newest-first: last two recorded are 3 and 4.
    actions = [it["action"] for it in body["items"]]
    assert actions == ["call-4", "call-3"]


async def test_audit_since_filter_drops_old(app_client: AsyncClient) -> None:
    """``?since=<timestamp>`` excludes older entries.

    ``audit.record()`` stamps entries with the current UTC
    time, so we filter on ``now`` and on ``now - 1h`` and
    confirm both keep the recent entry (since the entry
    was recorded during the test).
    """
    audit.record(actor="write", action="recent", target="-")

    # ``+`` in ISO-8601 offsets must be URL-encoded; use
    # ``quote`` to keep the test honest about what a real
    # HTTP client would send.
    from urllib.parse import quote

    now = datetime.now(timezone.utc)
    future = quote((now + timedelta(hours=1)).isoformat())
    r = await app_client.get(f"/api/v1/audit?since={future}")
    assert r.status_code == 200
    # Future cutoff excludes everything.
    assert r.json() == {"count": 0, "items": []}

    past = quote((now - timedelta(hours=1)).isoformat())
    r = await app_client.get(f"/api/v1/audit?since={past}")
    assert r.status_code == 200
    assert r.json()["count"] == 1


async def test_audit_action_filter(app_client: AsyncClient) -> None:
    """``?action=<substr>`` narrows to matching action entries.

    Cycle 19 added the ``action`` query param but no test for it;
    cycle 21 closes that gap.
    """
    audit.record(actor="write", action="POST canary", target="c1")
    audit.record(actor="read", action="GET events", target="-")
    audit.record(actor="write", action="DELETE canary", target="c2")

    r = await app_client.get("/api/v1/audit?action=canary")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    actions = {it["action"] for it in body["items"]}
    assert actions == {"POST canary", "DELETE canary"}


async def test_audit_action_and_actor_combined(app_client: AsyncClient) -> None:
    """``?actor=X&action=Y`` AND-combines the two substring filters."""
    audit.record(actor="write", action="POST canary", target="c1")
    audit.record(actor="write", action="GET events", target="-")
    audit.record(actor="read", action="POST canary", target="c2")

    r = await app_client.get("/api/v1/audit?actor=write&action=canary")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["items"][0]["actor"] == "write"
    assert body["items"][0]["action"] == "POST canary"


async def test_audit_invalid_since_rejected(app_client: AsyncClient) -> None:
    """Garbage ``?since=`` value returns 422 (not 500).

    FastAPI / Pydantic validates the ``datetime`` query param at
    the boundary; malformed ISO-8601 inputs are rejected with
    422 *before* the handler runs. This test pins that contract
    so a future refactor that loosens parsing (e.g. swallowing
    bad timestamps inside the handler) gets caught.
    """
    audit.record(actor="write", action="noop", target="-")

    r = await app_client.get("/api/v1/audit?since=not-a-timestamp")
    # 422 = Unprocessable Entity; never 500 (crash).
    assert r.status_code == 422


async def test_audit_limit_bounds_enforced(app_client: AsyncClient) -> None:
    """``limit`` outside ``[1, 1000]`` is rejected by FastAPI.

    The Query declares ``ge=1, le=1000``; this test pins the
    contract so future refactors don't silently widen it.
    """
    r = await app_client.get("/api/v1/audit?limit=0")
    assert r.status_code == 422

    r = await app_client.get("/api/v1/audit?limit=1001")
    assert r.status_code == 422