"""Tests for /api/v1/stats (cycle 53).

The endpoint is a pure diagnostic surface that aggregates a few
counters the ops dashboard already reads separately. Tests run
in dev mode so ``require_api_key`` is a no-op and the routes are
reachable without headers.

Coverage matrix:
  1. /stats returns the full set of keys with the correct
     types, never 5xx.
  2. /stats rules_loaded >= 0 and agents_connected >= 0
     (sentinel contract from /healthcheck).
  3. /stats uptime_seconds is a non-negative int and matches
     the value reported by the same module when called twice
     (monotonic check).
  4. /stats pid matches os.getpid() at test time.
"""

from __future__ import annotations

import os

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_api_v1_stats_shape(app_client: AsyncClient) -> None:
    """``/stats`` returns the full contract with correct types.

    The endpoint must never 5xx — the same scrape-tool
    stability contract as ``/healthcheck``.
    """
    r = await app_client.get("/api/v1/stats")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {
        "version",
        "git_sha",
        "rules_loaded",
        "agents_connected",
        "uptime_seconds",
        "pid",
    }
    assert isinstance(body["version"], str)
    assert body["version"]  # non-empty
    assert isinstance(body["git_sha"], str)
    assert isinstance(body["rules_loaded"], int)
    assert isinstance(body["agents_connected"], int)
    assert isinstance(body["uptime_seconds"], int)
    assert isinstance(body["pid"], int)


async def test_api_v1_stats_counters_non_negative(app_client: AsyncClient) -> None:
    """``rules_loaded`` and ``agents_connected`` never report < 0.

    Mirrors the cycle-30 healthcheck contract: the endpoint
    surfaces per-field sentinels (``-1``) only when the data
    source is missing. The happy path is non-negative ints.
    """
    r = await app_client.get("/api/v1/stats")
    body = r.json()
    assert body["rules_loaded"] >= 0
    assert body["agents_connected"] >= 0


async def test_api_v1_stats_uptime_is_non_negative(app_client: AsyncClient) -> None:
    """``uptime_seconds`` is a non-negative int.

    Two consecutive reads must not decrease (monotonic). The
    endpoint floors the value at 0 so a clock regression or a
    test that back-dates ``STARTED_AT`` still gets a sane int.
    """
    r1 = await app_client.get("/api/v1/stats")
    r2 = await app_client.get("/api/v1/stats")
    assert r1.status_code == 200
    assert r2.status_code == 200
    u1 = r1.json()["uptime_seconds"]
    u2 = r2.json()["uptime_seconds"]
    assert u1 >= 0
    assert u2 >= 0
    # Monotonic check: the second read cannot predate the first.
    assert u2 >= u1


async def test_api_v1_stats_pid_matches_process(app_client: AsyncClient) -> None:
    """``pid`` matches ``os.getpid()`` at test time.

    Regression guard: if the endpoint ever drifts to a stale or
    static pid, log correlation against the PID will silently
    misroute. We assert exact equality — the test process and
    the ASGI process share a pid because the app runs in-process.
    """
    r = await app_client.get("/api/v1/stats")
    body = r.json()
    assert body["pid"] == os.getpid()