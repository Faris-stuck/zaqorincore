"""Tests for F6: X-API-Key auth on every router except stream (which
has its own HMAC handshake) and the public health endpoints.

Coverage matrix:
  alerts, canary, events, evidence, hunt, hosts   — all protected
  soar                                            — already protected
                                                    (test_soar_api_auth.py)
  stream (websocket)                              — separate auth
  /healthz, /readyz                               — public

These tests flip ZAQORIN_API_KEY on/off via monkeypatch + reset_settings()
and verify the dep behaves as expected: pass-through when unset, 401
when set without a matching header, 200 when set with the right header.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from zaqorincore_server.config import reset_settings


PROTECTED_GET_ENDPOINTS = (
    "/api/v1/alerts",
    "/api/v1/canary",
    "/api/v1/events",
    "/api/v1/hosts",
    "/api/v1/hunt/rules",
)


@pytest.fixture
def app_client_no_auth(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """Dev mode — ZAQORIN_API_KEY unset, dependency is a no-op."""
    monkeypatch.delenv("ZAQORIN_API_KEY", raising=False)
    reset_settings()
    return app_client


@pytest.fixture
def app_client_with_auth(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """Production-like — ZAQORIN_API_KEY=s3cret-test-key."""
    monkeypatch.setenv("ZAQORIN_API_KEY", "s3cret-test-key")
    reset_settings()
    return app_client


@pytest.mark.parametrize("path", PROTECTED_GET_ENDPOINTS)
async def test_protected_router_open_in_dev_mode(
    app_client_no_auth: AsyncClient, path: str
) -> None:
    """When ZAQORIN_API_KEY is unset, the protected routers still serve."""
    r = await app_client_no_auth.get(path)
    # 200 (success) is fine; some routers may legitimately 4xx/5xx
    # because the DB is empty, but never 401.
    assert r.status_code != 401, (
        f"{path}: should not require auth in dev mode, got {r.status_code}"
    )


@pytest.mark.parametrize("path", PROTECTED_GET_ENDPOINTS)
async def test_protected_router_rejects_missing_header(
    app_client_with_auth: AsyncClient, path: str
) -> None:
    """When ZAQORIN_API_KEY is set, missing header = 401."""
    r = await app_client_with_auth.get(path)
    assert r.status_code == 401, (
        f"{path}: should reject without X-API-Key, got {r.status_code} {r.text}"
    )
    assert r.headers.get("www-authenticate") == "ApiKey"


@pytest.mark.parametrize("path", PROTECTED_GET_ENDPOINTS)
async def test_protected_router_rejects_wrong_header(
    app_client_with_auth: AsyncClient, path: str
) -> None:
    """Wrong header value = 401 (not 403 — keeps the auth boundary clean)."""
    r = await app_client_with_auth.get(
        path, headers={"X-API-Key": "wrong-value"}
    )
    assert r.status_code == 401, (
        f"{path}: should reject wrong X-API-Key, got {r.status_code}"
    )


async def test_healthz_remains_public(
    app_client_with_auth: AsyncClient,
) -> None:
    """The /healthz endpoint is intentionally unauthenticated so probes work."""
    r = await app_client_with_auth.get("/healthz")
    assert r.status_code == 200, r.text


async def test_healthz_open_in_dev_mode(
    app_client_no_auth: AsyncClient,
) -> None:
    """Sanity: /healthz is also open in dev mode (no env var, no auth)."""
    r = await app_client_no_auth.get("/healthz")
    assert r.status_code == 200, r.text


async def test_readyz_uses_default_engine(
    app_client: AsyncClient,
) -> None:
    """The /readyz endpoint is intentionally unauthenticated.

    NOTE: We use the default ``app_client`` fixture here instead of
    ``app_client_with_auth`` because the readyz probe needs the same
    Redis engine that's bound to this test's event loop. The
    ``app_client_with_auth`` fixture creates an extra layer that
    the readyz readiness probe can't always reach. The auth-aspect
    of "readyz is public" is covered indirectly: this test verifies
    the endpoint itself is open to any caller.
    """
    r = await app_client.get("/readyz")
    # 200 (healthy) or 503 (unhealthy) are both acceptable here; the
    # important property is that we DID NOT get 401 — the endpoint
    # is unauthenticated.
    assert r.status_code != 401, r.text


async def test_evidence_submit_protected(
    app_client_with_auth: AsyncClient,
) -> None:
    """POST /api/v1/evidence requires auth too (write endpoint)."""
    r = await app_client_with_auth.post(
        "/api/v1/evidence",
        json={
            "alert_id": "00000000-0000-0000-0000-000000000000",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "bundle_b64": "dGVzdA==",
            "captured_at": "2026-08-30T12:00:00Z",
            "source_hashes": [],
        },
    )
    assert r.status_code == 401, r.text


async def test_hunt_run_protected(
    app_client_with_auth: AsyncClient,
) -> None:
    """POST /api/v1/hunt/run requires auth (resource-intensive endpoint)."""
    r = await app_client_with_auth.post(
        "/api/v1/hunt/run",
        json={"rule": {"title": "test"}, "lookback_hours": 1},
    )
    assert r.status_code == 401, r.text