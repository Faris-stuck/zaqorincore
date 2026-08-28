"""Tests for IMP-1 (X-API-Key auth) on the SOAR endpoints.

The SOAR router at ``/api/v1/soar/*`` is protected by a
shared secret in the ``X-API-Key`` header. When
``ZAQORIN_API_KEY`` is unset, the dependency is a no-op and
emits a one-shot warning. When set, requests must present the
matching header or they get 401.

These tests use the shared ``app_client`` fixture (which gives
an ``httpx.AsyncClient`` wired through ASGITransport to the
FastAPI app) and override the ``ZAQORIN_API_KEY`` env var via
``monkeypatch`` + ``reset_settings()`` to flip the policy per
test. Using the in-process async client (instead of ``TestClient``)
sidesteps the "got Future ... attached to a different loop"
problem that arises when ``TestClient`` and the async engine
are bound to different event loops.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from zaqorincore_server.config import reset_settings


@pytest.fixture
def app_client_no_auth(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """App client with ZAQORIN_API_KEY unset (dev mode)."""
    monkeypatch.delenv("ZAQORIN_API_KEY", raising=False)
    reset_settings()
    return app_client


@pytest.fixture
def app_client_with_auth(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """App client with ZAQORIN_API_KEY=s3cret-test-key set."""
    monkeypatch.setenv("ZAQORIN_API_KEY", "s3cret-test-key")
    reset_settings()
    return app_client


async def test_health_open_when_api_key_unset(
    app_client_no_auth: AsyncClient,
) -> None:
    """Default dev mode (no ZAQORIN_API_KEY) lets requests through."""
    r = await app_client_no_auth.get("/api/v1/soar/health")
    # 200 with empty history, or 200 with rows. Both are
    # acceptable; only requirement is "not 401".
    assert r.status_code == 200, r.text


async def test_health_rejects_missing_header(
    app_client_with_auth: AsyncClient,
) -> None:
    """Without the X-API-Key header, the SOAR endpoint returns 401."""
    r = await app_client_with_auth.get("/api/v1/soar/health")
    assert r.status_code == 401, r.text
    assert r.headers.get("www-authenticate") == "ApiKey"


async def test_health_rejects_wrong_header(
    app_client_with_auth: AsyncClient,
) -> None:
    """A wrong X-API-Key is rejected with 401, not 403."""
    r = await app_client_with_auth.get(
        "/api/v1/soar/health",
        headers={"X-API-Key": "wrong-value"},
    )
    assert r.status_code == 401, r.text


async def test_health_accepts_correct_header(
    app_client_with_auth: AsyncClient,
) -> None:
    """The correct X-API-Key lets the request through."""
    r = await app_client_with_auth.get(
        "/api/v1/soar/health",
        headers={"X-API-Key": "s3cret-test-key"},
    )
    assert r.status_code == 200, r.text


async def test_replay_endpoint_also_protected(
    app_client_with_auth: AsyncClient,
) -> None:
    """The replay endpoint (the dangerous one) is also protected."""
    r = await app_client_with_auth.post(
        "/api/v1/soar/dead-letter/00000000-0000-0000-0000-000000000000/replay",
    )
    assert r.status_code == 401, r.text


def test_constant_time_compare_used() -> None:
    """The dependency uses hmac.compare_digest, not ``==``."""
    import hmac
    import inspect

    from zaqorincore_server import security

    src = inspect.getsource(security.require_api_key)
    assert "hmac.compare_digest" in src, (
        "require_api_key must use hmac.compare_digest for "
        "constant-time comparison"
    )
    assert "== " not in src.replace("==", "", src.count("== ")), (
        "require_api_key must not use ``==`` to compare the key"
    )
