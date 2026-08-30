"""Tests for the role-based API auth (v2.1.0 IMP-1 second slice).

Coverage matrix:

* each role accepted on GET  -> 200
* read role on POST          -> 403
* ingest role on GET          -> 403
* write role on POST          -> 2xx (full access)
* legacy ZAQORIN_API_KEY still works as ``write``
* /api/v1/auth/whoami returns the resolved role
* unauthenticated calls in role-mode -> 401
* missing/empty key -> 401
* wrong key -> 401

Fixtures use clearly-fake keys (``test-read-key-do-not-use`` etc.)
and the legacy key is unset unless a specific test sets it.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from zaqorincore_server.config import reset_settings


# Clearly-fake keys used by these tests. RFC5737 IPs are not used
# here because the endpoint doesn't care about source IP — these are
# just values; no real secret material.
READ_KEY = "test-read-key-do-not-use"
WRITE_KEY = "test-write-key-do-not-use"
INGEST_KEY = "test-ingest-key-do-not-use"
LEGACY_KEY = "legacy-test-key-do-not-use"


# GET endpoints that are role-protected in production. Any of the
# three role keys should be enough for a GET; ``read`` may not POST.
PROTECTED_GET = "/api/v1/alerts"


@pytest.fixture
def app_client_role_mode(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """Role-auth mode: 3 role keys set, legacy unset.

    Mirrors a fresh role-based deploy. The legacy
    ``ZAQORIN_API_KEY`` is unset so we can isolate the role
    contract from the F6 backward-compat path.
    """
    monkeypatch.delenv("ZAQORIN_API_KEY", raising=False)
    monkeypatch.setenv("ZAQORIN_API_KEY_READ", READ_KEY)
    monkeypatch.setenv("ZAQORIN_API_KEY_WRITE", WRITE_KEY)
    monkeypatch.setenv("ZAQORIN_API_KEY_INGEST", INGEST_KEY)
    reset_settings()
    return app_client


# ---- 1. Each role accepted on GET ----------------------------------------


@pytest.mark.asyncio
async def test_read_role_can_get(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        PROTECTED_GET, headers={"X-API-Key": READ_KEY}
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_write_role_can_get(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        PROTECTED_GET, headers={"X-API-Key": WRITE_KEY}
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_ingest_role_get_returns_403(
    app_client_role_mode: AsyncClient,
) -> None:
    """Ingest role is POST-only — even GET is forbidden.

    An ingest agent should push data but never read other
    tenants' events. The auth boundary is strict on purpose:
    a misconfigured agent that wants to read should escalate
    to a read key, not get free reads.
    """
    r = await app_client_role_mode.get(
        PROTECTED_GET, headers={"X-API-Key": INGEST_KEY}
    )
    assert r.status_code == 403, r.text
    assert "ingest" in r.json()["detail"].lower()


# ---- 2. Cross-role: read cannot POST, ingest cannot GET-mutate -----------


@pytest.mark.asyncio
async def test_read_role_post_returns_403(
    app_client_role_mode: AsyncClient,
) -> None:
    """A read-only key must NOT be able to POST. 403, not 401:
    the key was valid, the action is not authorised.
    """
    r = await app_client_role_mode.post(
        "/api/v1/evidence",
        headers={"X-API-Key": READ_KEY},
        json={
            "alert_id": "00000000-0000-0000-0000-000000000000",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "bundle_b64": "dGVzdA==",
            "captured_at": "2026-08-30T12:00:00Z",
            "source_hashes": [],
        },
    )
    assert r.status_code == 403, r.text
    # 403 still includes the role in the detail so the dashboard
    # can show the operator which key they need to escalate to.
    assert "read" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_read_role_delete_returns_403(
    app_client_role_mode: AsyncClient,
) -> None:
    """Same contract for DELETE: read role gets 403."""
    r = await app_client_role_mode.delete(
        "/api/v1/canary/00000000-0000-0000-0000-000000000000",
        headers={"X-API-Key": READ_KEY},
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_ingest_role_put_returns_403(
    app_client_role_mode: AsyncClient,
) -> None:
    """Ingest role gets 403 on PATCH — POST only.

    The /api/v1/hosts/{id} endpoint supports PATCH; the auth
    layer must reject it for the ingest role even before the
    handler runs.
    """
    r = await app_client_role_mode.patch(
        "/api/v1/hosts/00000000-0000-0000-0000-000000000001",
        headers={"X-API-Key": INGEST_KEY},
        json={"hostname": "should-not-update"},
    )
    assert r.status_code == 403, r.text
    assert "ingest" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_write_role_can_post_evidence(
    app_client_role_mode: AsyncClient,
) -> None:
    """Write role has full access — POST /evidence is allowed
    (the actual write may fail because the alert_id is bogus,
    but the auth layer must not block it).
    """
    r = await app_client_role_mode.post(
        "/api/v1/evidence",
        headers={"X-API-Key": WRITE_KEY},
        json={
            "alert_id": "00000000-0000-0000-0000-000000000000",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "bundle_b64": "dGVzdA==",
            "captured_at": "2026-08-30T12:00:00Z",
            "source_hashes": [],
        },
    )
    # The evidence endpoint validates the alert_id and will return
    # 4xx if it doesn't exist; what matters is we got past auth.
    assert r.status_code != 401, r.text
    assert r.status_code != 403, r.text


# ---- 3. /api/v1/auth/whoami ----------------------------------------------


@pytest.mark.asyncio
async def test_whoami_read(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        "/api/v1/auth/whoami", headers={"X-API-Key": READ_KEY}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role"] == "read"
    assert body["dev_mode"] is False
    assert set(body["configured_roles"]) == {"read", "write", "ingest"}


@pytest.mark.asyncio
async def test_whoami_write(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        "/api/v1/auth/whoami", headers={"X-API-Key": WRITE_KEY}
    )
    assert r.status_code == 200
    assert r.json()["role"] == "write"


@pytest.mark.asyncio
async def test_whoami_ingest(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        "/api/v1/auth/whoami", headers={"X-API-Key": INGEST_KEY}
    )
    assert r.status_code == 200
    assert r.json()["role"] == "ingest"


@pytest.mark.asyncio
async def test_whoami_unauthenticated_returns_401(
    app_client_role_mode: AsyncClient,
) -> None:
    """No header in role-mode -> 401, not 200."""
    r = await app_client_role_mode.get("/api/v1/auth/whoami")
    assert r.status_code == 401, r.text
    assert r.headers.get("www-authenticate") == "ApiKey"


@pytest.mark.asyncio
async def test_whoami_wrong_key_returns_401(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        "/api/v1/auth/whoami", headers={"X-API-Key": "definitely-wrong"}
    )
    assert r.status_code == 401, r.text


# ---- 4. Missing / wrong key -------------------------------------------------


@pytest.mark.asyncio
async def test_missing_header_returns_401(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(PROTECTED_GET)
    assert r.status_code == 401, r.text
    assert r.headers.get("www-authenticate") == "ApiKey"


@pytest.mark.asyncio
async def test_wrong_key_returns_401(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        PROTECTED_GET, headers={"X-API-Key": "definitely-wrong"}
    )
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_empty_key_returns_401(
    app_client_role_mode: AsyncClient,
) -> None:
    r = await app_client_role_mode.get(
        PROTECTED_GET, headers={"X-API-Key": ""}
    )
    assert r.status_code == 401, r.text


# ---- 5. Backward compat: legacy ZAQORIN_API_KEY works as 'write' ----------


@pytest.fixture
def app_client_legacy_only(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """F6-style deploy: only ``ZAQORIN_API_KEY`` set, no role keys."""
    monkeypatch.delenv("ZAQORIN_API_KEY_READ", raising=False)
    monkeypatch.delenv("ZAQORIN_API_KEY_WRITE", raising=False)
    monkeypatch.delenv("ZAQORIN_API_KEY_INGEST", raising=False)
    monkeypatch.setenv("ZAQORIN_API_KEY", LEGACY_KEY)
    reset_settings()
    return app_client


@pytest.mark.asyncio
async def test_legacy_key_works_on_get(
    app_client_legacy_only: AsyncClient,
) -> None:
    r = await app_client_legacy_only.get(
        PROTECTED_GET, headers={"X-API-Key": LEGACY_KEY}
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_legacy_key_works_on_post(
    app_client_legacy_only: AsyncClient,
) -> None:
    """Legacy key maps to 'write' role -> full access."""
    r = await app_client_legacy_only.post(
        "/api/v1/evidence",
        headers={"X-API-Key": LEGACY_KEY},
        json={
            "alert_id": "00000000-0000-0000-0000-000000000000",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "bundle_b64": "dGVzdA==",
            "captured_at": "2026-08-30T12:00:00Z",
            "source_hashes": [],
        },
    )
    assert r.status_code != 401, r.text
    assert r.status_code != 403, r.text


@pytest.mark.asyncio
async def test_legacy_key_reported_as_write(
    app_client_legacy_only: AsyncClient,
) -> None:
    r = await app_client_legacy_only.get(
        "/api/v1/auth/whoami", headers={"X-API-Key": LEGACY_KEY}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["role"] == "write"
    # Only legacy was set; ``write`` is the implicit role.
    assert body["configured_roles"] == ["write"]


# ---- 6. Mixed deploy: legacy + role keys coexist -------------------------


@pytest.fixture
def app_client_mixed(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncClient:
    """Legacy + read key set. Both must work; the legacy key
    is treated as ``write``, the dedicated var as ``read``.
    """
    monkeypatch.setenv("ZAQORIN_API_KEY", LEGACY_KEY)
    monkeypatch.setenv("ZAQORIN_API_KEY_READ", READ_KEY)
    monkeypatch.delenv("ZAQORIN_API_KEY_WRITE", raising=False)
    monkeypatch.delenv("ZAQORIN_API_KEY_INGEST", raising=False)
    reset_settings()
    return app_client


@pytest.mark.asyncio
async def test_mixed_legacy_can_post(
    app_client_mixed: AsyncClient,
) -> None:
    r = await app_client_mixed.post(
        "/api/v1/evidence",
        headers={"X-API-Key": LEGACY_KEY},
        json={
            "alert_id": "00000000-0000-0000-0000-000000000000",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "bundle_b64": "dGVzdA==",
            "captured_at": "2026-08-30T12:00:00Z",
            "source_hashes": [],
        },
    )
    assert r.status_code != 401, r.text
    assert r.status_code != 403, r.text


@pytest.mark.asyncio
async def test_mixed_read_role_cannot_post(
    app_client_mixed: AsyncClient,
) -> None:
    r = await app_client_mixed.post(
        "/api/v1/evidence",
        headers={"X-API-Key": READ_KEY},
        json={
            "alert_id": "00000000-0000-0000-0000-000000000000",
            "host_id": "00000000-0000-0000-0000-000000000001",
            "bundle_b64": "dGVzdA==",
            "captured_at": "2026-08-30T12:00:00Z",
            "source_hashes": [],
        },
    )
    assert r.status_code == 403, r.text


# ---- 7. Dev mode (no keys) -----------------------------------------------


@pytest.mark.asyncio
async def test_dev_mode_open(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No keys set -> dev mode, all roles pass (write by default)."""
    monkeypatch.delenv("ZAQORIN_API_KEY", raising=False)
    monkeypatch.delenv("ZAQORIN_API_KEY_READ", raising=False)
    monkeypatch.delenv("ZAQORIN_API_KEY_WRITE", raising=False)
    monkeypatch.delenv("ZAQORIN_API_KEY_INGEST", raising=False)
    reset_settings()
    # GET should pass (no auth needed in dev mode).
    r = await app_client.get(PROTECTED_GET)
    assert r.status_code != 401, r.text
    # /whoami should report dev_mode=True with role=write.
    r2 = await app_client.get("/api/v1/auth/whoami")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["dev_mode"] is True
    assert body["role"] == "write"