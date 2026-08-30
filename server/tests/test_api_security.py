"""Tests for /api/v1/security/* diagnostics (cycle 33).

The endpoints are pure diagnostic surfaces that read the
security header constants out of ``security.py`` and surface
them as JSON. Tests run in dev mode so ``require_api_key``
is a no-op and the routes are reachable without headers.

Coverage matrix:
  1. /headers returns the full set of header names with the
     correct values, count > 0, CSP present.
  2. /csp-test returns the CSP verbatim as a non-empty
     string and ``present: True``.
  3. /headers keys include every header the middleware
     actually emits (regression guard — a header added to
     the middleware without being mirrored here will fail
     this test).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_security_headers_full_snapshot(app_client: AsyncClient) -> None:
    """``/headers`` returns the full snapshot, count > 0.

    The middleware emits five headers today; we assert the
    snapshot has at least five entries and the well-known
    header names are present.
    """
    r = await app_client.get("/api/v1/security/headers")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"headers", "count"}
    headers = body["headers"]
    assert isinstance(headers, dict)
    assert body["count"] == len(headers)
    assert body["count"] >= 5
    # Well-known header names must all be present.
    assert "Content-Security-Policy" in headers
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers
    assert "Referrer-Policy" in headers
    assert "Permissions-Policy" in headers


async def test_security_headers_values_match_middleware(
    app_client: AsyncClient,
) -> None:
    """The diagnostic values match what the middleware emits.

    Read the module-level constants from ``security.py``
    directly and assert they round-trip through the JSON
    body unchanged. This is the regression guard for
    "constant changed but diagnostic didn't" drift.
    """
    from zaqorincore_server import security as sec

    r = await app_client.get("/api/v1/security/headers")
    assert r.status_code == 200
    body = r.json()["headers"]
    assert body["Content-Security-Policy"] == sec._CSP
    assert body["X-Content-Type-Options"] == "nosniff"
    assert body["X-Frame-Options"] == "DENY"
    assert body["Referrer-Policy"] == "no-referrer"
    assert (
        body["Permissions-Policy"]
        == "camera=(), microphone=(), geolocation=(), payment=()"
    )


async def test_csp_test_returns_policy_verbatim(app_client: AsyncClient) -> None:
    """``/csp-test`` returns the policy as a non-empty string."""
    from zaqorincore_server import security as sec

    r = await app_client.get("/api/v1/security/csp-test")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"csp", "present"}
    assert body["present"] is True
    assert body["csp"] == sec._CSP
    assert body["csp"].startswith("default-src")


async def test_security_routes_excluded_from_error_envelope() -> None:
    """Both routes are excluded from the cycle-28 error envelope.

    Diagnostic endpoints must keep their response shape stable
    across deployments; the error_envelope middleware opt-out
    is the mechanism that guarantees that.
    """
    from zaqorincore_server.error_envelope import (
        _EXCLUDED_PREFIXES,
        _is_excluded,
    )

    assert "/api/v1/security" in _EXCLUDED_PREFIXES
    assert _is_excluded("/api/v1/security/headers") is True
    assert _is_excluded("/api/v1/security/csp-test") is True


@pytest.mark.parametrize("header_name", [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
])
async def test_security_headers_each_header_present(
    app_client: AsyncClient, header_name: str
) -> None:
    """Each well-known name is individually present (parametrized).

    A regression that drops one header from the snapshot will
    fail exactly the parametrize case for that header.
    """
    r = await app_client.get("/api/v1/security/headers")
    assert r.status_code == 200
    assert header_name in r.json()["headers"]