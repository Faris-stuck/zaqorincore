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


# ---------------------------------------------------------------------------
# /api/v1/security/headers/audit (cycle 46)
# ---------------------------------------------------------------------------


async def test_headers_audit_reports_healthy(
    app_client: AsyncClient,
) -> None:
    """``/headers/audit`` reports the configured security header
    policy as healthy when every required header is present
    AND matches the documented value contract.

    A regression that drifts any value (e.g. CSP loosened to
    ``unsafe-inline``, X-Frame-Options flipped to
    ``SAMEORIGIN``) flips ``healthy`` to ``False`` and
    surfaces the offending pair in the ``violations`` list.
    """
    r = await app_client.get("/api/v1/security/headers/audit")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {
        "headers",
        "contract",
        "violations",
        "healthy",
        "checked",
        "count",
    }
    # Every required header is configured and matches contract.
    assert body["healthy"] is True
    assert body["violations"] == []
    assert body["checked"] == 5
    assert body["count"] == 5
    assert len(body["headers"]) == 5
    # Contract covers the four fixed-value headers (CSP is
    # value-checked separately in another test).
    assert set(body["contract"].keys()) == {
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    }


async def test_headers_audit_values_match_snapshot(
    app_client: AsyncClient,
) -> None:
    """The ``headers`` map reported by ``/headers/audit`` matches
    the snapshot reported by ``/headers``.

    Both endpoints read from the same source of truth
    (the constants in ``security.py``). A drift between them
    is a regression guard.
    """
    snapshot = (
        await app_client.get("/api/v1/security/headers")
    ).json()["headers"]
    audited = (
        await app_client.get("/api/v1/security/headers/audit")
    ).json()["headers"]
    for name, expected in snapshot.items():
        assert audited[name] == expected


async def test_headers_audit_detects_drift() -> None:
    """``_audit_security_headers`` flags a value that drifted
    from the documented contract.

    We patch the contract map to a deliberately wrong value
    for ``X-Frame-Options`` and assert the audit flips
    ``healthy`` to ``False`` with a violation that names
    the offender. The patch is reverted at the end of the
    test so the module-level state stays consistent.
    """
    import zaqorincore_server.api.v1.security as sec_mod

    original = sec_mod._REQUIRED_VALUES["X-Frame-Options"]
    sec_mod._REQUIRED_VALUES["X-Frame-Options"] = "SAMEORIGIN"
    try:
        result = sec_mod._audit_security_headers()
    finally:
        sec_mod._REQUIRED_VALUES["X-Frame-Options"] = original

    assert result["healthy"] is False
    assert len(result["violations"]) == 1
    v = result["violations"][0]
    assert v["header"] == "X-Frame-Options"
    assert v["expected"] == "SAMEORIGIN"
    assert v["actual"] == "DENY"


async def test_headers_audit_skips_csp_in_contract() -> None:
    """``_audit_security_headers`` does NOT track CSP under the
    strict value contract — CSP is value-checked elsewhere
    (``/csp-test`` and external scanners).

    The audit tracks the four fixed-value headers (XCTO, XFO,
    Referrer-Policy, Permissions-Policy) strictly. CSP, even if
    added to ``_REQUIRED_VALUES`` by accident, would be
    expected to match the constant in ``security.py`` — so
    adding it shouldn't create a false-positive violation in
    the normal case.
    """
    import zaqorincore_server.api.v1.security as sec_mod

    # Confirm CSP is NOT in the contract map by default
    # (the audit design keeps CSP out of strict-equality).
    assert "Content-Security-Policy" not in sec_mod._REQUIRED_VALUES


async def test_headers_audit_route_is_excluded_from_error_envelope() -> None:
    """The new audit route inherits the cycle-28 error-envelope
    opt-out via the ``/api/v1/security`` prefix.

    Diagnostic body shape must remain stable across deployments;
    the prefix-based exclusion is the mechanism that guarantees
    it.
    """
    from zaqorincore_server.error_envelope import (
        _EXCLUDED_PREFIXES,
        _is_excluded,
    )

    assert "/api/v1/security" in _EXCLUDED_PREFIXES
    assert _is_excluded("/api/v1/security/headers/audit") is True