"""Integration tests for the F-017 CSP throttle fix.

After v3.4.2 the ``/api/v1/_csp-report`` endpoint rate-limits by
the request's source IP (``request.client.host``), not by the
report body's ``document-uri``. Keying on ``document-uri`` was
CWE-770: an attacker submitting one report per unique
``document-uri`` could exhaust the budget without ever tripping
the throttle.

These tests pin the fixed behaviour. TestClient (synchronous)
matches ``test_csp_report_endpoint.py``. The endpoint is
intentionally unauthenticated, so no credentials are needed.
"""

from __future__ import annotations

import os
import secrets
import time

# Boot-time env so the package import does not fail.
os.environ.setdefault(
    "ZAQORIN_EVIDENCE_KEY", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_CLOUDFLARE_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_WEBHOOK_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_DATABASE_URL",
    "postgresql+asyncpg://zaqorin:secret@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from zaqorincore_server.self_defense import (  # noqa: E402
    csp_violation_reporter as reporter_mod,
)
from zaqorincore_server.self_defense.csp_violation_reporter import (  # noqa: E402
    _recent,
    router,
)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _reset_throttle():
    """Wipe the in-process throttle dict around every test."""
    _recent.clear()
    yield
    _recent.clear()


@pytest.fixture
def client() -> TestClient:
    """Fresh CSP router — no full-app boot, no auth (per design)."""
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _body_for(document_uri: str) -> dict:
    return {
        "csp-report": {
            "document-uri": document_uri,
            "violated-directive": "script-src 'self'",
            "blocked-uri": "inline",
            "original-policy": "default-src 'self'",
        }
    }


def test_throttle_keyed_by_src_ip(client: TestClient) -> None:
    """F-017 fix: 11 reports with different document-uri from the
    same source IP must produce exactly 10 successes and one 429.

    TestClient sends every request from the loopback address, so
    the per-src_ip budget is exhausted after the 10th call
    regardless of how varied the ``document-uri`` values are.
    """
    statuses = []
    for i in range(11):
        body = _body_for(f"https://attacker.example/page-{i}/")
        r = client.post("/api/v1/_csp-report", json=body)
        statuses.append(r.status_code)

    assert statuses.count(204) == 10, statuses
    assert statuses.count(429) == 1, statuses
    # The 429 must be the 11th call — the budget is consumed in order.
    assert statuses[-1] == 429, statuses


def test_throttle_resets_after_window(client: TestClient) -> None:
    """After the throttle window passes the bucket clears and a
    new request from the same src_ip is allowed again.

    We do not wait 60 seconds — we manipulate the in-process
    throttle deque directly to simulate window expiry. That keeps
    the test under a second while still exercising the real
    ``_throttle_allowed`` path.
    """
    for i in range(10):
        body = _body_for(f"https://attacker.example/page-{i}/")
        r = client.post("/api/v1/_csp-report", json=body)
        assert r.status_code == 204

    # Bucket should be full — next call from the same src_ip is 429.
    blocked = client.post(
        "/api/v1/_csp-report", json=_body_for("https://attacker.example/x/")
    )
    assert blocked.status_code == 429

    # Reset the in-process bucket — equivalent to the window elapsing.
    _recent.clear()

    fresh = client.post(
        "/api/v1/_csp-report", json=_body_for("https://attacker.example/y/")
    )
    assert fresh.status_code == 204


def test_resolve_src_ip_prefers_configured_header() -> None:
    """When ``ZAQORIN_SRC_IP_HEADER`` is set the resolver prefers
    the header value over ``request.client.host``.
    """
    from starlette.requests import Request as _Request

    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"10.0.0.5")],
        "client": ("127.0.0.1", 12345),
    }
    request = _Request(scope)

    os.environ["ZAQORIN_SRC_IP_HEADER"] = "X-Forwarded-For"
    try:
        ip = reporter_mod._resolve_src_ip(request)
    finally:
        del os.environ["ZAQORIN_SRC_IP_HEADER"]

    assert ip == "10.0.0.5"


def test_resolve_src_ip_falls_back_to_client_host() -> None:
    """Without a configured header the resolver falls back to
    ``request.client.host``.
    """
    from starlette.requests import Request as _Request

    scope = {
        "type": "http",
        "headers": [],
        "client": ("192.0.2.50", 54321),
    }
    request = _Request(scope)

    os.environ.pop("ZAQORIN_SRC_IP_HEADER", None)
    ip = reporter_mod._resolve_src_ip(request)

    assert ip == "192.0.2.50"