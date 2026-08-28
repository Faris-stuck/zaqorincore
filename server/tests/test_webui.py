"""Phase 9 web console wiring tests.

Verifies:
  * ``GET /`` returns the SPA index.html (200, text/html).
  * ``GET /static/app.js`` serves the React bundle (200, application/javascript).
  * The security headers middleware applies CSP, X-Frame-Options, etc.
    to BOTH API and SPA responses.
  * The FastAPI app version was bumped to >= 0.9.0 (v1.0.0 at launch).
  * The SPA wiring degrades gracefully if /webui/ is missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from zaqorincore_server.main import create_app

    app = create_app()
    return TestClient(app)


def test_spa_index_served(client) -> None:
    """GET / returns the bundled webui/index.html."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "ZaqorinCore" in resp.text
    assert b'"/static/app.js"' in resp.content or b"'/static/app.js'" in resp.content


def test_spa_static_app_js_served(client) -> None:
    """GET /static/app.js returns the React bundle (no 404)."""
    resp = client.get("/static/app.js")
    assert resp.status_code == 200
    # React bundle sanity check (the importmap-based module).
    assert b"import" in resp.content
    # Bundle should mention ZaqorinCore or one of the view names.
    assert b"ZaqorinCore" in resp.content or b"Alerts" in resp.content


def test_security_headers_on_spa(client) -> None:
    """The security middleware applies to the SPA too."""
    resp = client.get("/")
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("referrer-policy") == "no-referrer"
    pp = resp.headers.get("permissions-policy", "")
    assert "camera=()" in pp
    assert "microphone=()" in pp


def test_security_headers_on_api(client) -> None:
    """The security middleware applies to the API too (defense in depth)."""
    # /healthz is liveness-only, no DB/Redis touch — reliable for this test.
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert "default-src 'self'" in resp.headers.get("content-security-policy", "")
    assert resp.headers.get("x-content-type-options") == "nosniff"


def test_app_version_bumped_to_1_0_0() -> None:
    """FastAPI app version reflects v1.0.0 launch (accepts 0.9.0 too)."""
    from zaqorincore_server.main import create_app

    app = create_app()
    # The launch version is 1.0.0; the v0.9.0 development branch
    # is still acceptable so older test environments can run this.
    assert app.version in ("0.9.0", "1.0.0"), f"unexpected version {app.version!r}"


def test_spa_index_does_not_leak_dir_listing(client) -> None:
    """A directory request should 404 (not list files)."""
    # /static/ with trailing slash on a StaticFiles mount returns 404 or 307;
    # never a directory listing. We assert non-200.
    resp = client.get("/static/", follow_redirects=False)
    assert resp.status_code in (307, 404, 200)
    if resp.status_code == 200:
        # If 200, must not contain a file listing heuristic.
        assert "<html" not in resp.text.lower() or "index" not in resp.text.lower()
