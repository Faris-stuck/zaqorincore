"""Integration tests documenting F-017: CSP report throttle gap.

F-017 (cycle 55): the ``/api/v1/_csp-report`` throttle is keyed by
``document-uri`` host (per ``csp_violation_reporter.py``'s
``_throttle_allowed``). This means an attacker rotating document
URIs from a single source IP can submit an unbounded number of
reports — the throttle budget never fills up because each new
document-uri gets its own bucket.

These tests **document the current behavior** so the fix ships
in a follow-up cycle with a known baseline. After the fix, the
``test_throttle_keyed_by_document_uri_NOT_src_ip`` assertion must
invert to ``429 in statuses`` (and the comment block at the top
of the test updated).

TestClient (synchronous) — matches ``test_csp_report_endpoint.py``.
No credentials required: the CSP report endpoint is intentionally
unauthenticated.
"""

from __future__ import annotations

import os
import secrets

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

from zaqorincore_server.self_defense.csp_violation_reporter import (  # noqa: E402
    router,
)

pytestmark = pytest.mark.integration


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


def test_throttle_keyed_by_document_uri_NOT_src_ip(
    client: TestClient,
) -> None:
    """F-017 GAP TEST: confirms the throttle is keyed by document-uri,
    not by src_ip.

    With the current implementation, the throttle key is the
    document-uri host — so 11 reports with different document
    URIs all succeed. From TestClient the src_ip is the same
    on every call (the loopback address), so the *intended*
    behavior (per-src_ip rate limit) would 429 once 11 reports
    arrive. Instead, every report succeeds because each
    document-uri gets its own bucket.

    Behavior we are locking in for the F-017 fix:

    Pre-fix (today): every status is 204.
    Post-fix (next cycle): at least one status is 429, and
    successes are bounded by the budget (currently 10/min).

    NOTE: when the fix ships, this test must be inverted to
    assert ``429 in statuses`` and ``statuses.count(204) <= 10``.
    """
    statuses = []
    for i in range(11):
        body = _body_for(f"https://attacker.example/page-{i}/")
        r = client.post("/api/v1/_csp-report", json=body)
        statuses.append(r.status_code)

    # Document the gap: every report succeeded because each
    # document-uri opened a fresh bucket. The per-src_ip cap
    # never engaged.
    assert 429 not in statuses, (
        "F-017 fix may have shipped — invert the assertion to "
        "'429 in statuses' and update the docstring above."
    )
    assert statuses.count(204) == 11, statuses


def test_throttle_persists_state_in_process(
    client: TestClient,
) -> None:
    """Two reports with different document-uris from the same src_ip
    both succeed — each gets its own bucket.

    Sanity check on the in-process state model: the throttle
    dict is keyed by document-uri, so swapping URIs yields two
    fresh buckets. The fix will need to change the key (e.g.
    to client IP, which TestClient doesn't expose — see
    ``src_ip_header`` config) without breaking this test's
    no-credential posture.
    """
    body_a = _body_for("https://attacker.example/a/")
    body_b = _body_for("https://attacker.example/b/")

    r_a = client.post("/api/v1/_csp-report", json=body_a)
    r_b = client.post("/api/v1/_csp-report", json=body_b)

    assert r_a.status_code == 204
    assert r_b.status_code == 204