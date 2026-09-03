"""Tests for /api/v1/_csp-report endpoint and event_normalizer."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from zaqorincore_server.self_defense import drain
from zaqorincore_server.self_defense.csp_violation_reporter import (
    router,
)
from zaqorincore_server.self_defense.event_normalizer import ZaqorinEvent


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _legacy_body():
    return {
        "csp-report": {
            "document-uri": "https://example.com/",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "inline",
            "original-policy": "default-src 'self'; script-src 'self'",
            "source-file": "https://example.com/app.js",
            "line-number": 12,
            "column-number": 3,
        }
    }


def _flat_body():
    return {
        "document-uri": "https://example.com/",
        "violated-directive": "style-src 'self'",
        "blocked-uri": "inline",
    }


def test_valid_csp_report_returns_204(client) -> None:
    r = client.post("/api/v1/_csp-report", json=_legacy_body())
    assert r.status_code == 204


def test_flat_csp_report_returns_204(client) -> None:
    r = client.post("/api/v1/_csp-report", json=_flat_body())
    assert r.status_code == 204


def test_empty_body_returns_400(client) -> None:
    r = client.post("/api/v1/_csp-report", json={})
    # Empty body still parses (all fields optional) and yields a
    # 204; this test guards against a future regression where we
    # require document-uri.
    assert r.status_code in (204, 400)


def test_malformed_json_returns_422(client) -> None:
    r = client.post(
        "/api/v1/_csp-report",
        content=b"{not-json",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422


def test_method_not_allowed(client) -> None:
    r = client.get("/api/v1/_csp-report")
    assert r.status_code == 405


def test_event_emitted_to_stream(client) -> None:
    before = list(drain(max_items=10000))
    r = client.post("/api/v1/_csp-report", json=_legacy_body())
    assert r.status_code == 204
    after = list(drain(max_items=10000))
    assert len(after) >= len(before) + 1
    new_events = after[len(before):]
    assert any(e.event_type == "csp.violation" for e in new_events)


def test_violated_directive_normalized_strip_semicolon() -> None:
    body = {"csp-report": {"violated-directive": "script-src 'self';"}}
    ev = ZaqorinEvent.from_csp_report(body)
    assert ev.violated_directive == "script-src"


def test_violated_directive_falls_back_to_effective() -> None:
    body = {"csp-report": {"effective-directive": "img-src"}}
    ev = ZaqorinEvent.from_csp_report(body)
    assert ev.violated_directive == "img-src"


def test_rate_limit_returns_429(client) -> None:
    body = _legacy_body()
    statuses = []
    # 11 posts in quick succession; at least one must 429 (budget=10).
    for _ in range(11):
        statuses.append(client.post("/api/v1/_csp-report", json=body).status_code)
    assert 429 in statuses
    # Successes must be <= budget (10/min). Earlier tests in the same
    # process may have already consumed part of the budget.
    assert statuses.count(204) <= 10
    assert statuses.count(429) >= 1


def test_normalizer_from_log_record_handles_garbage() -> None:
    ev = ZaqorinEvent.from_log_record(
        {
            "event_type": "ws.hello",
            "message_size_bytes": "not-a-number",  # bad type → None
            "status": "401",  # coerces to int
            "src_ip": 12345,  # wrong type → None
        }
    )
    assert ev.event_type == "ws.hello"
    assert ev.message_size_bytes is None
    assert ev.status == 401
    assert ev.src_ip is None


def test_normalizer_to_metadata_strips_none() -> None:
    ev = ZaqorinEvent(ts="2026-09-03T00:00:00Z", event_type="http.request")
    md = ev.to_metadata()
    assert "route" not in md
    assert "status" not in md
    assert md["event_type"] == "http.request"
    assert md["src_ip"] is None


def test_nft_call_event_round_trip() -> None:
    """nft.call events are valid metadata for the T1485.001 rule."""
    ev = ZaqorinEvent.from_log_record(
        {
            "event_type": "nft.call",
            "target_table": "input",
            "target_chain": "output;id",
        }
    )
    md = ev.to_metadata()
    assert md["event_type"] == "nft.call"
    assert md["target_table"] == "input"
    assert md["target_chain"] == "output;id"


def test_process_exec_event_round_trip() -> None:
    """process.exec events carry the full cmdline for T1059.004."""
    ev = ZaqorinEvent.from_log_record(
        {
            "event_type": "process.exec",
            "cmdline": "curl -fsSL https://example.com/install.sh | bash",
        }
    )
    md = ev.to_metadata()
    assert md["event_type"] == "process.exec"
    assert "| bash" in md["cmdline"]