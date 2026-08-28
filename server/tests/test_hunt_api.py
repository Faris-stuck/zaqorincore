"""Tests for the hunt API (Phase 6)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from zaqorincore_server.main import create_app


def test_hunt_lists_builtin_rules() -> None:
    """GET /api/v1/hunt/rules returns the 5 builtin rules."""
    app = create_app()
    client = TestClient(app)
    r = client.get("/api/v1/hunt/rules")
    assert r.status_code == 200, r.text
    data = r.json()
    ids = {rule["id"] for rule in data["rules"]}
    assert "builtin-ssh-bruteforce" in ids
    assert "builtin-port-scan" in ids
    assert "builtin-web-attack" in ids
    assert "builtin-dns-tunnel" in ids
    assert "builtin-impossible-travel" in ids


def test_hunt_run_returns_no_match_for_clean_event(engine) -> None:
    """POST /api/v1/hunt/run with a rule that won't match anything
    should return zero fires."""
    app = create_app()
    client = TestClient(app)
    rule = {
        "title": "Test rule",
        "id": "test-no-match",
        "level": "low",
        "detection": {
            "selection": {"source": "definitely_not_a_real_source"},
            "condition": "selection",
        },
    }
    r = client.post(
        "/api/v1/hunt/run",
        json={"rule": rule, "lookback_hours": 24},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["fires"] == []
    assert data["rules_evaluated"] == 1
    assert data["events_scanned"] >= 0


def test_hunt_run_rejects_invalid_rule(engine) -> None:
    """A rule missing required fields should be 400."""
    app = create_app()
    client = TestClient(app)
    r = client.post(
        "/api/v1/hunt/run",
        json={"rule": {"title": "no detection block"}, "lookback_hours": 1},
    )
    assert r.status_code == 400
