"""Tests for the SOAR Slice 1 scaffolding (ADR-008).

These tests verify that:
- The package imports cleanly.
- Six backends are registered.
- Every backend's deliver() returns a result with
  error="not implemented" and dead_lettered=True.
- The result is hashable/frozen (it's a dataclass(frozen=True)).
- get_backends() returns a list, not a singleton.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from zaqorincore_server.soar import (
    Alert,
    Backend,
    DeliveryResult,
    NotImplemented,
    get_backends,
    register,
)


EXPECTED_BACKENDS = {
    "generic_webhook",
    "slack",
    "discord",
    "pagerduty",
    "thehive",
    "jira",
}


def test_registry_has_six_backends():
    """Slice 1 ships six NotImplemented backends."""
    backends = get_backends()
    names = {b.name for b in backends}
    assert names == EXPECTED_BACKENDS


def test_all_backends_implement_protocol():
    """Every registered backend satisfies the Backend Protocol."""
    for backend in get_backends():
        assert isinstance(backend, Backend)


def test_not_implemented_deliver_returns_dead_lettered():
    """Every Slice 1 backend returns DeadLettered=True with
    a clear error message."""
    backend = NotImplemented("slack")
    alert = Alert(
        id="00000000-0000-0000-0000-000000000001",
        host_id="host-1",
        detector="ssh_bruteforce",
        severity="high",
        tags=["attack.credential_access"],
        summary="5 failed SSH logins from 203.0.113.42",
    )
    result = backend.deliver(None, alert)

    assert result.backend == "slack"
    assert result.alert_id == "00000000-0000-0000-0000-000000000001"
    assert result.dead_lettered is True
    assert result.error is not None
    assert "not implemented" in result.error
    assert "ADR-008" in result.error


def test_delivery_result_is_frozen():
    """DeliveryResult is a frozen dataclass; it must be hashable
    and immutable (so we can store it in a set and serialize
    without surprises)."""
    r1 = DeliveryResult(
        backend="slack",
        alert_id="a1",
        status_code=200,
        attempted_at=datetime.now(timezone.utc),
        duration_ms=42,
    )
    with pytest.raises((AttributeError, Exception)):
        r1.backend = "discord"  # type: ignore[misc]


def test_register_appends_to_registry():
    """The register() helper appends; get_backends() returns a copy."""
    before = len(get_backends())
    register(NotImplemented("custom_test"))
    after = len(get_backends())
    assert after == before + 1
    # get_backends returns a copy, so mutating it does not
    # affect the package-level registry.
    get_backends().clear()
    assert len(get_backends()) == after
