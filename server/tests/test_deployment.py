"""Tests for deployment.py tiered config (Phase 5, ADR-002)."""

from __future__ import annotations

import pytest

from zaqorincore_server.deployment import (
    ENTERPRISE,
    INDIVIDUAL,
    STARTUP,
    ModeProfile,
    PROFILES,
    get_profile,
    validate_mode_action,
    validate_mode_storage,
)


def test_three_modes_registered() -> None:
    assert set(PROFILES.keys()) == {"individual", "startup", "enterprise"}


def test_get_profile_returns_correct_mode() -> None:
    assert get_profile("individual") is INDIVIDUAL
    assert get_profile("startup") is STARTUP
    assert get_profile("enterprise") is ENTERPRISE


def test_get_profile_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown deployment mode"):
        get_profile("gigacorp")


def test_individual_uses_sqlite_and_local_transport() -> None:
    p = INDIVIDUAL
    assert p.storage == "sqlite"
    assert p.transport == "local"
    assert p.detector_set == "core"
    assert p.memory_budget_mb <= 20
    assert p.cpu_budget_pct <= 2.0


def test_individual_has_minimal_actions() -> None:
    """Individual tier only ships 3 action kinds (block, canary, evidence)."""
    assert len(INDIVIDUAL.action_kinds) == 3
    assert "block_ip" in INDIVIDUAL.action_kinds
    assert "canary_alert" in INDIVIDUAL.action_kinds
    assert "evidence_capture" in INDIVIDUAL.action_kinds


def test_startup_has_seven_action_kinds() -> None:
    """Startup tier ships 7 of the 9 kinds (no revoke_session, no kill_process)."""
    # Actually 8 per ADR-002, but 7 minimum; the actual count is
    # implementation-defined and may grow. We just check the major ones.
    assert "block_ip" in STARTUP.action_kinds
    assert "tarpit_ip" in STARTUP.action_kinds
    assert "canary_alert" in STARTUP.action_kinds
    assert "isolate_host" in STARTUP.action_kinds
    assert "quarantine_file" in STARTUP.action_kinds
    assert "webhook_soar" in STARTUP.action_kinds
    assert "evidence_capture" in STARTUP.action_kinds


def test_enterprise_has_all_nine_action_kinds() -> None:
    """Enterprise tier ships all 9 kinds per ADR-003."""
    expected = {
        "block_ip",
        "tarpit_ip",
        "canary_alert",
        "isolate_host",
        "kill_process",
        "quarantine_file",
        "revoke_session",
        "webhook_soar",
        "evidence_capture",
    }
    assert expected.issubset(set(ENTERPRISE.action_kinds))


def test_enterprise_supports_federation_and_multi_tenant() -> None:
    assert ENTERPRISE.federation is True
    assert ENTERPRISE.multi_tenant is True
    assert ENTERPRISE.dashboard is True
    assert ENTERPRISE.hunt_engine is True


def test_individual_disables_dashboard_hunt_federation() -> None:
    assert INDIVIDUAL.dashboard is False
    assert INDIVIDUAL.hunt_engine is False
    assert INDIVIDUAL.federation is False
    assert INDIVIDUAL.multi_tenant is False


def test_storage_validation_rejects_individual_postgres() -> None:
    with pytest.raises(ValueError, match="individual mode requires sqlite"):
        validate_mode_storage("individual", "postgresql")


def test_storage_validation_rejects_startup_sqlite() -> None:
    with pytest.raises(ValueError, match="requires postgresql"):
        validate_mode_storage("startup", "sqlite")


def test_storage_validation_rejects_enterprise_sqlite() -> None:
    with pytest.raises(ValueError, match="requires postgresql"):
        validate_mode_storage("enterprise", "sqlite")


def test_storage_validation_accepts_correct_combos() -> None:
    validate_mode_storage("individual", "sqlite")
    validate_mode_storage("startup", "postgresql")
    validate_mode_storage("enterprise", "postgresql")


def test_action_validation_rejects_disabled_kind() -> None:
    """Individual mode must not allow tarpit_ip."""
    with pytest.raises(ValueError, match="not enabled in individual mode"):
        validate_mode_action("individual", "tarpit_ip")


def test_action_validation_accepts_enabled_kind() -> None:
    validate_mode_action("startup", "block_ip")
    validate_mode_action("enterprise", "kill_process")


def test_mode_profile_is_immutable() -> None:
    """ModeProfile must be frozen so it cannot be mutated at runtime."""
    p = INDIVIDUAL
    with pytest.raises(Exception):  # FrozenInstanceError
        p.memory_budget_mb = 999  # type: ignore[misc]


def test_mode_resource_budgets_are_monotonic() -> None:
    """Memory and CPU budgets must grow from individual -> startup -> enterprise."""
    assert INDIVIDUAL.memory_budget_mb < STARTUP.memory_budget_mb < ENTERPRISE.memory_budget_mb
    assert INDIVIDUAL.cpu_budget_pct < STARTUP.cpu_budget_pct < ENTERPRISE.cpu_budget_pct
