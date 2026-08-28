"""Deployment mode configuration.

Phase 5 introduces tiered deployment modes (individual / startup / enterprise)
per ADR-002. The mode selects a config profile that controls which features
are enabled and what their resource budgets are. Explicit operator config
overrides profile defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Mode = Literal["individual", "startup", "enterprise"]


@dataclass(frozen=True)
class ModeProfile:
    """Resource and feature budget for a deployment mode."""

    name: Mode
    storage: Literal["sqlite", "postgresql"]
    transport: Literal["local", "websocket"]
    detector_set: Literal["core", "standard", "full"]
    action_kinds: tuple[str, ...]
    memory_budget_mb: int
    cpu_budget_pct: float
    dashboard: bool
    hunt_engine: bool
    federation: bool
    multi_tenant: bool


# Profile definitions. The defaults below mirror ADR-002.
INDIVIDUAL = ModeProfile(
    name="individual",
    storage="sqlite",
    transport="local",
    detector_set="core",
    action_kinds=("block_ip", "canary_alert", "evidence_capture"),
    memory_budget_mb=20,
    cpu_budget_pct=1.5,
    dashboard=False,
    hunt_engine=False,
    federation=False,
    multi_tenant=False,
)

STARTUP = ModeProfile(
    name="startup",
    storage="postgresql",
    transport="websocket",
    detector_set="standard",
    action_kinds=(
        "block_ip",
        "tarpit_ip",
        "canary_alert",
        "isolate_host",
        "kill_process",
        "quarantine_file",
        "webhook_soar",
        "evidence_capture",
    ),
    memory_budget_mb=200,
    cpu_budget_pct=5.0,
    dashboard=True,
    hunt_engine=True,
    federation=False,
    multi_tenant=False,
)

ENTERPRISE = ModeProfile(
    name="enterprise",
    storage="postgresql",
    transport="websocket",
    detector_set="full",
    action_kinds=(
        "block_ip",
        "tarpit_ip",
        "canary_alert",
        "isolate_host",
        "kill_process",
        "quarantine_file",
        "revoke_session",
        "webhook_soar",
        "evidence_capture",
    ),
    memory_budget_mb=1024,
    cpu_budget_pct=10.0,
    dashboard=True,
    hunt_engine=True,
    federation=True,
    multi_tenant=True,
)

PROFILES: dict[Mode, ModeProfile] = {
    "individual": INDIVIDUAL,
    "startup": STARTUP,
    "enterprise": ENTERPRISE,
}


def get_profile(mode: str) -> ModeProfile:
    """Return the ModeProfile for a mode string.

    Unknown modes raise ValueError so the operator gets a clear error
    at startup rather than silent fallback.
    """
    if mode not in PROFILES:
        valid = ", ".join(PROFILES.keys())
        raise ValueError(
            f"unknown deployment mode {mode!r}; valid modes: {valid}"
        )
    return PROFILES[mode]


def validate_mode_storage(mode: str, storage: str) -> None:
    """Reject mode/storage combinations that are not supported.

    SQLite is only valid in individual mode. PostgreSQL is required for
    startup and enterprise.
    """
    if mode == "individual" and storage != "sqlite":
        raise ValueError(
            "individual mode requires sqlite storage; "
            f"got {storage!r}. Use startup or enterprise for PostgreSQL."
        )
    if mode in ("startup", "enterprise") and storage != "postgresql":
        raise ValueError(
            f"{mode} mode requires postgresql storage; got {storage!r}."
        )


def validate_mode_action(mode: str, action_kind: str) -> None:
    """Reject action kinds that are not enabled for the mode."""
    profile = get_profile(mode)
    if action_kind not in profile.action_kinds:
        raise ValueError(
            f"action kind {action_kind!r} not enabled in {mode} mode; "
            f"allowed: {', '.join(profile.action_kinds)}"
        )
