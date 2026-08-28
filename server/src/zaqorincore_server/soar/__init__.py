# Package soar holds the SOAR webhook delivery backend for
# ZaqorinCore (v1.3 - see ADR-008).
#
# Slice 1 (this file) provides the package skeleton, the
# DeliveryResult dataclass, the Backend interface, and six
# NotImplemented backends (generic_webhook, slack, discord,
# pagerduty, thehive, jira) that all return "not implemented"
# errors. Slices 2-9 (v1.3) implement them one at a time.
#
# This file does not register a worker yet - Slice 1 ships
# the design + the package so that the agent, web console,
# and DB migration can be sized against the design without
# any behavior change.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from datetime import datetime, timezone


@dataclass(frozen=True)
class DeliveryResult:
    """Structured outcome of one delivery attempt.

    All HTTP backends populate it; the dispatcher writes one
    row per attempt to soar_deliveries.
    """

    backend: str
    alert_id: str
    status_code: int
    attempted_at: datetime
    duration_ms: int
    error: str | None = None
    dead_lettered: bool = False


@dataclass
class Alert:
    """Wire shape the SOAR worker reads from the alerts table.

    Fields are denormalized for ease of templating; values
    are the same as the JSON wire schema.
    """

    id: str
    host_id: str
    detector: str
    severity: str  # critical|high|medium|low|info
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    evidence: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@runtime_checkable
class Backend(Protocol):
    """Interface every delivery backend implements."""

    name: str

    def deliver(self, ctx: object, alert: Alert) -> DeliveryResult:
        """Send the alert and return the structured result.

        Must be safe to call concurrently; backends are
        registered as singletons and called from the worker
        pool.
        """
        ...


class NotImplemented:
    """Backend returned by every Slice 1 backend.

    It implements the interface so the registry is populated,
    but every call returns a result with Error set and
    DeadLettered=True. Slices 2-7 replace this with real
    HTTP delivery.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def deliver(self, ctx: object, alert: Alert) -> DeliveryResult:
        return DeliveryResult(
            backend=self.name,
            alert_id=alert.id,
            status_code=0,
            attempted_at=datetime.now(timezone.utc),
            duration_ms=0,
            error="backend not implemented in this release (Slice 1 scaffolding; see ADR-008)",
            dead_lettered=True,
        )


# Package-level registry. Slice 1 registers six backends
# so the import surface is stable across Slices 2-7. The
# real server code reads this list and dispatches per
# soar.toml config.
_REGISTRY: list[Backend] = []


def get_backends() -> list[Backend]:
    """Return the registered backends."""
    return list(_REGISTRY)


def register(backend: Backend) -> None:
    """Register a backend at runtime (used by Slices 2-7)."""
    _REGISTRY.append(backend)


# init: register the six Slice-1 NotImplemented backends.
# Slices 2-7 replace the entries one at a time.
for _name in ("generic_webhook", "slack", "discord", "pagerduty", "thehive", "jira"):
    register(NotImplemented(_name))
