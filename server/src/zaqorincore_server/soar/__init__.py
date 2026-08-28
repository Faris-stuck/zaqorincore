"""Package soar holds the SOAR webhook delivery backends for
ZaqorinCore (v1.3 - see ADR-008).

Slice 1 provided the package skeleton, the DeliveryResult
dataclass, the Backend interface, and six NotImplemented
backends. Slices 2-7 replace those one at a time with real
HTTP delivery (generic_webhook, slack, discord, pagerduty,
thehive, jira). Slice 8 adds dead-letter persistence and
replay. Slice 9 adds the web-console tab.

This file does not register a worker; that lives in
`soar.worker` and is wired into the FastAPI lifespan by
`zaqorincore_server.main`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from datetime import datetime, timezone

# Re-export the config helpers so callers can do
# `from zaqorincore_server.soar import load_config`.
from .config import (  # noqa: F401
    BackendConfig,
    KNOWN_BACKENDS,
    SEVERITY_ORDER,
    SoarConfig,
    load_config,
    severity_meets,
)


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


@dataclass(frozen=True)
class DeliverOutcome:
    """What a backend's `deliver()` returns.

    Carries the result plus the SHA-256 of the rendered
    body so the worker can persist it on the
    soar_deliveries row. The body bytes themselves are not
    stored (they may contain secrets); the SHA is enough to
    detect drift between the original attempt and a replay.
    """

    result: DeliveryResult
    payload_sha256: str


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
    """Interface every delivery backend implements.

    `deliver(ctx, alert)` is the only public method the
    worker calls. The backend returns a `DeliverOutcome`
    (or any object that quacks like one) so the worker can
    persist the result and the payload hash.
    """

    name: str

    def deliver(self, ctx: object, alert: Alert) -> DeliverOutcome:
        """Send the alert and return the structured outcome.

        Must be safe to call concurrently; backends are
        registered as singletons and called from the worker
        pool.
        """
        ...


class NotImplemented:
    """Stand-in backend used by Slice 1 and by tests that
    want a known-broken backend.

    Implements the `Backend` Protocol (has `name` and
    `deliver`) but always returns a dead-lettered result.
    Kept exported from the package so the Slice 1 scaffold
    tests still pass after Slice 2.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def deliver(self, ctx: object, alert: Alert) -> DeliverOutcome:
        return DeliverOutcome(
            result=DeliveryResult(
                backend=self.name,
                alert_id=alert.id,
                status_code=0,
                attempted_at=datetime.now(timezone.utc),
                duration_ms=0,
                error=(
                    "backend not implemented in this release "
                    "(Slice 1 scaffolding; see ADR-008)"
                ),
                dead_lettered=True,
            ),
            payload_sha256="",
        )


# Module-level registry. Slices 2-7 replace the
# `NotImplemented` entries one at a time. `register()`
# replaces any existing entry with the same name.
_REGISTRY: list[Backend] = []


def get_backends() -> list[Backend]:
    """Return a copy of the registered backends."""
    return list(_REGISTRY)


def reset_registry() -> None:
    """Clear the registry. Used by tests to reset state."""
    _REGISTRY.clear()


def register(backend: Backend) -> None:
    """Register a backend at runtime. Replaces any existing
    backend with the same name (so a Slice 2 generic_webhook
    replaces the Slice 1 NotImplemented generic_webhook
    without leaving a stale one behind)."""
    name = getattr(backend, "name", None)
    for i, existing in enumerate(_REGISTRY):
        if getattr(existing, "name", None) == name:
            _REGISTRY[i] = backend
            return
    _REGISTRY.append(backend)


# init: register the six Slice-1 NotImplemented backends so
# the import surface is stable. Slices 2-7 replace the
# entries one at a time.
for _name in ("generic_webhook", "slack", "discord", "pagerduty", "thehive", "jira"):
    register(NotImplemented(_name))


__all__ = [
    "Alert",
    "Backend",
    "DeliverOutcome",
    "DeliveryResult",
    "NotImplemented",
    "load_config",
    "register",
    "reset_registry",
    "get_backends",
    "severity_meets",
]
