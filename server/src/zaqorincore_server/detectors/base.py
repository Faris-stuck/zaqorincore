"""Detector plugin protocol and shared context.

A detector is a small object that knows how to look at one event
and (optionally) produce a list of `DetectionResult` objects.

Adding a new detector = drop a new file here that exposes a
`Detector` instance, and add it to `BUILTIN_DETECTORS` below.
No DB migration required; no other server code changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..config import Settings


@dataclass(frozen=True)
class DetectionResult:
    """What a detector returns when it fires.

    The runner turns each result into one Alert row in the DB.
    If `action` is set, the runner ALSO enqueues an Action row
    in `actions` (status=pending), which the Phase 4 dispatcher
    will sign and ship back to the originating agent.
    """

    detector: str           # e.g. "ssh_bruteforce"
    severity: str           # "low" | "medium" | "high" | "critical"
    summary: str            # one-line human summary
    detail: dict[str, Any]  # structured detail (free-form JSONB)
    # Cooldown: the runner will not emit another alert for the
    # same (host_id, detector, dedup_key) inside this window.
    cooldown_sec: int = 300
    dedup_key: str = ""     # typically the source IP or attacker id
    # Optional Phase 4 action to enqueue. None = alert only.
    action: "DetectionAction | None" = None

    def __post_init__(self) -> None:  # pragma: no cover - trivial
        if self.severity not in ("low", "medium", "high", "critical"):
            raise ValueError(f"invalid severity: {self.severity}")


@dataclass(frozen=True)
class DetectionAction:
    """An auto-response action the runner should enqueue.

    `kind` is the wire-contract verb (e.g. "block_ip"). `target`
    is the parameter (an IP, a PID, a username). `ttl_sec`
    controls how long the agent should keep the effect in
    place; the agent is responsible for un-applying it
    after the TTL.
    """

    kind: str
    target: str
    ttl_sec: int | None = None


@dataclass
class DetectorContext:
    """Read-only access to state detectors need.

    A fresh context is built once at startup and shared by all
    detectors across all events. It is intentionally narrow.
    """

    redis: aioredis.Redis
    settings: Settings
    session_factory: async_sessionmaker[Any]


@dataclass(frozen=True)
class ParsedEvent:
    """The minimal projection of a wire event the detectors need.

    We avoid leaking the full Pydantic model so detectors can be
    tested without the WS layer.
    """

    event_id: UUID
    host_id: UUID
    source: str
    raw: str
    metadata: dict[str, str]
    occurred_at: datetime


@runtime_checkable
class Detector(Protocol):
    """A detector plugin.

    The `name` is what the runner keys on for the `alerts.detector`
    column. `on_event` is called once per event; it returns a list
    of `DetectionResult` (zero, one, or many — most detectors
    return 0 or 1).
    """

    name: str

    async def on_event(
        self, event: ParsedEvent, ctx: DetectorContext
    ) -> list[DetectionResult]: ...


__all__ = [
    "DetectionResult",
    "DetectionAction",
    "DetectorContext",
    "Detector",
    "ParsedEvent",
]
