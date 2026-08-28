"""Canary token manager (Phase 7, ADR-005).

A canary token is a file (or a TCP socket, or a credential)
that nobody legitimate should ever touch. The agent watches
a list of canary paths; any read/write/exec on a canary
fires a `canary_alert` action with zero false positive risk.

This module runs in the **agent** (Go). On the server side,
the canary paths are configured per-host and the watch list
is pushed down to the agent in a CONFIG frame. The agent
emits a `canary_touched` event and the server routes it
through the same rule engine as everything else.

This Python file ships with the server because:
  1. tests need to construct canary descriptors,
  2. the `/api/v1/canary/*` endpoints expose the descriptors,
  3. operators can list/rotate canary tokens via the API.

The agent implementation lives in
`agent/internal/canary/canary.go`.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


# Allowed canary token types. Each one is wired to a different
# watch mechanism in the agent. Adding a new type means adding
# a watcher in the Go agent.
CanaryKind = Literal["file", "tcp_socket", "http_endpoint", "credential"]


@dataclass
class CanaryDescriptor:
    """A canary token that the agent is watching."""

    id: str
    kind: CanaryKind
    path: str  # For file: the file path. For tcp_socket: the port. For http: the URL path. For credential: a label.
    created_at: datetime
    secret: str = field(default_factory=lambda: secrets.token_urlsafe(24))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "created_at": self.created_at.isoformat(),
            "secret": self.secret,
        }


class CanarySpec(BaseModel):
    """Operator-supplied canary token definition."""

    kind: CanaryKind = Field(..., description="file | tcp_socket | http_endpoint | credential")
    path: str = Field(..., description="The path the agent will watch")


class CanaryList(BaseModel):
    """Response shape for GET /api/v1/canary."""

    canaries: list[dict]


class CanaryTouchedEvent(BaseModel):
    """Payload the agent sends when a canary is touched.

    The server ingests this as a normal event with a special
    `event_type` so the rule engine can match on it.
    """

    canary_id: str
    touched_by: str = Field(..., description="Process name, IP, or user that touched the canary")
    evidence_path: str | None = Field(None, description="Local path to the canary for evidence capture")


def make_canary(spec: CanarySpec) -> CanaryDescriptor:
    """Build a new canary descriptor with a fresh secret."""
    return CanaryDescriptor(
        id=str(uuid.uuid4()),
        kind=spec.kind,
        path=spec.path,
        created_at=datetime.utcnow(),
    )


def persist_canary_descriptor(
    base_dir: Path, descriptor: CanaryDescriptor,
) -> Path:
    """Write the descriptor to a JSON file under base_dir/canary/.
    Operators back this up with their usual config management.
    Returns the path that was written.
    """
    base_dir.mkdir(parents=True, exist_ok=True)
    out = base_dir / f"{descriptor.id}.json"
    import json
    out.write_text(json.dumps(descriptor.to_dict(), indent=2))
    return out


__all__ = [
    "CanaryDescriptor",
    "CanarySpec",
    "CanaryList",
    "CanaryTouchedEvent",
    "make_canary",
    "persist_canary_descriptor",
]
