"""Wire-format Pydantic schemas.

These mirror exactly what the v0.1.0 agent sends. Any new field the
agent adds is a breaking change here too — that's by design, so we
notice it.

Frames (Phase 2 server only consumes hello/event/bye; command is
parsed for forward-compat but the server never sends it back yet).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


# ---- inner objects ----------------------------------------------------


class HelloFrame(BaseModel):
    """Sent by the agent immediately on connect."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["hello"] = "hello"
    agent_id: uuid.UUID
    version: str = Field(..., min_length=1, max_length=32)


class EventInner(BaseModel):
    """The 'event' object inside an EventFrame."""

    # 'schema' is reserved on BaseModel; we use the field name
    # 'event_schema' in Python and alias it to 'schema' on the wire.
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    event_schema: str = Field(
        alias="schema", min_length=1, max_length=16
    )
    id: uuid.UUID
    timestamp: datetime
    host_id: uuid.UUID
    source: str = Field(..., min_length=1, max_length=255)
    raw: str
    metadata: dict[str, str] = Field(default_factory=dict)


class EventFrame(BaseModel):
    """One event from the agent."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["event"] = "event"
    event: EventInner


class ByeFrame(BaseModel):
    """Sent by the agent when shutting down."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["bye"] = "bye"
    reason: str = Field(..., min_length=1, max_length=128)


class CommandFrame(BaseModel):
    """Server -> agent command. Phase 4 sends these; v0.1.0 agents
    parse-and-ignore them (the field set is additive)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["command"] = "command"
    id: uuid.UUID
    kind: str = Field(..., min_length=1, max_length=64)
    target: str = Field(..., min_length=1, max_length=512)
    ttl_sec: int | None = Field(default=None, ge=0, le=86_400 * 30)
    issued_at: str = Field(..., min_length=1, max_length=64)
    hmac: str = Field(..., min_length=64, max_length=64)


class CommandAckFrame(BaseModel):
    """Agent -> server ack for a CommandFrame. Phase 4 introduces this."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["command_ack"] = "command_ack"
    id: uuid.UUID
    status: Literal["applied", "failed"]
    error: str | None = Field(default=None, max_length=512)


# ---- discriminated union ----------------------------------------------


# Pydantic v2 uses `Annotated[Union[...], Field(discriminator=...)]`.
# The discriminator field is "type" on the wire, so Pydantic will pick
# the right model based on the JSON.
AgentFrame = Annotated[
    Union[HelloFrame, EventFrame, ByeFrame],
    Field(discriminator="type"),
]


__all__ = [
    "HelloFrame",
    "EventInner",
    "EventFrame",
    "ByeFrame",
    "CommandFrame",
    "CommandAckFrame",
    "AgentFrame",
]
