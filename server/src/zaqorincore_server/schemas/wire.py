"""Wire-format Pydantic schemas for the agent/server protocol."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


class HelloFrame(BaseModel):
    """Authenticated agent HELLO for protocol v2."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["hello"] = "hello"
    agent_id: uuid.UUID
    v: Literal[2]
    version: str = Field(..., min_length=1, max_length=32)
    nonce: str = Field(..., min_length=64, max_length=64)
    sig: str = Field(..., min_length=64, max_length=64)


class EventInner(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    event_schema: str = Field(alias="schema", min_length=1, max_length=16)
    id: uuid.UUID
    timestamp: datetime
    host_id: uuid.UUID
    source: str = Field(..., min_length=1, max_length=255)
    raw: str = Field(..., max_length=64 * 1024)
    metadata: dict[str, str] = Field(default_factory=dict)


class EventFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["event"] = "event"
    event: EventInner


class ByeFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["bye"] = "bye"
    reason: str = Field(..., min_length=1, max_length=128)


class CommandFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["command"] = "command"
    id: uuid.UUID
    kind: str = Field(..., min_length=1, max_length=64)
    target: str = Field(..., min_length=1, max_length=512)
    ttl_sec: int | None = Field(default=None, ge=0, le=86_400 * 30)
    issued_at: str = Field(..., min_length=1, max_length=64)
    hmac: str = Field(..., min_length=64, max_length=64)


class CommandAckFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["command_ack"] = "command_ack"
    id: uuid.UUID
    status: Literal["applied", "failed"]
    error: str | None = Field(default=None, max_length=512)


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
