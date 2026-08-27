"""Wire-format schema tests. No DB needed."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from zaqorincore_server.schemas.wire import (
    ByeFrame,
    CommandFrame,
    EventFrame,
    EventInner,
    HelloFrame,
)


def test_hello_minimal() -> None:
    h = HelloFrame.model_validate(
        {"type": "hello", "agent_id": str(uuid.uuid4()), "version": "1.0"}
    )
    assert h.type == "hello"
    assert h.version == "1.0"
    assert isinstance(h.agent_id, uuid.UUID)


def test_hello_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        HelloFrame.model_validate(
            {
                "type": "hello",
                "agent_id": str(uuid.uuid4()),
                "version": "1.0",
                "rogue": "x",
            }
        )


def test_event_inner_schema_alias() -> None:
    """The 'schema' field on the wire maps to event_schema in Python
    because 'schema' is reserved on BaseModel.
    """
    eid = str(uuid.uuid4())
    host = str(uuid.uuid4())
    inner = EventInner.model_validate(
        {
            "schema": "1.0",
            "id": eid,
            "timestamp": "2026-08-28T12:00:00Z",
            "host_id": host,
            "source": "auth",
            "raw": "Accepted publickey for foo",
            "metadata": {"k": "v"},
        }
    )
    assert inner.event_schema == "1.0"
    assert inner.id == uuid.UUID(eid)
    assert inner.source == "auth"
    assert inner.metadata == {"k": "v"}


def test_event_inner_default_metadata() -> None:
    """metadata is optional."""
    eid = str(uuid.uuid4())
    inner = EventInner.model_validate(
        {
            "schema": "1.0",
            "id": eid,
            "timestamp": "2026-08-28T12:00:00Z",
            "host_id": str(uuid.uuid4()),
            "source": "auth",
            "raw": "line",
        }
    )
    assert inner.metadata == {}


def test_event_frame() -> None:
    f = EventFrame.model_validate(
        {
            "type": "event",
            "event": {
                "schema": "1.0",
                "id": str(uuid.uuid4()),
                "timestamp": "2026-08-28T12:00:00Z",
                "host_id": str(uuid.uuid4()),
                "source": "auth",
                "raw": "x",
            },
        }
    )
    assert f.type == "event"
    assert f.event.source == "auth"


def test_bye_frame() -> None:
    b = ByeFrame.model_validate({"type": "bye", "reason": "shutdown"})
    assert b.reason == "shutdown"


def test_command_frame() -> None:
    c = CommandFrame.model_validate(
        {
            "type": "command",
            "id": str(uuid.uuid4()),
            "kind": "block_ip",
            "target": "1.2.3.4",
            "ttl_sec": 3600,
        }
    )
    assert c.kind == "block_ip"
    assert c.ttl_sec == 3600


def test_command_rejects_negative_ttl() -> None:
    with pytest.raises(ValidationError):
        CommandFrame.model_validate(
            {
                "type": "command",
                "id": str(uuid.uuid4()),
                "kind": "block_ip",
                "target": "1.2.3.4",
                "ttl_sec": -1,
            }
        )
