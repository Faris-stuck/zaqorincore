"""End-to-end test of the /ws/agent endpoint.

We construct a mock WebSocket object, drive the handler function
directly (no TestClient, no threads, no real port). This is the
cleanest way to test WebSocket handlers in FastAPI/starlette.

The mock WebSocket is a minimal implementation that captures
sent frames and replays a scripted set of received frames.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

import pytest

from zaqorincore_server.api.v1.stream import ws_agent
from zaqorincore_server.models import Base, Event, Host
from sqlalchemy import func, select

pytestmark = pytest.mark.asyncio


class MockWebSocket:
    """A minimal in-memory WebSocket for testing the handler."""

    def __init__(self, incoming: Iterable[dict[str, Any]]):
        self._incoming = list(incoming)
        self._idx = 0
        self.accepted = False
        self.sent: list[dict[str, Any]] = []
        self.client = ("testclient", 50000)
        self.closed: bool = False
        self.close_code: int | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def receive_text(self) -> str:
        if self._idx >= len(self._incoming):
            # Simulate graceful close from the agent's side.
            from starlette.websockets import WebSocketState

            # Setting state to DISCONNECTED makes receive_text raise.
            self.client_state = WebSocketState.DISCONNECTED
            from fastapi import WebSocketDisconnect

            raise WebSocketDisconnect(code=1000)
        frame = self._incoming[self._idx]
        self._idx += 1
        return json.dumps(frame)

    async def send_json(self, data: dict[str, Any]) -> None:
        self.sent.append(data)

    async def send_text(self, data: str) -> None:
        self.sent.append(json.loads(data))

    async def close(self, code: int = 1000) -> None:
        self.closed = True
        self.close_code = code


def _script(agent_id: str) -> list[dict[str, Any]]:
    """The script the mock will play back to the handler."""
    return [
        {"type": "hello", "agent_id": agent_id, "version": "1.0"},
        {
            "type": "event",
            "event": {
                "schema": "1.0",
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "host_id": agent_id,
                "source": "pytest",
                "raw": "line-1",
                "metadata": {},
            },
        },
        {
            "type": "event",
            "event": {
                "schema": "1.0",
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "host_id": agent_id,
                "source": "pytest",
                "raw": "line-2",
                "metadata": {},
            },
        },
        {
            "type": "event",
            "event": {
                "schema": "1.0",
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "host_id": agent_id,
                "source": "pytest",
                "raw": "line-3",
                "metadata": {},
            },
        },
        {"type": "bye", "reason": "test_done"},
    ]


async def test_ws_handler_persists_hello_event_bye(engine) -> None:
    """Run the ws_agent handler against a mock WebSocket and verify
    the rows landed in the database.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    agent_id = str(uuid.uuid4())
    ws = MockWebSocket(_script(agent_id))
    await ws_agent(ws)  # type: ignore[arg-type]
    assert ws.accepted
    # Verify rows in DB
    async with engine.connect() as conn:
        host_count = await conn.scalar(
            select(func.count(Host.id)).where(Host.id == uuid.UUID(agent_id))
        )
        event_count = await conn.scalar(
            select(func.count(Event.id)).where(
                Event.host_id == uuid.UUID(agent_id)
            )
        )
    assert host_count == 1, f"expected 1 host, got {host_count}"
    assert event_count == 3, f"expected 3 events, got {event_count}"


async def test_ws_handler_rejects_non_hello_first_frame(engine) -> None:
    """The handler must close the socket if the first frame isn't HELLO."""
    agent_id = str(uuid.uuid4())
    ws = MockWebSocket(
        [
            {"type": "event", "event": {}},  # not a hello!
        ]
    )
    await ws_agent(ws)  # type: ignore[arg-type]
    assert ws.closed
    assert ws.close_code == 1002  # protocol error
