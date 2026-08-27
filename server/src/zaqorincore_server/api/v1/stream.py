"""WebSocket endpoint: /ws/agent.

The agent v0.1.0 connects here. We expect:
    1. HELLO   once on connect
    2. EVENT   zero or more times
    3. BYE     on graceful shutdown

We accept a malformed frame by closing the socket (the agent's
reconnect logic will see the drop and try again with a fresh HELLO).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from ...config import get_settings
from ...db import get_session_factory
from ...logging import get_logger
from ...schemas.wire import ByeFrame, EventFrame, HelloFrame
from ...service import event_service, host_service
from ...service.event_service import DuplicateEvent

router = APIRouter()
log = get_logger(__name__)
std_log = logging.getLogger(__name__)


@router.websocket("/ws/agent")
async def ws_agent(ws: WebSocket) -> None:
    settings = get_settings()
    await ws.accept()
    log.info("ws connected", client=str(ws.client))
    agent_id: str | None = None
    try:
        # The first frame MUST be a hello. Anything else is a
        # protocol violation; we close so the agent reconnects and
        # tries again from a clean state.
        first_raw = await ws.receive_text()
        try:
            first = json.loads(first_raw)
        except json.JSONDecodeError:
            std_log.warning("ws first frame not json: %r", first_raw)
            await ws.close(code=1003)  # 1003 = unsupported data
            return

        if first.get("type") != "hello":
            std_log.warning(
                "ws first frame not hello: %r", first.get("type")
            )
            await ws.close(code=1002)  # 1002 = protocol error
            return

        try:
            hello = HelloFrame.model_validate(first)
        except ValidationError as exc:
            std_log.warning("ws hello invalid: %s", exc)
            await ws.close(code=1002)
            return

        agent_id = str(hello.agent_id)
        factory = get_session_factory()
        async with factory() as session:
            await host_service.upsert_on_hello(
                session,
                agent_id=hello.agent_id,
                version=hello.version,
            )
            await session.commit()
        log.info("ws hello accepted", host_id=agent_id, version=hello.version)

        # Now drain events until the agent sends BYE or disconnects.
        while True:
            raw = await ws.receive_text()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                std_log.warning("ws frame not json from %s: %r", agent_id, raw)
                continue  # don't kill the connection on a bad line

            frame_type = payload.get("type")
            if frame_type == "event":
                try:
                    frame = EventFrame.model_validate(payload)
                except ValidationError as exc:
                    std_log.warning(
                        "ws event invalid from %s: %s", agent_id, exc
                    )
                    continue
                async with factory() as session:
                    try:
                        await event_service.persist_event(session, frame)
                    except DuplicateEvent as dup:
                        log.info(
                            "ws duplicate event ignored",
                            host_id=agent_id,
                            event_id=str(frame.event.id),
                            reason=str(dup),
                        )
            elif frame_type == "bye":
                try:
                    bye = ByeFrame.model_validate(payload)
                except ValidationError:
                    bye = ByeFrame(reason="unknown")
                log.info(
                    "ws bye",
                    host_id=agent_id,
                    reason=bye.reason,
                    ts=datetime.now(timezone.utc).isoformat(),
                )
                break
            else:
                std_log.warning(
                    "ws unknown frame type from %s: %r", agent_id, frame_type
                )
                # ignore unknown frames in Phase 2 — wire contract
                # could add new types without us breaking.

    except WebSocketDisconnect:
        log.info("ws disconnected", host_id=agent_id)
    except Exception:
        log.exception("ws handler crashed", host_id=agent_id)
        try:
            await ws.close(code=1011)  # 1011 = internal error
        except Exception:  # noqa: BLE001
            pass
