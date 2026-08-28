"""WebSocket endpoint: /ws/agent.

The agent v0.1.0+ connects here. We expect:
    1. HELLO   once on connect
    2. EVENT   zero or more times
    3. BYE     on graceful shutdown
    4. COMMAND_ACK zero or more times (Phase 4+)

After HELLO, the server replies with a `X-Zaqorin-Secret`
HTTP header (only on first connect; the server's response
object is exposed via `WebSocket.headers` after accept).
The agent bootstraps its local `state_dir/shared_secret` from
that header.

The host's WebSocket is registered with the dispatcher on
connect and unregistered on disconnect, so the dispatcher
can push signed COMMAND frames back to the agent.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from ...config import get_settings
from ...db import get_session_factory
from ...dispatcher import registry
from ...logging import get_logger
from ...schemas.wire import (
    ByeFrame,
    CommandAckFrame,
    EventFrame,
    HelloFrame,
)
from ...service import event_service, host_service
from ...service.event_service import DuplicateEvent
from ...detectors import action_service

router = APIRouter()
log = get_logger(__name__)
std_log = logging.getLogger(__name__)


@router.websocket("/ws/agent")
async def ws_agent(ws: WebSocket) -> None:
    settings = get_settings()
    await ws.accept()
    log.info("ws connected", client=str(ws.client))
    agent_id: uuid.UUID | None = None
    first_connect = False
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

        agent_id = hello.agent_id
        factory = get_session_factory()
        async with factory() as session:
            host = await host_service.upsert_on_hello(
                session,
                agent_id=hello.agent_id,
                version=hello.version,
            )
            # Detect first connect by checking if the host had
            # last_seen_at == first_seen_at (within a second).
            # We do this client-side rather than reading the
            # previous value because the upsert already updated
            # both columns to the same now. Instead, we use
            # the presence of a `secret` field (always present
            # post-Phase-4) plus the auto-detect trick: a
            # bootstrap response is sent on the very first
            # connection since the host was created.
            await session.commit()
        # Send the bootstrap secret in a custom response header.
        # FastAPI/Starlette do not let us add headers after
        # accept(), so we use the lower-level `ws.headers` dict
        # which the underlying ASGI response honours on the
        # first frame's reply. Starlette has `ws.send_message`
        # but the right idiom here is `ws.scope["headers"]`
        # mutation; the cleanest portable path is to surface
        # the secret in a dedicated HELLO_ACK frame on the
        # WebSocket, AFTER the initial HELLO. v0.1.0 agents
        # ignore the extra frame; v0.4.0+ agents read it.
        log.info(
            "ws hello accepted",
            host_id=str(agent_id),
            version=hello.version,
            secret_present=bool(host.secret),
        )
        # Send HELLO_ACK with the secret. The agent reads it and
        # persists to state_dir/shared_secret.
        await ws.send_text(
            json.dumps(
                {
                    "type": "hello_ack",
                    "agent_id": str(host.id),
                    "shared_secret": host.secret,
                }
            )
        )
        # Register with the dispatcher so COMMAND frames can be
        # pushed back.
        await registry.register(host.id, ws)

        # Now drain events until the agent sends BYE or disconnects.
        while True:
            raw = await ws.receive_text()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                std_log.warning("ws frame not json from %s: %r", str(agent_id), raw)
                continue  # don't kill the connection on a bad line

            frame_type = payload.get("type")
            if frame_type == "event":
                try:
                    frame = EventFrame.model_validate(payload)
                except ValidationError as exc:
                    std_log.warning(
                        "ws event invalid from %s: %s", str(agent_id), exc
                    )
                    continue
                async with factory() as session:
                    try:
                        await event_service.persist_event(session, frame)
                    except DuplicateEvent as dup:
                        log.info(
                            "ws duplicate event ignored",
                            host_id=str(agent_id),
                            event_id=str(frame.event.id),
                            reason=str(dup),
                        )
            elif frame_type == "command_ack":
                # Phase 4: agent is acking a COMMAND. Update the
                # action row from `dispatched` to `applied` or
                # `failed` based on the status field.
                try:
                    ack = CommandAckFrame.model_validate(payload)
                except ValidationError as exc:
                    std_log.warning(
                        "ws command_ack invalid from %s: %s", str(agent_id), exc
                    )
                    continue
                if ack.status == "applied":
                    ok = await action_service.mark_applied(
                        factory, ack.id
                    )
                else:
                    ok = await action_service.mark_failed(
                        factory, ack.id, ack.error
                    )
                log.info(
                    "ws command_ack",
                    host_id=str(agent_id),
                    action_id=str(ack.id),
                    status=ack.status,
                    updated=ok,
                )
            elif frame_type == "bye":
                try:
                    bye = ByeFrame.model_validate(payload)
                except ValidationError:
                    bye = ByeFrame(reason="unknown")
                log.info(
                    "ws bye",
                    host_id=str(agent_id),
                    reason=bye.reason,
                    ts=datetime.now(timezone.utc).isoformat(),
                )
                break
            else:
                std_log.warning(
                    "ws unknown frame type from %s: %r", str(agent_id), frame_type
                )
                # ignore unknown frames — wire contract
                # could add new types without us breaking.

    except WebSocketDisconnect:
        log.info("ws disconnected", host_id=str(agent_id))
    except Exception:
        log.exception("ws handler crashed", host_id=str(agent_id))
        try:
            await ws.close(code=1011)  # 1011 = internal error
        except Exception:  # noqa: BLE001
            pass
    finally:
        if agent_id is not None:
            try:
                await registry.unregister(agent_id)
            except Exception:  # noqa: BLE001
                pass
