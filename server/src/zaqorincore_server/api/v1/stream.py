"""WebSocket endpoint: /ws/agent.

The agent v0.5.0+ connects here. We expect a strict handshake:

  1. HELLO   once on connect (v0.5.0+ sends auth material)
  2. EVENT   zero or more times
  3. BYE     on graceful shutdown
  4. COMMAND_ACK zero or more times (Phase 4+)

v3.2.1 PROTO v2 — HMAC challenge-response (F1 security fix):

The legacy protocol accepted any client that claimed an
agent_id and replied with the host's shared_secret in a
plaintext HELLO_ACK frame. That was a critical leak: anyone
who could open a TCP connection to /ws/agent could harvest
every host's shared secret simply by guessing or scraping
agent UUIDs.

The new flow is:

  server -> agent : {"type":"challenge","nonce":<32-byte hex>}
  agent  -> server : {"type":"hello","agent_id":..., "v":2,
                      "version":"<agent>",
                      "nonce":<echo>,
                      "sig":<hex(HMAC-SHA256(shared_secret, nonce))>}
  server -> agent : {"type":"hello_ack","agent_id":...}

The server verifies sig == HMAC(shared_secret, nonce) before
registering the host. On any failure the socket is closed
with 1008 (policy violation). The shared_secret is never
sent over the wire again.

Old agents (v0.1.0..v0.4.x) that send {"type":"hello", ...}
without a v field are refused with 1002. Bumping the
protocol version is acceptable for v3.2.1 — operators
running a mixed fleet upgrade in lockstep.

The host's WebSocket is registered with the dispatcher on
successful auth and unregistered on disconnect, so the
dispatcher can push signed COMMAND frames back to the
agent.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import logging
import os
import secrets
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


def _compute_sig(secret: str, nonce: str) -> str:
    """HMAC-SHA256(secret, nonce) hex digest."""
    return hmac.new(
        secret.encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@router.websocket("/ws/agent")
async def ws_agent(ws: WebSocket) -> None:
    settings = get_settings()
    await ws.accept()
    log.info("ws connected", client=str(ws.client))
    agent_id: uuid.UUID | None = None
    try:
        # --- Step 1: send a server nonce. The client must
        # echo this nonce back inside a signed HELLO. ---
        nonce = secrets.token_hex(32)
        await ws.send_text(
            json.dumps({"type": "challenge", "nonce": nonce, "v": 2})
        )

        # --- Step 2: read the agent's reply. It must be a
        # HELLO with the echoed nonce and a valid signature. ---
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

        # Protocol v2 mandates "v": 2 on the HELLO frame.
        # Legacy v0.1.0..v0.4.x agents send no v field and
        # are rejected. Bumping the protocol is a deliberate
        # backward-incompatible change for v3.2.1.
        if first.get("v") != 2:
            std_log.warning(
                "ws hello proto mismatch, want v=2 got v=%r",
                first.get("v"),
            )
            await ws.close(code=1002)  # protocol error
            return

        try:
            hello = HelloFrame.model_validate(first)
        except ValidationError as exc:
            std_log.warning("ws hello invalid: %s", exc)
            await ws.close(code=1002)
            return

        # The agent must echo the nonce we sent. A missing or
        # mismatched nonce is a tampering signal.
        echoed_nonce = first.get("nonce")
        if not echoed_nonce or echoed_nonce != nonce:
            std_log.warning(
                "ws hello nonce mismatch, want %r got %r",
                nonce,
                echoed_nonce,
            )
            await ws.close(code=1002)
            return

        agent_id = hello.agent_id
        sig = first.get("sig", "")
        if not isinstance(sig, str) or not sig:
            std_log.warning(
                "ws hello missing sig from %s", str(agent_id)
            )
            await ws.close(code=1002)
            return

        # --- Step 3: look up the host, then verify the
        # signature against the host's stored shared_secret. ---
        factory = get_session_factory()
        async with factory() as session:
            host = await host_service.upsert_on_hello(
                session,
                agent_id=hello.agent_id,
                version=hello.version,
            )
            await session.commit()

        if not host.secret:
            std_log.warning(
                "ws hello from %s but host has no secret",
                str(agent_id),
            )
            await ws.close(code=1008)
            return
        expected = _compute_sig(host.secret, nonce)
        if not hmac.compare_digest(expected, sig):
            std_log.warning(
                "ws hello bad signature from %s", str(agent_id)
            )
            # 1008 = policy violation
            await ws.close(code=1008)
            return

        log.info(
            "ws hello accepted",
            host_id=str(agent_id),
            version=hello.version,
            proto_v=2,
        )

        # --- Step 4: send HELLO_ACK. Crucially, the
        # shared_secret is NOT included any more. ---
        await ws.send_text(
            json.dumps(
                {
                    "type": "hello_ack",
                    "agent_id": str(host.id),
                    "v": 2,
                }
            )
        )

        # F-009 (v3.2.3): per-connection WS DoS guard. Cap
        # the raw frame size and the rolling-window
        # per-minute message rate. Both knobs live in
        # Settings so operators can tune them without
        # code changes. A violation drops the WS with
        # the standard close codes (1009 / 1013).
        ws_max_bytes = settings.ws_max_msg_bytes
        ws_max_per_min = settings.ws_max_msg_per_min
        window_start = time.monotonic()
        msg_in_window = 0

        # Register with the dispatcher so COMMAND frames can be
        # pushed back.
        await registry.register(host.id, ws)

        # Now drain events until the agent sends BYE or disconnects.
        while True:
            # F-009: per-frame size cap. We measure the
            # text frame length BEFORE parsing it so an
            # oversize blob never lands in JSON memory.
            raw = await ws.receive_text()
            if len(raw) > ws_max_bytes:
                std_log.warning(
                    "ws frame too big from %s: %d > %d",
                    str(agent_id), len(raw), ws_max_bytes,
                )
                # 1009 = message too big
                await ws.close(code=1009)
                return

            # F-009: rolling-window per-minute message cap.
            # Counter resets each time we cross a 60s
            # boundary. Sustained overage drops the WS.
            msg_in_window += 1
            now = time.monotonic()
            if now - window_start >= 60.0:
                window_start = now
                msg_in_window = 1
            if msg_in_window > ws_max_per_min:
                std_log.warning(
                    "ws rate limit exceeded from %s: %d msg/min > %d",
                    str(agent_id), msg_in_window, ws_max_per_min,
                )
                # 1013 = try again later
                await ws.close(code=1013)
                return

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
