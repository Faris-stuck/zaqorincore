"""Phase 4 E2E: SSH brute-force detection + auto-response dispatch.

What this proves:
  1. Agent connects via WebSocket; server returns the host's
     `shared_secret` in a `hello_ack` frame.
  2. We PATCH the host with `auto_block=true` to opt-in.
  3. Five SSH "Failed password" events from the same source IP
     are sent to the server.
  4. The server's ssh_bruteforce detector fires and writes an
     Alert row + a pending Action row.
  5. The server's dispatcher signs the COMMAND frame with the
     host's secret and pushes it to our WebSocket.
  6. We verify the HMAC byte-identically to the Go agent's
     crypto package (kept in lockstep).
  7. We send a command_ack, the server transitions the Action
     row to applied.

This is server-side E2E. The agent binary isn't invoked; we
import the same HMAC algorithm and assert it verifies the
server's signed frame.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx
import websockets
from sqlalchemy import select

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from zaqorincore_server.config import get_settings  # noqa: E402
from zaqorincore_server.db import get_session_factory  # noqa: E402
from zaqorincore_server.logging import get_logger  # noqa: E402
from zaqorincore_server.models import Action  # noqa: E402

SERVER_URL = os.environ.get("ZAQORIN_SERVER_URL", "ws://127.0.0.1:8000/ws/agent")
API_URL = os.environ.get("ZAQORIN_API_URL", "http://127.0.0.1:8000")
SOURCE_IP = "198.51.100.99"  # documentation range
EVENTS_TO_SEND = 5
CMD_TIMEOUT_S = 15


def _canonical_form(cmd_id: str, kind: str, target: str, ttl: int, issued_at: str) -> bytes:
    """Byte-identical to server/crypto.py and agent/crypto.go."""
    return f"{cmd_id}|{kind}|{target}|{ttl}|{issued_at}".encode("utf-8")


def sign_command(secret: str, cmd_id: str, kind: str, target: str, ttl: int, issued_at: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        _canonical_form(cmd_id, kind, target, ttl, issued_at),
        hashlib.sha256,
    ).hexdigest()


def verify_command(secret: str, cmd_id: str, kind: str, target: str, ttl: int, issued_at: str, sig: str) -> bool:
    expected = sign_command(secret, cmd_id, kind, target, ttl, issued_at)
    return hmac.compare_digest(expected, sig.lower())


def _failed_ssh_event(host_id: str, source_ip: str, n: int) -> dict:
    return {
        "type": "event",
        "event": {
            "schema": "sshd.v1",
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host_id": host_id,
            "source": "sshd",
            "raw": (
                f"Aug 28 12:00:0{n} host sshd[1234]: Failed password for invalid user root "
                f"from {source_ip} port 1234 ssh2"
            ),
            "metadata": {"status": "failed", "user": "root", "service": "sshd"},
        },
    }


async def _wait_for_action_applied(factory, host_id: str, timeout: float) -> Action:
    deadline = time.time() + timeout
    while time.time() < deadline:
        async with factory() as session:
            stmt = (
                select(Action)
                .where(Action.host_id == uuid.UUID(host_id))
                .where(Action.status == "applied")
                .order_by(Action.created_at.desc())
                .limit(1)
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is not None:
                return row
        await asyncio.sleep(0.3)
    raise TimeoutError(f"no applied action for host {host_id} within {timeout}s")


async def main() -> int:
    log = get_logger("smoke_response")
    settings = get_settings()
    log.info(
        "smoke_response: starting",
        extra={"db": settings.database_url.split("@")[-1], "server": SERVER_URL},
    )

    agent_id = str(uuid.uuid4())
    secret: str | None = None

    async with websockets.connect(SERVER_URL, open_timeout=5) as ws:
        # HELLO
        await ws.send(json.dumps({"type": "hello", "agent_id": agent_id, "version": "0.4.0"}))

        # Read hello_ack with the shared_secret
        for _ in range(10):
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
            except asyncio.TimeoutError:
                break
            env = json.loads(raw)
            if env.get("type") == "hello_ack":
                secret = env.get("shared_secret")
                break
        if not secret:
            print("FAIL: server did not send hello_ack with shared_secret", file=sys.stderr)
            return 1
        log.info("smoke_response: got shared_secret via hello_ack")

        # PATCH host to enable auto_block (opt-in)
        async with httpx.AsyncClient(base_url=API_URL, timeout=5) as http:
            r = await http.patch(
                f"/api/v1/hosts/{agent_id}",
                json={"auto_block": True},
            )
            r.raise_for_status()
        log.info("smoke_response: auto_block=true")

        # Send 5 failed-login events
        for i in range(EVENTS_TO_SEND):
            await ws.send(json.dumps(_failed_ssh_event(agent_id, SOURCE_IP, i)))
            await asyncio.sleep(0.05)
        log.info("smoke_response: sent events", extra={"count": EVENTS_TO_SEND})

        # Wait for a signed command frame
        received_cmd = None
        deadline = time.time() + CMD_TIMEOUT_S
        while time.time() < deadline and received_cmd is None:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            env = json.loads(raw)
            if env.get("type") == "command":
                received_cmd = env
        if received_cmd is None:
            print("FAIL: no command frame received within timeout", file=sys.stderr)
            return 1

        # Verify HMAC
        if not verify_command(
            secret,
            received_cmd["id"],
            received_cmd["kind"],
            received_cmd["target"],
            received_cmd["ttl_sec"],
            received_cmd["issued_at"],
            received_cmd["hmac"],
        ):
            print("FAIL: HMAC verification failed", file=sys.stderr)
            return 1
        if received_cmd["kind"] != "block_ip":
            print(f"FAIL: expected kind=block_ip, got {received_cmd['kind']}", file=sys.stderr)
            return 1
        if received_cmd["target"] != SOURCE_IP:
            print(
                f"FAIL: expected target={SOURCE_IP}, got {received_cmd['target']}",
                file=sys.stderr,
            )
            return 1
        log.info(
            "smoke_response: command verified",
            extra={"kind": received_cmd["kind"], "target": received_cmd["target"]},
        )

        # ACK
        await ws.send(
            json.dumps(
                {
                    "type": "command_ack",
                    "id": received_cmd["id"],
                    "status": "applied",
                    "error": "",
                }
            )
        )

    # Wait for the action row to be marked applied
    factory = get_session_factory()
    try:
        action = await _wait_for_action_applied(factory, agent_id, timeout=5)
    except TimeoutError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        await factory().close()

    print(
        f"OK: ssh_bruteforce -> action_id={action.id} "
        f"status={action.status} kind={action.kind} target={action.target}"
    )
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(asyncio.run(main()))
