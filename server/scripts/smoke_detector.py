"""E2E smoke for Phase 3 (detector pipeline).

Connects to a running server at ws://127.0.0.1:8000/ws/agent,
sends HELLO + 5 SSH failed-login events from the same source
IP within the sliding window, then BYE. Polls
/api/v1/alerts until the ssh_bruteforce alert shows up.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from datetime import datetime, timezone

import urllib.request
import websockets

WS_URL = "ws://127.0.0.1:8000/ws/agent"
API_URL = "http://127.0.0.1:8000/api/v1/alerts"

ATTACKER_IP = "203.0.113.42"


def _now_iso() -> str:
    # RFC3339Nano-ish, microsecond precision.
    return (
        datetime.now(tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _failed_event(event_id: uuid.UUID, host_id: uuid.UUID) -> dict:
    return {
        "type": "event",
        "event": {
            "schema": "1.0",
            "id": str(event_id),
            "timestamp": _now_iso(),
            "host_id": str(host_id),
            "source": "auth",
            "raw": (
                f"Aug 28 00:00:00 host sshd[1234]: "
                f"Failed password for root from {ATTACKER_IP} port 55555 ssh2"
            ),
            "metadata": {
                "status": "failed",
                "source_ip": ATTACKER_IP,
            },
        },
    }


async def main() -> int:
    agent_id = uuid.uuid4()
    host_id = agent_id  # WS handler uses the agent_id as host_id

    print(f"connecting to {WS_URL} as agent_id={agent_id}")
    async with websockets.connect(WS_URL) as ws:
        hello = {"type": "hello", "agent_id": str(agent_id), "version": "1.0"}
        await ws.send(json.dumps(hello))
        print("sent HELLO")

        # Send 5 events, all from the same attacker IP.
        for i in range(5):
            ev = _failed_event(uuid.uuid4(), host_id)
            await ws.send(json.dumps(ev))
            print(f"sent EVENT {i + 1}/5 ({ev['event']['id']})")
            await asyncio.sleep(0.1)

        bye = {"type": "bye", "reason": "smoke done"}
        await ws.send(json.dumps(bye))
        print("sent BYE")

    # Poll /api/v1/alerts for the ssh_bruteforce alert.
    deadline = time.time() + 10
    last_count = -1
    while time.time() < deadline:
        with urllib.request.urlopen(API_URL, timeout=2) as r:
            body = json.loads(r.read().decode("utf-8"))
        n = len(body.get("items", []))
        if n != last_count:
            print(f"  alerts so far: {n}")
            last_count = n
        ssh_alerts = [
            a for a in body.get("items", [])
            if a["detector"] == "ssh_bruteforce"
        ]
        if ssh_alerts:
            a = ssh_alerts[0]
            print()
            print("SSH-BRUTEFORCE ALERT DETECTED:")
            print(json.dumps(a, indent=2))
            assert ATTACKER_IP in a["summary"], a["summary"]
            assert a["detail"]["source_ip"] == ATTACKER_IP
            assert a["severity"] == "medium"
            print()
            print("✅ E2E detector smoke PASS")
            return 0
        await asyncio.sleep(0.5)

    print("❌ E2E detector smoke FAIL: no alert within 10s")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
