"""Quick end-to-end test: WebSocket client sends HELLO + 3 EVENT + BYE,
server persists to DB. Used as the smoke test for Phase 2.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx
import websockets

SERVER = "ws://127.0.0.1:8000/ws/agent"
API = "http://127.0.0.1:8000"


async def main() -> int:
    agent_id = str(uuid.uuid4())
    now_iso = lambda: datetime.now(timezone.utc).isoformat()

    async with websockets.connect(SERVER) as ws:
        # 1. HELLO
        hello = {"type": "hello", "agent_id": agent_id, "version": "1.0"}
        await ws.send(json.dumps(hello))
        print(f"[smoke] sent HELLO agent_id={agent_id}")

        # 2. Three EVENTs
        for i in range(3):
            ev = {
                "type": "event",
                "event": {
                    "schema": "1.0",
                    "id": str(uuid.uuid4()),
                    "timestamp": now_iso(),
                    "host_id": agent_id,
                    "source": "test",
                    "raw": f"smoke-line-{i + 1}",
                    "metadata": {"smoke": "1"},
                },
            }
            await ws.send(json.dumps(ev))
            print(f"[smoke] sent EVENT {i + 1}: {ev['event']['id']}")
            await asyncio.sleep(0.1)

        # 3. BYE
        await ws.send(json.dumps({"type": "bye", "reason": "smoke_done"}))
        print("[smoke] sent BYE")

    # 4. Verify via REST API
    await asyncio.sleep(0.5)  # let server commit
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{API}/api/v1/hosts/{agent_id}")
        if r.status_code != 200:
            print(f"[smoke] FAIL: hosts/{agent_id} -> {r.status_code} {r.text}")
            return 1
        host = r.json()
        if host["event_count"] != 3:
            print(
                f"[smoke] FAIL: expected 3 events, got {host['event_count']} "
                f"({r.text})"
            )
            return 1
        print(
            f"[smoke] host OK: id={host['id']} event_count={host['event_count']}"
        )

        r = await client.get(
            f"{API}/api/v1/events", params={"host": agent_id, "limit": 10}
        )
        events = r.json()
        if len(events) != 3:
            print(
                f"[smoke] FAIL: expected 3 events, got {len(events)}: {events}"
            )
            return 1
        for ev in events:
            assert ev["source"] == "test", ev
            assert ev["raw"].startswith("smoke-line-"), ev
        print(f"[smoke] events OK: {len(events)} rows, all from 'test' source")

    print("[smoke] SMOKE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
