# F-009: WebSocket `/ws/agent` accepts arbitrarily large messages — DoS via single frame

| Field | Value |
|---|---|
| Severity | Medium |
| CWE | CWE-400 (Uncontrolled Resource Consumption) |
| CVSS-like | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) |
| Location | `server/src/zaqorincore_server/api/v1/stream.py:102` |
| Status | Open |

## Description

The agent WebSocket handler reads the first frame with no size cap:

```python
# server/src/zaqorincore_server/api/v1/stream.py
@router.websocket("/ws/agent")
async def ws_agent(ws: WebSocket) -> None:
    settings = get_settings()
    await ws.accept()
    ...
    first_raw = await ws.receive_text()       # line 102 — no max message limit
```

`receive_text()` waits until the WebSocket peer finishes a frame. The frame can be of
arbitrary size — uvicorn's default `ws_max_size` is 16 MiB but a misconfigured upstream
proxy or a hostile agent (or any TCP peer that has somehow gotten past the HMAC check
via a valid but reused nonce) can deliver a multi-MiB text frame and the server will
buffer it all into RAM before parsing.

There is no idle-disconnect heartbeat either — an agent that connects, sends the
challenge nonce echo, and then stalls forever (e.g. TCP keepalive off, half-open
connection) keeps the connection in the registry and one of the worker threads busy.

## Impact

* **Memory exhaustion** — concurrent WebSocket peers each pushing a single large frame
  (the server doesn't validate until JSON-parsing is attempted). With uvicorn defaults
  a single 16 MiB frame per concurrent connection is enough to OOM a server sized for the
  expected agent count.
* **Slow-loris-style DoS** — a peer can trickle a single frame at one byte per N seconds
  and the server will keep the connection open indefinitely because there is no
  read timeout.

## POC sketch

* Open a TCP connection to `/ws/agent`.
* Receive the challenge.
* Start streaming a JSON document of several GiB (`{"type":"hello", ...}` with `...`
  being a multi-GiB string) — the server will buffer all of it in RAM.

Even simpler: after receiving the challenge, send nothing for an hour. The connection
sits idle but consumes a registry slot and a worker thread.

## Remediation sketch

1. Wrap `receive_text()` with a per-call byte budget:

   ```python
   MAX_FIRST_FRAME = 64 * 1024          # 64 KiB is plenty for a HELLO frame
   first_raw = await ws.receive_text()
   if len(first_raw.encode("utf-8")) > MAX_FIRST_FRAME:
       await ws.close(code=1009)         # message too big
       return
   ```

2. Wrap subsequent `receive_*` calls with the same budget.
3. Add a server-side `ping_interval` / `ping_timeout` to uvicorn so half-open
   connections are reaped within seconds.
4. Consider a max-connections-per-IP gate at the WebSocket accept point.