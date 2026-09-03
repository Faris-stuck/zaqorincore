# F-029 — WebSocket `/ws/agent`: HELLO frame is uncapped, and JSON parse is unbounded in nesting depth (Medium)

| Field | Value |
|---|---|
| **ID** | F-029 |
| **Round** | 19 (cycle 102, narrow scope) |
| **Phase** | 1 (SECURITY track) |
| **Date** | 2026-09-04 |
| **Commit under audit** | `a815ced` (v3.4.29) |
| **Component** | `server/src/zaqorincore_server/api/v1/stream.py` (lines 101-108, 252) |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits or Throttling) |
| **Severity** | **Medium** |
| **Status** | **Closed in v3.4.30** (cycle 102) |

## Summary

Two related issues in the agent WebSocket path that the F-009 fix left
behind:

1. The HELLO frame (line 103) is read with no application-level byte
   cap. F-009 only capped subsequent frames via
   ``settings.ws_max_msg_bytes`` (default 1 MiB) — the size check
   happens *after* ``receive_text()`` returns, so the server has
   already buffered the entire frame into RAM. A hostile or buggy
   agent that passes the HMAC check can deliver a multi-MiB first
   frame and exhaust server memory.

2. Both the HELLO parse and the subsequent per-frame parse call
   ``json.loads`` (lines 105, 252). ``json.loads`` is unbounded in
   nesting depth — a 64 KiB HELLO of `[[[...]]]]` trips
   ``sys.setrecursionlimit`` (default 1000) and raises
   ``RecursionError``. The current code catches ``json.JSONDecodeError``
   but **not** ``RecursionError``, so the exception propagates, kills
   the worker, and the connection 500s.

## Impact

1. **Memory exhaustion.** A single agent that opens `/ws/agent`,
   receives the challenge, then sends a multi-MiB first frame will
   cause the server to allocate the full frame in RAM before any
   further work. Concurrent connections each doing this can OOM a
   server sized for the expected agent count. The uvicorn default
   `ws_max_size` of 16 MiB is the upper bound at the network layer
   — the application does not tighten it.

2. **Recursion-amplified CPU DoS.** A small (under 64 KiB) frame of
   `{"a":{"a":{"a":...}}}` raises `RecursionError` in the default
   CPython JSON decoder, which the route handler does not catch. The
   exception propagates up through FastAPI, the worker 500s, and the
   WebSocket disconnects. An attacker who has the HMAC secret (or
   misconfigured agent) can deny service with very few requests.

3. **No integrity loss.** The HMAC check happens *after* both
   bytes-of-frame and JSON parse, so a rejected frame never
   produces an authenticated session. The impact is purely
   availability.

## Reproduction

```python
# 1. Connect to /ws/agent (requires knowing the HMAC secret or
#    running a misconfigured agent). Receive the challenge.
# 2. Send a 16 MiB HELLO frame:
#    {"type":"hello","v":2,"id":"...","nonce":"...","sig":"...","pad":"<16 MiB>"}
# 3. Server buffers the full frame in RAM; size check fires AFTER
#    receive_text() returns, so the damage is done.
```

```python
# 1. Same setup.
# 2. Send a 4 KiB HELLO of deeply-nested JSON:
#    {"a":{"a":{"a":{...{"a":null}...}}}}   (1000+ levels)
# 3. json.loads raises RecursionError. Not caught. Worker 500s.
```

## Recommended fix (applied in v3.4.30)

1. Add a HELLO-specific byte cap of 64 KiB. A well-formed HELLO is
   well under 1 KiB even with a generous HMAC; 64 KiB is paranoid
   but bounded.
2. Re-use the depth-limited decoder from F-027 / F-028
   (``zaqorincore_server.utils.depth_json.safe_loads``) for both
   the HELLO and the per-event-frame parse. This caps nesting
   depth at 32 levels and converts deep-nest attacks into
   ``ValueError`` (which is already caught).

## Verification

`server/tests/api/test_ws_hello_f029.py` covers:

* normal HELLO parses cleanly
* HELLO exceeding the 64 KiB byte cap is identified as oversize
* HELLO within the byte cap but over the depth cap is rejected
* event frames at the depth cap parse; over the cap are rejected
* `DepthLimitedDecoder` default cap matches the module constant

23/23 tests pass (F-027 + F-028 + F-029 combined).

## Pitfall

The size check on `len(first_raw) > MAX_HELLO_BYTES` must happen
*after* `receive_text()` returns but *before* the `json.loads` call.
Placing it after the parse is too late — the buffer has already
been allocated. The fix above puts the byte check first, then the
depth-limited parse, then the protocol-level checks.
