# Phase 4 — Auto-response (v0.4.0)

## What shipped

When the `ssh_bruteforce` detector fires, the central server signs a
`COMMAND` frame with the affected host's shared secret and pushes it
down the existing WebSocket. The agent verifies the HMAC, applies
the action (Phase 4: `block_ip` via nftables), and acks back. The
server transitions the row from `pending → dispatched → applied`.

This closes the loop: ZaqorinCore is no longer just an observer, it
is a closed-loop IDS that can react to what it sees.

## Architecture

```
sshd auth.log
  │
  ▼  (Go agent tailer)
EVENT frame
  │
  ▼  (WebSocket)
server event_service.persist_event ─┐
                                    │
                                    ▼
                            Redis Stream zaqorin:events
                                    │
                                    ▼
ssh_bruteforce detector
   ├─ Alert row inserted (alerts table)
   └─ Action row inserted (actions table, status=pending)
                                    │
                                    ▼
            Dispatcher (background loop, 1s tick)
                │
                ├─ Skip if host.auto_block = false
                ├─ Skip if host not connected
                └─ For each pending Action:
                    ├─ sign_command(host.secret, ...)
                    ├─ send to registered WebSocket
                    └─ mark_dispatched()
                                    │
                                    ▼  (WebSocket)
agent transport.readPump
   ├─ cfg.CommandHandler(ctx, cmd)
   │   │
   │   ▼
   │  response.Handler.Handle
   │      ├─ crypto.Verify(secret, ...)
   │      └─ blockIP(ip, ttl)  ── nft add element inet zaqorin blocked_v4
   └─ sendAck(id, status)
                                    │
                                    ▼
server action_service.mark_applied / mark_failed
```

## Key design decisions

### 1. HMAC-SHA256, not JWT, not signature chains
A single shared secret, HMAC-SHA256 over a byte-stable canonical
form. The canonical form is pipe-separated text (NOT JSON) so it is
trivially byte-identical between Python and Go:

```
{command_id}|{kind}|{target}|{ttl_sec}|{issued_at}
```

JWTs add key-rotation complexity we don't need yet. When we grow
beyond per-host secrets, we'll move to Ed25519 signatures with
per-host keypairs (Phase 7+).

### 2. Per-host opt-in via `auto_block` flag
Each Host row has `auto_block BOOLEAN DEFAULT false`. The
dispatcher skips any pending Action whose host has `auto_block=false`
— the row stays `pending` forever, no COMMAND frame is sent.

Operators toggle the flag via `PATCH /api/v1/hosts/{id}`:

```bash
curl -X PATCH http://server:8000/api/v1/hosts/{agent_id} \
  -H 'Content-Type: application/json' \
  -d '{"auto_block": true}'
```

This is the "human in the loop" gate. No host is auto-blocking
without an operator flipping the switch.

### 3. Secret bootstrap is OUT-of-band
The server generates a per-host secret on first HELLO. The secret
is sent back to the agent in a `hello_ack` frame. The agent is
expected to write it to `<state_dir>/secret` (mode 0600) and exit if
the file is missing on startup.

In a real deployment the secret is delivered by the install script
that provisions the agent — not by the running agent. This is a
Phase 5 deliverable; for now we lean on the `hello_ack` frame.

### 4. Dispatcher is one loop, fans out to N hosts
A single `Dispatcher` task polls the `actions` table once a second
and pulls every `pending` row. For each one it looks up the host's
WebSocket in a `HostConnectionRegistry` and writes the frame.

If the host is disconnected, the row stays `pending` — when the
agent reconnects, the dispatcher will pick it up on the next tick.
(Phase 5 will add a "stale" timeout that surfaces undelivered
actions in `/api/v1/actions`.)

### 5. nftables, not iptables
The agent populates a named set `inet zaqorin blocked_v4` with
`flags timeout` and adds each IP with a TTL. The DROP rule that
consults the set is operator-installed (out of scope for the
agent; the install script provisions it). This is the modern
nftables idiom and avoids the iptables/nftables dual-stack
headache on systemd-managed distros.

Default rule (provided in the install script):

```
nft add table inet zaqorin
nft add set inet zaqorin blocked_v4 \
  '{ type ipv4_addr; flags timeout; }'
nft add chain inet zaqorin incoming
nft add rule inet zaqorin incoming \
  'ip saddr @blocked_v4 counter drop'
nft add rule inet zaqorin incoming \
  'ct state established,related accept'
nft add rule inet zaqorin incoming \
  'iif lo accept'
nft add rule inet zaqorin incoming \
  'tcp dport 22 accept'
```

The agent only writes to the set; it does not touch the chain.

### 6. Idempotency via command_id throttling
The agent's `response.Handler` records every successfully-applied
`command_id` in a 60s sliding window. If the server re-sends the
same `command_id` (e.g. after a flaky network), the second call
returns "applied" without re-invoking nft. The set element with
`flags timeout` is already present, so this is a no-op either
way, but the early return saves an exec.

### 7. Cooldown is per-(host, ip), not global
`actions.dedup_key` is empty for now (we deduplicate at the
detector layer, not the action layer). The Action table has a
unique index on `(host_id, kind, dedup_key)` to be filled in
Phase 5 when we add more action kinds.

## Wire contract additions

### Server → agent: COMMAND

```json
{
  "type": "command",
  "id": "5e764881-78b3-40eb-bd56-7909b9ba6025",
  "kind": "block_ip",
  "target": "198.51.100.99",
  "ttl_sec": 300,
  "issued_at": "2026-08-28T08:34:13Z",
  "hmac": "ab12...64hex"
}
```

### Agent → server: COMMAND_ACK

```json
{
  "type": "command_ack",
  "id": "5e764881-78b3-40eb-bd56-7909b9ba6025",
  "status": "applied",
  "error": ""
}
```

`status` is `"applied"` or `"failed"`. `error` is populated on
failure (HMAC mismatch, nft error, invalid IP, etc.).

### Server → agent: HELLO_ACK (on first connect)

```json
{
  "type": "hello_ack",
  "agent_id": "...",
  "shared_secret": "z4d...48char-hex"
}
```

`shared_secret` is sent exactly once, on the first HELLO from a
new agent_id. Subsequent reconnects do NOT receive a fresh
`hello_ack` — the existing secret is reused.

## Test coverage

- 55/55 server tests pass (was 28; +27 for Phase 4)
- 9/9 Go agent tests pass (Phase 4 + previous)
- Go agent binary builds clean (`go build -trimpath`)
- E2E: `scripts/smoke_response.py` proves the full loop
  (5 fails → 1 alert → 1 action → 1 signed command → HMAC
  verify → ack → action applied)

## Pitfalls hit

1. **`from ..config` was wrong in dispatcher.py** — relative
   imports must match the package depth. `dispatcher.py` is at
   the top of `zaqorincore_server`, so it imports `.config` not
   `..config`.
2. **`asyncio_default_fixture_loop_scope = "function"`** — already
   in `pyproject.toml` from Phase 3, but new tests that combine
   redis + engine + httpx ALL need the same loop. Made the
   function-scoping the rule.
3. **Conftest `engine` fixture returns `AsyncEngine`**, not a
   session factory. Tests that call `write_action(factory, ...)`
   must build `factory = async_sessionmaker(engine, ...)` first.
4. **`Dispatcher()` defaults to `registry=module_registry`** — a
   bare `Dispatcher(settings, factory)` looks at the global
   singleton, which is empty in tests. Always pass
   `registry=reg` in tests.
5. **HMAC byte-stability requires `strconv.Itoa`** for ints, not
   `fmt.Sprintf("%d", ...)` (which inserts a width spec that
   happens to be the same here, but isn't guaranteed for negative
   numbers or padding). Use `strconv.Itoa(ttlSec)`.
6. **httpx's `client.patch` raises on 4xx/5xx by default**, so
   `.raise_for_status()` is just an extra step that gives a
   clearer error.
7. **`conftest.py` password is `zaqorin:***` (sanitized form)** —
   the smoke script and pytest both need the real env var
   `zaqorin:zaqorin@` set.

## Files added / changed

**New:**
- `server/src/zaqorincore_server/crypto.py` — HMAC sign/verify
- `server/src/zaqorincore_server/detectors/action_service.py` —
  write_action, mark_dispatched, mark_applied, mark_failed
- `server/src/zaqorincore_server/dispatcher.py` —
  HostConnectionRegistry + Dispatcher
- `server/src/zaqorincore_server/migrations/versions/0002_auto_block.py`
- `agent/internal/crypto/crypto.go` — HMAC sign/verify
- `agent/internal/response/response.go` — secret file, HMAC
  verify, nftables block_ip, command_id throttle
- `server/tests/test_crypto.py` (7 tests)
- `server/tests/test_action_service.py` (4 tests)
- `server/tests/test_dispatcher.py` (3 tests)
- `server/tests/test_api_hosts_patch.py` (1 test)
- `server/tests/test_phase4_wiring.py` (1 test)
- `agent/internal/crypto/crypto_test.go` (8 tests)
- `agent/internal/response/response_test.go` (10 tests)
- `server/scripts/smoke_response.py`
- `docs/PHASE4.md` (this file)
- `docs/PHASE4_PLAN.md`

**Changed:**
- `server/src/zaqorincore_server/models/host.py` — +secret +auto_block
- `server/src/zaqorincore_server/schemas/wire.py` — +CommandFrame
  +CommandAckFrame
- `server/src/zaqorincore_server/detectors/base.py` — +
  DetectionAction dataclass; DetectionResult.action field
- `server/src/zaqorincore_server/detectors/ssh_bruteforce.py` —
  returns DetectionAction when firing
- `server/src/zaqorincore_server/detectors/runner.py` — writes
  Action row when detector returns an action
- `server/src/zaqorincore_server/api/v1/stream.py` — sends
  hello_ack, registers/unregisters in dispatcher, accepts
  command_ack, transitions Action rows
- `server/src/zaqorincore_server/api/v1/hosts.py` — PATCH
  /api/v1/hosts/{id}
- `server/src/zaqorincore_server/main.py` — starts Dispatcher in
  lifespan
- `server/src/zaqorincore_server/config.py` — +actions_poll_interval
- `server/tests/test_schemas.py` — CommandFrame test updated
- `agent/internal/transport/transport.go` — +Command type, +
  CommandHandler hook, +SetCommandHandler, +sendAck
- `agent/internal/app/app.go` — Dependencies.CommandHandler,
  re-exports Command
- `agent/cmd/zaqorin-agent/main.go` — builds response.Handler,
  registers as CommandHandler
- `CHANGELOG.md` — [0.4.0] section, [0.3.0] archived
- `ROADMAP.md` — Phase 4 ✅, Phase 3 archived
