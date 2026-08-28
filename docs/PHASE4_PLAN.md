# Phase 4 — Auto-response (v0.4.0)

## Goal

When the `ssh_bruteforce` detector fires, the server signs
a `COMMAND` frame, pushes it back to the affected agent over
the existing WebSocket, the agent verifies the HMAC, runs
`iptables -I INPUT -s <ip> -j DROP` with a TTL, and acks
back. The action row in `actions` table tracks lifecycle:
`pending` → `dispatched` → `applied` (or `failed`).

Auto-block is **opt-in per host** (default `false`).

## Wire contract v1.1 (additive — v1.0 agents ignore COMMANDS)

### server → client: `command` frame
```json
{
  "type": "command",
  "id": "<uuid>",
  "kind": "block_ip",
  "target": "1.2.3.4",
  "ttl_sec": 3600,
  "issued_at": "2026-08-28T12:34:56Z",
  "hmac": "<hex>"  // HMAC-SHA256 of canonical payload w/ host secret
}
```

The `command` frame uses an **envelope** that already exists
in the agent's `commandFrame` struct (Phase 1 added it but
ignored the frame). The new fields are `issued_at` and
`hmac`. The `commandFrame` struct grows.

### client → server: `command_ack` frame (NEW)
```json
{
  "type": "command_ack",
  "id": "<uuid>",         // the command id
  "status": "applied" | "failed",
  "error": "<string>"     // only on failed
}
```

The agent's `ws_agent` handler learns to accept this frame
and update the corresponding `actions` row.

## HMAC signing

Canonical payload (the bytes signed):
```
{id}|{kind}|{target}|{ttl_sec}|{issued_at}
```

The host secret lives in a new `hosts.secret` column
(NOT exposed via REST), generated server-side at HELLO
time if not present. The secret is 32 random bytes,
base64-encoded. The agent does NOT learn the secret over
the wire — operators bootstrap it via `agent.example.toml`
`response.shared_secret` OR via a one-time `GET
/api/v1/hosts/{agent_id}/bootstrap` (Phase 4 ships the
secret on the HELLO response header for simplicity, see
"Pitfalls").

## Lifecycle of an action row

1. `pending` — `Action` row inserted in `write_action` after
   `write_alert` returns. `host_id`, `alert_id`, `kind`,
   `target`, `ttl_sec` are set.
2. `dispatched` — Dispatcher pops the row, looks up the
   host's WS connection (or queues onto a per-host Redis
   list if the agent is offline), and writes the signed
   `command` frame. `sent_at` is set.
3. `applied` or `failed` — Agent runs the action (or
   refuses it), sends `command_ack`. Server sets `acked_at`
   + `status`.

## Files added / changed

**Server (`server/src/zaqorincore_server/`):**
- `crypto.py` (NEW) — `sign_command(secret, payload) -> str`,
  `verify_command(secret, frame) -> bool`, plus key-gen.
- `detectors/action_service.py` (NEW) — `write_action`,
  `mark_dispatched`, `mark_applied`, `mark_failed`.
- `dispatcher.py` (NEW) — background task: polls the
  `actions` table for `pending` rows, signs the command,
  delivers it to the host's WS (or queues it), marks
  `dispatched`. Acks flow back through the WS handler and
  flip the row to `applied`/`failed`.
- `migrations/versions/0002_auto_block.py` (NEW) — adds
  `hosts.secret` (nullable, 64 chars base64) + adds
  `commands_queue` (per-host Redis list) handling.
- `api/v1/stream.py` (MOD) — HELLO response now sends
  back the host's secret in a header (NOT a frame, because
  the agent is still mid-frame). Acks update action rows.
- `schemas/wire.py` (MOD) — `CommandFrame` and
  `CommandAckFrame` Pydantic models.
- `detectors/runner.py` (MOD) — after a `DetectionResult`
  is successfully written, also call
  `dispatcher.enqueue_for(host_id, ...)` for any
  `result.action` payloads (Phase 3 detector optionally
  returns one).

**Agent (`agent/`):**
- `internal/response/response.go` (NEW) — interface
  `Response` with `BlockIP(ip, ttl) error`; concrete
  `IptablesResponse` impl.
- `internal/crypto/verify.go` (NEW) — `VerifyCommand(
  payload, secret, hmacHex) error`.
- `internal/transport/transport.go` (MOD) — `commandFrame`
  adds `IssuedAt` and `HMAC`. `readPump` calls a registered
  `CommandHandler` after successful verify. Adds
  `SendAck(ctx, id, status, errMsg) error` to the Client.
- `internal/config/config.go` (MOD) — `Response.SharedSecret`
  field, validated at startup. (Bootstrap via the HELLO
  response header from the server; agent persists to
  `state_dir/shared_secret`.)

## What this phase does NOT do

- **No offline-queue persistence on agent side.** If the
  agent reconnects AFTER the server has pushed a command,
  the server still has the row; we re-send on reconnect.
  We don't keep a per-agent in-memory queue because
  losing the agent process loses the command — the server
  is the source of truth.
- **No automatic unblock cron.** The TTL is a hint; the
  agent is responsible for `iptables -D INPUT` after
  `ttl_sec` seconds. (We can move this to a server-side
  cron in Phase 5.)
- **No multi-action queues.** A host that is supposed to
  receive two commands concurrently serialises them
  through the WebSocket.
- **No command retry on the agent side.** If `iptables`
  fails, the agent sends `command_ack` with `status=failed`
  and the server records it.

## Pitfalls (planned)

- **Agent secret bootstrap**: the easiest scheme is to
  send the secret back in the HELLO response HTTP header
  (since the agent is still mid-WS-handshake). The
  alternative is a second REST call after HELLO, which
  races. We use the header. The agent writes it to
  `state_dir/shared_secret` and uses it from there on.
- **Per-host WS connection registry**: the dispatcher
  needs a `dict[host_id, WebSocket]` the WS handler
  populates on connect and removes on disconnect. The
  same registry is used to send a `command` frame
  (synchronous `await ws.send_text`).
- **HMAC over a canonical form, not the raw JSON**, to
  avoid whitespace / ordering differences. The canonical
  form is `id|kind|target|ttl_sec|issued_at`.
- **iptables privilege**: the agent must be run as root
  (or with `CAP_NET_ADMIN`). Operator responsibility.
  The agent refuses to run if `dry_run=true` and `iptables`
  actually does anything.

## DoD

- [ ] `migrations/versions/0002_auto_block.py` applies
- [ ] `crypto.py` roundtrip (sign → verify) passes unit
- [ ] `action_service.py` write/mark_* helpers tested
- [ ] `dispatcher.py` pops pending → dispatches via WS
- [ ] WS handler accepts `command_ack` and updates action
- [ ] Agent `IptablesResponse` applies + removes on TTL
- [ ] Agent `VerifyCommand` rejects bad HMAC
- [ ] E2E: 5 SSH failed-login events → 1 alert → 1 action
      applied, `iptables` shows the rule, action row is
      `applied` with `acked_at` set
- [ ] 32+ pytest pass
- [ ] `docs/PHASE4.md`, CHANGELOG v0.4.0, ROADMAP Phase 4
      ✅
- [ ] Tag v0.4.0 + push
