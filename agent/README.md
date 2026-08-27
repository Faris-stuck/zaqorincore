# ZaqorinCore Agent

The agent is the half of ZaqorinCore that lives on the host you want to protect. It tails log files, packages each new line as a structured event, and ships those events over WebSocket to the central server.

> **Phase 1 status:** shipped as v0.1.0. Transport and event-schema contracts are stable. The agent is what gets you from "raw log line" to "JSON event on a WebSocket" in <100 ms on a quiet host.

## What you can do with this today

- Tail any file (default `/var/log/auth.log`), each new line becomes one JSON event
- Stream events to any WebSocket server (`wss://...` or `ws://...`) — including a one-line `websocat` echo for testing
- Survive server outages with exponential backoff (1s → 30s cap) and `BYE`-on-shutdown semantics
- Run as a hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `ReadWritePaths` scoped, …)
- Have a stable `agent_id` across restarts (auto-generated UUID v4, persisted to `state_dir/agent_id`)

## Quick start (developer)

```bash
# 1. Build a static binary
make build

# 2. Start a local echo server (separate terminal)
websocat -s 127.0.0.1:9001

# 3. Edit agent.example.toml — set server_url = "ws://127.0.0.1:9001"
#    and add at least one [[log_source]] block.
cp agent.example.toml agent.toml
$EDITOR agent.toml

# 4. Run the agent
./bin/zaqorin-agent --config ./agent.toml

# 5. In another terminal, append a line to the tailed file
echo "$(date) smoke test" >> /var/log/auth.log   # or whatever you configured
```

You should see the line appear on the `websocat` side as a JSON event. To assert the same end-to-end without thinking about it: `make smoke`.

## Install as a systemd service

See [`docs/PHASE1.md`](../docs/PHASE1.md) for the full operator walkthrough. Short version:

```bash
sudo install -m 0755 bin/zaqorin-agent /usr/local/bin/zaqorin-agent
sudo install -d -m 0755 /etc/zaqorin
sudo install -m 0600 agent.example.toml /etc/zaqorin/agent.toml
sudoedit /etc/zaqorin/agent.toml
sudo install -m 0644 packaging/zaqorin-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zaqorin-agent
sudo journalctl -u zaqorin-agent -f
```

## CLI flags

```text
zaqorin-agent [flags]

  -config string       path to TOML config (default "/etc/zaqorin/agent.toml")
  -log-format string   "json" (default, parseable by Loki) or "text" (human-readable)
```

Everything else is config-driven. See `agent.example.toml` at the repo root for every field.

## Layout

```
cmd/zaqorin-agent/    # main entrypoint (~70 lines: flags, signal, app.Run)
internal/
  app/                # wiring logic, testable via app.Run(ctx, cfg, log)
  config/             # TOML config loader + strict validation
  event/              # event struct + JSON schema (the wire contract)
  logger/             # log/slog wrapper, JSON/text
  tailer/             # rotation-safe file tailer (nxadm/tail)
  transport/          # WebSocket client with reconnect + heartbeat (gorilla/websocket)
packaging/            # systemd unit, env example
testdata/             # fixtures (rotation sample log, etc.)
scripts/              # smoke.sh (end-to-end)
```

## Development

```bash
make help         # list targets
make build        # static binary into ./bin/
make test         # unit tests
make test-race    # unit tests with -race
make vet          # go vet
make fmt          # go fmt -s -w
make tidy         # go mod tidy
make smoke        # end-to-end test against a local websocat
make clean        # remove ./bin/
```

## Wire frames (stable as of v0.1.0)

The frame envelope is a JSON object with a `type` discriminator. The
agent-to-server frames are the wire contract that Phase 2's central
server will consume. **All fields shown here are what is actually
on the wire today** — verified by capturing `make smoke` output
(`scripts/smoke.sh`).

```json
// Client → server on connect
{"type":"hello","agent_id":"<uuid>","version":"1.0"}

// Client → server per log line
{"type":"event","event":{"schema":"1.0","id":"<uuid>","timestamp":"2026-08-28T05:00:00.123Z","host_id":"<agent_id>","source":"auth","raw":"Aug 28 05:00:00 ...","metadata":{}}}

// Client → server on graceful shutdown
{"type":"bye","reason":"context_canceled"}

// Server → client (parsed and logged, but not applied — Phase 4)
{"type":"command","id":"<uuid>","kind":"block_ip","target":"1.2.3.4","ttl_sec":3600}
```

Notes on the shape:

- `event.host_id` equals `hello.agent_id` in Phase 1 — there is no
  separate host concept yet. The agent IS the host from the server's
  point of view.
- `event.metadata` is emitted as an empty object `{}` (not `null`)
  and `omitempty` so it is dropped entirely when there are no
  metadata keys.
- `version` in the hello frame is the protocol version (`"1.0"`),
  independent of the binary version.

## Test coverage

- `go test -race -count=1 ./...` clean on Go 1.22 and 1.23.
- 30+ test cases across 6 packages, including: rotation (rename + recreate), missing-file-then-appears, concurrent writers, WebSocket reconnect after server close, command-frame parsing, config validation round-trip, JSON shape stability, pool reuse, end-to-end app wiring.

## Design references

- Repo root: `ARCHITECTURE.md` — the full system design
- Repo root: `docs/PHASE1_PLAN.md` — what Phase 1 ships and what it does not
- `docs/PHASE1.md` — operator walkthrough (install, run, troubleshoot)
- `internal/event/event.go` — the wire contract in code
- `CHANGELOG.md` — what changed in v0.1.0

## What this version does NOT do

- No detection. The agent emits raw events; the server-side detectors land in Phase 3.
- No response. The agent receives `command` frames and logs them, but does not act on them. Phase 4 adds HMAC verification + the `block_ip` dispatch.
- No hot-reload of config. Restart the service after editing the TOML.
- No Windows or macOS agent. Linux only for v0.1.0.
