# Phase 1 Plan — Agent MVP

**Phase goal:** Go single-binary agent that tails a log file and pushes structured events to a server over WebSocket. No detection, no response — just transport. Smoke-testable end-to-end against a local echo server.

**Source of truth for the design:** `ARCHITECTURE.md` in repo root.
**Done when:** an operator can install the agent on a Linux host, point it at any WebSocket echo server, and see their `auth.log` lines arrive in real time.

---

## Architecture (locked for Phase 1)

```
┌────────────────────┐  WSS/HTTPS  ┌────────────────────┐
│   zaqorin-agent    │ ───────────▶│  WebSocket server  │
│  (Go single-bin)   │   events    │  (any echo server) │
│                    │             │  - wscat           │
│  - tailer          │             │  - websocat        │
│  - transport       │             │  - future Phase 2  │
│  - config loader   │             └────────────────────┘
│  - logger          │
│  - signal handler  │
└────────────────────┘
```

**No iptables, no HMAC, no auto-response in Phase 1.** That is Phase 4.

---

## File / Package Layout (locked)

```
zaqorincore/                    (this repo)
├── agent/
│   ├── go.mod
│   ├── go.sum
│   ├── Makefile
│   ├── README.md                (how to build/run)
│   ├── cmd/
│   │   └── zaqorin-agent/
│   │       └── main.go          (entrypoint, signal handling, wiring)
│   ├── internal/
│   │   ├── config/
│   │   │   ├── config.go        (TOML loader, defaults, validation)
│   │   │   └── config_test.go
│   │   ├── tailer/
│   │   │   ├── tailer.go        (rotation-safe file tailer, channel-based)
│   │   │   └── tailer_test.go
│   │   ├── transport/
│   │   │   ├── transport.go     (WebSocket client, reconnect, heartbeat)
│   │   │   └── transport_test.go
│   │   ├── event/
│   │   │   ├── event.go         (event struct, JSON serialization, schema)
│   │   │   └── event_test.go
│   │   └── logger/
│   │       └── logger.go        (slog wrapper, structured JSON or text)
│   ├── packaging/
│   │   ├── zaqorin-agent.service   (systemd unit, hardened)
│   │   └── zaqorin-agent.env.example
│   └── testdata/
│       ├── auth_sample.log         (10 lines, varied)
│       └── rotate_test/            (used in tailer rotation test)
└── docs/
    └── PHASE1.md                (operator-facing install + run notes)
```

---

## Task Breakdown

Tasks are sized for ~2-5 minutes of focused subagent work each. Each task includes TDD where applicable.

### Task 1: Bootstrap Go module
- Create `agent/go.mod` (module `github.com/Faris-stuck/zaqorincore/agent`, Go 1.22)
- Create `agent/Makefile` with targets: `build`, `test`, `lint`, `vet`, `clean`, `run`
- Create `agent/README.md` with quick start
- **No code logic yet** — just scaffolding so `go build ./...` and `make test` work.

### Task 2: Event schema (`internal/event`)
- `Event` struct: `id` (UUID v4), `timestamp` (RFC3339Nano, UTC), `host_id` (from agent config), `source` (e.g. "auth"), `raw` (the raw log line), `metadata` (map[string]string, optional, for future detector hints)
- `New(hostID, source, raw string) Event` constructor — generates ID + timestamp
- `MarshalJSON` / `UnmarshalJSON` — explicit, with field naming `snake_case`
- Tests:
  - Round-trip JSON marshal/unmarshal preserves all fields
  - `New()` produces a valid event with non-empty ID and parseable timestamp
  - `metadata` is optional, defaults to empty map (not nil) to keep JSON output stable

### Task 3: Config loader (`internal/config`)
- TOML file (use `github.com/BurntSushi/toml`)
- Fields:
  - `server_url` (string, required, must start with `ws://` or `wss://`)
  - `agent_id` (string, defaults to "auto" → resolved to UUID at startup, persisted to `state_dir/agent_id`)
  - `auth_token` (string, optional for Phase 1, used as `Authorization: Bearer <token>` header)
  - `log_level` (string, one of "debug"|"info"|"warn"|"error", default "info")
  - `state_dir` (string, default "/var/lib/zaqorin-agent")
  - `dry_run` (bool, default true, ignored by transport in Phase 1 but present in config)
  - `[[log_source]]` array: `name` (string, required, unique), `path` (string, required, absolute)
- `Load(path string) (*Config, error)` — parses file, validates, applies defaults
- Tests:
  - Valid minimal config loads successfully
  - Missing `server_url` → error
  - `server_url` not starting with ws/wss → error
  - `log_level` invalid → error
  - Two `log_source` with same `name` → error
  - Defaults applied when fields omitted
  - Round-trip: write a config, load it, get the same struct back

### Task 4: Logger wrapper (`internal/logger`)
- Thin wrapper over `log/slog` (stdlib, no extra dep)
- `New(level string, w io.Writer) *slog.Logger`
- Default: JSON output to stderr, parseable by Loki/similar later
- Tests:
  - Output at chosen level passes through, below-level is dropped
  - Invalid level string → fall back to info + warning log (not crash)
  - JSON output is line-delimited and parseable

### Task 5: Tailer (`internal/tailer`) — biggest single task
- Rotation-safe file tailer using `github.com/nxadm/tail` (industry standard, handles rename/truncate)
- `Tailer` struct holds: source config, output channel of `[]byte` (raw lines), cancel func, wait group
- `New(source SourceConfig, logger *slog.Logger) *Tailer`
- `Start(ctx context.Context) (<-chan []byte, error)` — non-blocking, returns channel + starts goroutine
- Behavior:
  - On open, seeks to end of file (do NOT replay history) — Phase 1 is forward-only
  - On file rename/rotation, re-opens the new file at the new end
  - On context cancel, drains in-flight reads and closes channel
  - On unrecoverable error (permission denied etc), logs and closes channel — does not crash
- Tests (use `testdata/rotate_test/`):
  - Happy path: append to a file, receive the appended lines
  - File rotation: rename file, append to new file with same name, still receive new lines
  - Context cancel: start, cancel, channel closes within reasonable time
  - Missing file at start: log warning, retry with backoff; when file appears, start tailing
  - Permission denied: logs error, closes channel (no crash)

### Task 6: Transport — WebSocket client (`internal/transport`)
- Use `github.com/gorilla/websocket` (most common Go WS lib)
- `Client` struct: config (URL, token, agent_id), logger, backoff policy
- `Dial(ctx context.Context) (*Conn, error)` — opens WS, sends initial HELLO frame with `{type: "hello", agent_id, version}`
- `Send(ctx context.Context, ev event.Event) error` — JSON-encode, write, respect ctx
- Reconnect logic: exponential backoff (1s, 2s, 4s, ..., max 30s), reset on successful dial
- Heartbeat: ping every 20s, expect pong within 10s, else reconnect
- Clean shutdown on context cancel: send `type: "bye"` frame, close
- Tests (use `httptest.NewServer` + `gorilla/websocket` Upgrader):
  - Connect, receive HELLO on server side
  - Send 100 events, server receives all 100 with correct payload
  - Server forcibly closes → client reconnects, sends another event successfully
  - Heartbeat: server stops responding to pings → client reconnects within ~30s
  - Backoff: rapid disconnect/reconnect cycle does not hammer the server (assert min delay)

### Task 7: Main wiring (`cmd/zaqorin-agent/main.go`)
- Flag parsing: `--config /etc/zaqorin/agent.toml` (default)
- Load config → resolve agent_id (read from `state_dir/agent_id` or generate UUID v4 + persist)
- Init logger
- Open each `log_source` with a tailer, merge their channels with `select`/fan-in
- Open transport connection
- For each line from any tailer:
  1. Wrap as `event.New(agent_id, source.Name, line)`
  2. Send via transport (non-blocking-ish — drop on full send channel with WARN log to avoid backpressure deadlock)
- Signal handling: SIGINT/SIGTERM → cancel root context → wait for tailers + transport to drain → exit 0
- Tests:
  - `main.go` itself is hard to unit test (it's `package main`). The package-level init logic in `internal/app` (wiring) is what gets tested. (Refactor: extract wiring into `internal/app/app.go` so it can be tested.)
- Refactor: split wiring into `internal/app/app.go` with `Run(ctx, cfg, logger) error`. `main.go` becomes ~20 lines: parse flags, call `app.Run`.

### Task 8: Systemd unit + env example (`packaging/`)
- `zaqorin-agent.service`:
  - `Type=simple`
  - `User=root` (Phase 1 needs root to read `/var/log/auth.log`; Phase 4 will tighten with capability drops)
  - `ExecStart=/usr/local/bin/zaqorin-agent --config /etc/zaqorin/agent.toml`
  - `Restart=on-failure`, `RestartSec=5s`
  - `StateDirectory=zaqorin-agent`
  - `LogsDirectory=zaqorin-agent`
  - `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `ReadWritePaths=/var/log/zaqorin`
  - Hardening: `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute` (reviewable)
  - `LimitNOFILE=65536`
- `zaqorin-agent.env.example`: env-var override format for sensitive fields (e.g. `ZAQORIN_AUTH_TOKEN`)

### Task 9: Makefile targets + CI smoke
- `make build` → `CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o bin/zaqorin-agent ./cmd/zaqorin-agent`
- `make test` → `go test -race -coverprofile=coverage.out ./...`
- `make lint` → `go vet ./...` (stdlib; no golangci-lint dependency for now, document in README)
- `make vet` → alias of lint
- `make clean` → remove `bin/` and `coverage.out`
- `make run` → build + run with `--config ./agent.example.toml` if present
- `make smoke` → build, start `websocat -s 127.0.0.1:9001` in background, run agent pointed at `ws://127.0.0.1:9001`, append to a test log file, assert events arrive (script in `scripts/smoke.sh`)

### Task 10: Operator docs + repo updates
- `docs/PHASE1.md` — install, configure, run, troubleshoot (log locations, common errors)
- `agent/README.md` — quick start for developers
- `scripts/smoke.sh` — the end-to-end smoke test
- Update root `README.md` Phase 1 row from ⏳ to 🟡 in `ROADMAP.md`
- Update root `CHANGELOG.md` with the Phase 1 entry
- Tag `v0.1.0` (Phase 1 agent MVP) — not yet a stable release, but a checkpoint tag

### Task 11: Final integration review
- Subagent reviews whole `agent/` for: package boundaries, error handling consistency, test coverage, leftover `TODO`s, security flags in systemd unit, `go vet` and `go test` clean
- Subagent runs the smoke script end-to-end, reports PASS/FAIL
- Only mark Phase 1 complete when both reviewers pass.

---

## Out of Scope for Phase 1 (deferred)

- HMAC command signing (Phase 4)
- `iptables` / `nftables` integration (Phase 4)
- Multi-source fan-out with per-source backpressure (Phase 1: simple select)
- Metrics export (Prometheus) — Phase 5 or 6
- macOS / Windows support — never on roadmap
- Config hot-reload — Phase 6
- mTLS / cert pinning — Phase 4

---

## Dependencies to vendor / go get

| Module | Use |
|---|---|
| `github.com/BurntSushi/toml` | config file |
| `github.com/google/uuid` | event ID + agent_id |
| `github.com/gorilla/websocket` | WebSocket client |
| `github.com/nxadm/tail` | log tailer (rotation-safe) |

Stdlib only for: `log/slog`, `os/signal`, `context`, `encoding/json`, `net/http`, `crypto/tls`, `testing`.

No interface{} / `any` outside of explicit `metadata map[string]string`.

---

## Definition of Done (Phase 1)

- [ ] `go test -race ./...` clean
- [ ] `go vet ./...` clean
- [ ] `make build` produces a static binary under 15 MB
- [ ] `make smoke` end-to-end passes: agent tails a test file, events arrive at `websocat` echo server, payloads parse as valid JSON with the right schema
- [ ] `agent/README.md` documents install + run for an operator who has never seen the project
- [ ] `docs/PHASE1.md` exists with the operator walkthrough
- [ ] Systemd unit syntax-validates (`systemd-analyze verify`)
- [ ] No `panic`, no swallowed errors without a log
- [ ] No `TODO`s left without a tracked issue link
- [ ] `ROADMAP.md` Phase 1 row updated to ✅
- [ ] `CHANGELOG.md` has the v0.1.0 entry
- [ ] `v0.1.0` tag pushed
