# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-08-28

### Added
- **Auto-response (Phase 4)**: closed-loop IDS. When the `ssh_bruteforce` detector fires, the server signs a `COMMAND` frame with the affected host's shared secret and pushes it down the existing WebSocket. The agent verifies the HMAC, applies the action, and acks back. Server transitions the row from `pending → dispatched → applied`.
- **HMAC-SHA256 wire signing** (`server/crypto.py`, `agent/internal/crypto/crypto.go`): byte-stable canonical form `cmd_id|kind|target|ttl_sec|issued_at`, kept in lockstep between Python and Go via shared test cases. Constant-time compare.
- **`actions` table** + `action_service` (write/mark_dispatched/mark_applied/mark_failed). Migration `0002_auto_block` adds `secret` and `auto_block` columns to `hosts`.
- **Dispatcher** (`server/dispatcher.py`): single background loop polls `actions` for `pending` rows, looks up the host's WebSocket in a `HostConnectionRegistry`, signs the command, sends it, marks dispatched.
- **`PATCH /api/v1/hosts/{id}`** — operator gate to flip `auto_block` on/off. Default `false`; no host auto-blocks without an explicit operator action.
- **`hello_ack` frame**: server returns the per-host `shared_secret` on first HELLO. Agent persists to `<state_dir>/secret` (mode 0600).
- **`COMMAND_ACK` wire frame**: agent → server outcome report (`status: applied|failed`, `error: string`).
- **Agent `response` package** (`agent/internal/response/response.go`): loads secret file, verifies HMAC, applies `block_ip` via `nft add element inet zaqorin blocked_v4 { ip timeout <ttl>s`. DryRun mode for tests. 60s command_id throttle for idempotency.
- **`scripts/smoke_response.py`** — E2E: 5 SSH failed-login events → 1 alert → 1 signed COMMAND → HMAC verify → ACK → action `applied`. Proves the full loop.
- **Tests**: 55/55 server (was 28, +27 for Phase 4) + 9/9 Go agent tests pass.
- **`docs/PHASE4.md`** — full architecture, decisions, pitfalls, wire contract, install script for the nftables rule that consults the set.

### Wire contract additions
- `COMMAND` (server → agent): `type=command, id, kind, target, ttl_sec, issued_at, hmac`
- `COMMAND_ACK` (agent → server): `type=command_ack, id, status, error?`
- `HELLO_ACK` (server → agent, on first connect only): `type=hello_ack, agent_id, shared_secret`

### Security
- HMAC verify is constant-time.
- Secret is sent in plaintext over the existing WebSocket (assumed WSS-terminated at the load balancer). Phase 5 will add per-command nonce + replay protection.
- `auto_block` defaults to `false` — opt-in only.

### Pitfalls hit (see `docs/PHASE4.md` for full list)
- `from ..config` was wrong import path in `dispatcher.py`.
- `Dispatcher(...)` defaults to module-level `registry` — tests must pass `registry=reg` explicitly.
- Conftest `engine` fixture returns `AsyncEngine`, not session factory — tests must wrap with `async_sessionmaker`.
- HMAC byte-stability requires `strconv.Itoa` for ints in Go, not `fmt.Sprintf` (could differ for negative numbers or width).

## [0.3.0] — 2026-08-28

### Added
- **`server/detectors/`** — Phase 3 detector pipeline. A background asyncio task consumes events off the `zaqorin:events` Redis stream via the `zaqorin-detectors` consumer group, fans them through registered detector plugins, and persists `Alert` rows when a rule fires.
- **`ssh_bruteforce` detector** — sliding-window rule over failed SSH-login events. Threshold (default 5 failed logins in 60s) and cooldown (default 300s) are env-var-tunable. State lives in Redis sorted sets; the detector is fail-open on Redis errors.
- **`GET /api/v1/alerts`** now returns a real paginated, filterable list (the v0.2.0 stub is gone). Response shape: `{ items: [...], next_before: <iso|null> }`. Filters: `host_id`, `detector`, `since`, `until`, `limit`.
- **`scripts/smoke_detector.py`** — E2E smoke that drives the running server with 5 SSH failed-login events from `203.0.113.42` and asserts exactly one `ssh_bruteforce` alert lands in DB.
- `docs/PHASE3.md` — operator walkthrough of the detector framework.

### Changed
- **Server version** bumped to 0.3.0.
- **Settings** added `detectors_enabled`, `ssh_bruteforce_threshold`, `ssh_bruteforce_window_sec`, `ssh_bruteforce_cooldown_sec`.
- **pyproject.toml** `asyncio_default_fixture_loop_scope` changed from `session` to `function` (required by the new detector tests that talk to real Redis on the test event loop).
- The v0.2.0 `[Unreleased]` notes (`stream_name` reserved for Phase 3, `streams_enabled` test flag, etc.) are now obsolete and removed from the Unreleased section.

### Fixed
- **Detached host_id in detector tests** — every `_make_event()` was generating a new `host_id` which meant every event went to a different Redis key. Tests now use a stable `_TEST_HOST_ID` per module.
- **FK violation in alert writer tests** — tests now insert a host row before writing an alert with a non-null `host_id`.
- **`test_alerts_empty`** in `test_api_health.py` — was asserting `r.json() == []` (the old stub shape). Now asserts the new `{"items": [], "next_before": null}` shape.

### Test coverage
- `pytest` clean: **28 tests in 6 files** (`test_schemas.py` 8, `test_api_health.py` 3, `test_service.py` 4, `test_ws_hello_event_bye.py` 2, `test_detector_ssh_bruteforce.py` 6, `test_alert_service.py` 2, `test_api_alerts.py` 3) in ~7s.
- E2E: `scripts/smoke_detector.py` PASS — 5 events with `status=failed, source_ip=203.0.113.42` → 1 alert in DB.
- E2E (regression): `scripts/smoke.py` PASS — 3 events without SSH metadata → 0 alerts (detector filter works).

## [0.2.0] — 2026-08-28

### Added
- **`server/`** — Phase 2 server. A FastAPI app that accepts WebSocket streams from any `zaqorin-agent` v0.1.0+, persists events to PostgreSQL, fans them through Redis Streams, and exposes a read-only REST API. ~2,400 LOC Python.
  - `POSTGRES 16` schema with 4 tables (`hosts`, `events`, `alerts` placeholder, `actions` placeholder) and an Alembic migration (`migrations/versions/0001_initial.py`).
  - `redis.asyncio` Streams publisher (`XADD` to `zaqorin:events` with consumer group `zaqorin-detectors` reserved for Phase 3).
  - Pydantic v2 wire-contract schemas (`schemas/wire.py`) with `ConfigDict(extra="forbid")`.
  - `WS /ws/agent` handler with first-frame MUST-be-HELLO enforcement (closes 1002 on violation), per-event idempotency on `event.id` (duplicate raises `DuplicateEvent` → silent ack), 64 KiB frame cap.
  - `GET /healthz` (liveness) and `GET /readyz` (readiness: pings DB + Redis, 503 on either failure).
  - `GET /api/v1/hosts`, `GET /api/v1/hosts/{agent_id}`, `GET /api/v1/events` (filters: `since`, `until`, `host_id`, `source`), `GET /api/v1/alerts` (returns `[]` until Phase 3).
- `server/src/zaqorincore_server/` — package layout: `api/{health,v1}`, `models/{host,event,alert,action,base}`, `service/{host_service,event_service}`, `streams/{publisher,consumer}`, `schemas/wire.py`, `config.py`, `db.py`, `logging.py`, `main.py`.
- `server/Dockerfile` — multi-stage build (~150 MB), non-root `zaqorin` user, `HEALTHCHECK` on `/healthz`.
- `server/docker-compose.yml` — full Phase 2.5+ production stack (postgres + redis + server).
- `server/scripts/smoke.py` — end-to-end WebSocket client that drives a real uvicorn + the actual `zaqorin-agent` v0.1.0 binary and asserts DB rows.
- `server/tests/` — 17 unit + integration tests, all green in ~4.5s.
- `docs/PHASE2.md` — operator walkthrough: dev loop, prod deploy, API reference, wire contract.

### Test coverage
- `pytest` clean: 17 tests in 4 files (`test_schemas.py` 8, `test_api_health.py` 3, `test_service.py` 4, `test_ws_hello_event_bye.py` 2).
- Function-scoped async engine (NullPool) wired into the module-level singleton per test so the WS handler runs on the same event loop as the test runner.
- End-to-end: real `zaqorin-agent` v0.1.0 → real `uvicorn` → real `postgres:16-alpine` → DB rows verifiable.

### Notes
- The dev loop uses the existing `zc-postgres` container on `127.0.0.1:25432` and `laporin-redis` on db 5 to avoid colliding with the Cogniflux production postgres (port 5432 host) and the Laporin production Redis (db 0, 422 keys).
- No authentication on `/ws/agent` — agents are identified by the `agent_id` they present. A future Phase 2.1 will add per-agent shared-secret auth.
- No tests for Redis Streams yet (the `streams_enabled=False` switch skips them in unit tests). Phase 3 will add stream-consumption tests.

## [0.1.0] — 2026-08-28

### Added

- **`agent/`** — Phase 1 agent MVP. A Go single-binary that tails log files and ships each new line to a WebSocket server. ~5 MB static binary, `linux/amd64` and `linux/arm64`.
- `internal/event` — wire-contract schema (UUID v4 IDs, RFC3339Nano UTC timestamps, snake_case JSON, stable `metadata` map, object pool for high-throughput).
- `internal/tailer` — rotation-safe file tailer backed by `nxadm/tail` (handles rename, truncate, missing file with exponential backoff retry).
- `internal/transport` — `gorilla/websocket` client with HELLO/EVENT/BYE/COMMAND frames, exponential reconnect backoff (1s → 30s cap), heartbeat ping every 20s with 10s pong-wait, and concurrent-safe `Send`.
- `internal/config` — TOML loader with strict validation (URL scheme, log level enum, duplicate source detection, absolute-path enforcement) and stable `agent_id` resolution (operator-pinned UUID or auto-generated + persisted).
- `internal/logger` — `log/slog` wrapper with JSON / text format and graceful fallback on invalid level.
- `internal/app` + `cmd/zaqorin-agent` — wiring layer and entrypoint. Signal handling via `signal.NotifyContext(SIGINT, SIGTERM)`.
- `packaging/zaqorin-agent.service` — hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges`, scoped `ReadWritePaths`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `IPAddressDeny=any` by default).
- `packaging/zaqorin-agent.env.example` — environment-variable override template for secrets.
- `scripts/smoke.sh` — end-to-end smoke test against `websocat` (asserts 1 HELLO + N EVENT frames).
- `.github/workflows/ci.yml` — CI on push/PR: `go test -race` against Go 1.22 + 1.23, `go vet`, static binary build, binary size budget (15 MB cap), and the smoke test.
- `docs/PHASE1.md` — operator walkthrough: install, run, troubleshoot.
- `docs/PHASE1_PLAN.md` — the design plan that this phase implements (locked, kept for posterity).

### Test coverage

- `go test -race -count=1 ./...` clean on Go 1.22 / 1.23.
- 30+ test cases across 6 packages, including: rotation (rename + recreate), missing-file-then-appears, concurrent writers, WebSocket reconnect after server close, command-frame parsing, config validation round-trip, JSON shape stability.

### Notes

- The `command` frame type is **parsed and logged** but not applied. Phase 4 will add HMAC verification + an action dispatch table (`block_ip` only in Phase 4; `kill_process` / `disable_user` / `notify` are planned but not yet implemented).
- No CLI flag for `--dry-run` override exists; the config field is parsed and stored but transport does not gate on it yet (no commands to gate).

## [0.0.0] — 2026-08-27

### Added

- Public repository created at <https://github.com/Faris-stuck/zaqorincore>
- Project intent: self-hosted proactive defense platform (real-time detection + auto-response)
- MIT License

[Unreleased]: https://github.com/Faris-stuck/zaqorincore/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.0.0...v0.1.0
[0.0.0]: https://github.com/Faris-stuck/zaqorincore/releases/tag/v0.0.0
