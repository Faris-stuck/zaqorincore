# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Faris-stuck/zaqorincore/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.0.0...v0.1.0
[0.0.0]: https://github.com/Faris-stuck/zaqorincore/releases/tag/v0.0.0
