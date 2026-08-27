# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

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

[Unreleased]: https://github.com/Faris-stuck/zaqorincore/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.0.0...v0.1.0
[0.0.0]: https://github.com/Faris-stuck/zaqorincore/releases/tag/v0.0.0
