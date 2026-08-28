# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-08-28

### Added

- **Canary tokens** (`server/canary.py`, `agent/internal/canary/canary.go`).
  Deception layer: drop a file or bind a TCP port, watch it via
  fsnotify, alert on touch. Two of four kinds shipped (`file`,
  `tcp_socket`); `http_endpoint` and `credential` are stubbed
  for Phase 8.
- **Evidence locker** (`server/evidence.py`, `agent/internal/evidence/evidence.go`).
  When an alert fires, an operator can capture a snapshot of
  the relevant files, tar+gz them, and POST the bundle. The
  server verifies SHA-256, writes a sidecar JSON, and HMAC-
  signs it. Operators verify integrity via `/api/v1/evidence/{id}/verify`.
- **Operator API** for canary (`/api/v1/canary`) and evidence
  (`/api/v1/evidence`).

### Changed

- `EvidenceSubmit` wire field renamed `tarball` → `tarball_b64`
  to make base64 encoding explicit (pydantic v2 `bytes`
  validation is ambiguous in JSON). Raw `tarball` is still
  accepted as a legacy alias for tests.

## [0.6.0] - 2026-08-28

### Added

- **Sigma-compatible rule engine** (`server/src/zaqorincore_server/rule_engine/`).
  Operators write detection rules in YAML and the server runs them
  against the event stream. Supports selection (string, list, `re:`,
  `contains:`), timeframe, count threshold, per-rule cooldown,
  per-dedup-key action emission.
- **Five built-in Sigma rules** under `server/rules/builtin/`:
  ssh_bruteforce, port_scan, web_attack, dns_tunnel, impossible_travel.
- **Hunt query API** (`/api/v1/hunt/rules`, `/api/v1/hunt/run`).
  Replay a Sigma rule against historical events for forensic
  search. Read-only, no alerts or actions created.
- **FakeRedis** (`server/tests/fake_redis.py`). Tiny in-memory
  Redis stand-in for the rule runner tests.

### Changed

- `server/detectors/runner.py` now runs both Python detectors
  AND Sigma rules on every event.
- `Settings.rules_dir` added (default `rules/builtin`).

### Pitfalls

- PyYAML single-quoted strings interpret `\b` as backspace.
  Use single quotes for regex patterns with word boundaries.
- `event.occurred_at` is no longer used for sliding-window
  timing; the runner uses its injected `clock`. Tests must
  pass a fake clock to control time.

## [0.5.0] - 2026-08-28

### Added

- **Multi-scale deployment** via `ZAQORIN_DEPLOYMENT_MODE`
  (individual / startup / enterprise). One binary, three
  presets, runtime mode flag.
- **Nine action kinds** (`server/action_kinds.py`,
  `agent/internal/response/kinds/`). Dispatcher validates
  every action against the per-kind policy; the agent
  executors apply them.
- **Four new detectors**: port_scan, web_attack, dns_tunnel,
  auth_anomaly.
- **Five ADRs** in `docs/decisions/`.
- **18 new Go tests** for the 9 action executors.

### Changed

- `server/dispatcher.py` now consults `action_kinds.KINDS` on
  every command. Unknown kinds are rejected at sign time.

## [0.4.0] - 2026-08-28

### Added

- **Auto-response**: SSH brute-force detector fires an Action,
  the dispatcher signs and pushes a `block_ip` command to the
  agent, the agent applies it via `nftables` (nft set with TTL).
- **Cross-language HMAC** between Go and Python over the WS
  COMMAND frame. Canonical pipe-separated form, constant-time
  compare, 32-byte urlsafe shared secret.
- **`command_ack` frame** from agent to server, marks the
  Action row as `applied`.

## [0.3.0] - 2026-08-28

### Added

- **Detector pipeline**: `server/detectors/runner.py` consumes
  `zaqorin:events` via XREADGROUP, fans events through registered
  detector plugins, persists Alert rows.
- **One detector ships**: `ssh_bruteforce` (sliding window 5/60s,
  cooldown 300s, Redis sorted-set state, fail-open on Redis errors).
- **Real `/api/v1/alerts`** endpoint (replaces Phase 2 stub):
  paginated, filterable by detector, host, severity, time range.

## [0.2.0] - 2026-08-28

### Added

- **FastAPI server** with PostgreSQL 16 + Redis Streams.
- **WebSocket** `/ws/agent` for the agent transport.
- **Alembic migrations** for hosts, events, alerts, actions.
- **`/healthz`** and **`/readyz`** probes.
- **17 server tests**.

## [0.1.0] - 2026-08-28

### Added

- **Go agent** that tails `auth.log` (and any configured file),
  parses failed-login lines, and ships them to the server over
  a WebSocket transport. ~5 MB static binary, hardened systemd
  unit, TOML config, `make build` for linux/amd64 + linux/arm64.
- **End-to-end smoke** (`scripts/smoke.sh`).

[Unreleased]: https://github.com/Faris-stuck/zaqorincore/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Faris-stuck/zaqorincore/releases/tag/v0.1.0
