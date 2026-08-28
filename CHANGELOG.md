# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-08-28

### Added

- **Bundled web console** — single-page React 18 app served
  from the same FastAPI process. Drop the binary on a host,
  point a browser at `http://<host>:8000/`, get the whole SOC.
  - **Alerts** (`#/alerts`): filter by severity / host_id,
    paginate via `before` cursor, expand JSON detail per
    alert.
  - **Hunt** (`#/hunt`): list all 56 rules, pick one, run
    against the last 1/7/30/90 days, render matches.
  - **Evidence** (`#/evidence`): list every signed bundle,
    one-click verify against the stored HMAC + SHA-256
    sidecar. Shows "chain of custody intact" / "INVALID".
  - **Canary** (`#/canary`): list active canaries, create
    new file / tcp_socket / http_endpoint / credential
    canaries, surface every `touched` event.
  - SPA is a single HTML file + one `static/app.js` bundle
    (no build step, no Node toolchain).
- **`SecurityHeadersMiddleware`** — applies a baseline of
  HTTP security headers to every response (API + SPA):
  CSP, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy: camera=(), microphone=(),
  geolocation=(), payment=()`. This is a SOC console —
  none of those features are ever needed.
- **CSP is allowlisted** so the page can load React 18
  from the esm.sh CDN with a documented post-1.0
  tightening plan (`script-src 'self'` only, after
  vendoring React into `webui/static/vendor/`).
- 6 new tests in `tests/test_webui.py` covering SPA
  serving + security headers (170/170 server tests pass).

### Notes

- **No auth UI yet.** The console assumes the server is
  reachable only on a trusted network. Adding
  OIDC/SAML/mTLS/bearer-token auth is a v1.0+ task; see
  the Phase 9 doc + `ROADMAP.md`.
- FastAPI app version bumped `0.8.0 → 0.9.0`.
- Zero new Go code — Phase 9 is server + browser only.

## [0.8.0] - 2026-08-28

### Added

- **Compliance pack** — 51 new Sigma rules organized by framework:
  - `iso27001_nist80053/` (13 rules): ISO 27001:2022 Annex A +
    NIST SP 800-53. Each rule names the specific control
    (A.5.15, A.5.16, A.5.17, A.5.18, A.5.24, A.5.25, A.5.28,
    A.5.30, A.5.31, A.5.34, A.5.36, A.8.5, A.8.15).
  - `pci_dss/` (13 rules): PCI DSS v4.0 requirements 1–12
    (req1 firewall, req2 default creds, req3 cardholder data,
    req4 encryption, req5 antimalware, req6 patches, req7 RBAC,
    req8 user identification, req9 physical media, req10 audit
    log, req11 vuln scan, req12 security policy, appendix C
    payment app).
  - `uu_pdp/` (13 rules): Indonesia UU PDP No. 27/2022 +
    POJK/BI. Rules in Bahasa Indonesia, covering pasal
    35–48, plus data-anak perlindungan and POJK-13 data
    nasabah.
  - `mitre_attack/` (12 rules): MITRE ATT&CK Enterprise
    techniques (T1003, T1059, T1078, T1110, T1190, T1486,
    T1490, T1543, T1547, T1552, T1567, T1569).
  - Every rule has `tags` + `references` so auditors can
    trace coverage to the standard.
  - Total rules in `rules/builtin/`: 56 (51 compliance + 5
    baseline).
- **Go canary kinds extended** to 4:
  - `file` (fsnotify)
  - `tcp_socket` (net.Listen)
  - `http_endpoint` (net/http server with 200 honeypot)
  - `credential` (inotify-style watcher on `/etc/shadow`,
    `/etc/passwd`).
- **Evidence locker key rotation**:
  - `EvidenceStore.rotate()` generates a new signing key
    and keeps the old one in history (`current` / `previous`
    slots).
  - Old evidence still verifies after rotation.
  - Sidecar JSON records the key id that signed each
    bundle.
  - Wiping a key causes evidence signed with it to fail
    verification — chain-of-custody is preserved.

### Tests added

- `test_compliance_packs.py` (8 tests):
  - Floor counts per pack.
  - Unique ids across the whole tree.
  - Every rule has `tags`.
  - Every rule has `references`.
- `test_evidence_rotation.py` (4 tests):
  - Rotate changes active key.
  - Evidence verifies across rotation.
  - Sidecar records key id.
  - Wiped key → verification fails.

### Metrics

- Server test count: **164** (was 152 at v0.7.0).
- Go test packages: **10** (still all green).

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
