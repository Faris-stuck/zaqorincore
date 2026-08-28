# Roadmap

> The full public plan. Updated as phases ship. If a phase slips, we update this file in the same commit as the slip — no silent drift.

## Status legend

- ✅ Shipped
- 🟡 In progress
- ⏳ Queued
- ❌ Cancelled / descoped (with reason)

---

## Phase 0 — Spec & scaffolding ✅

**Goal:** establish the project, file the legal/governance paperwork, and write down the architecture so future contributors can ramp up.

**Deliverables:**

- [x] Pick a name and a repo location
- [x] Create the public repo
- [x] Pick a license (MIT)
- [x] Write the README
- [x] Write the architecture document
- [x] Write the security disclosure policy
- [x] Write the code of conduct
- [x] Write the contributing guide
- [x] Write the issue / PR templates
- [x] First GitHub Release tagged `v0.0.0` (this scaffolding)

**Done when:** the repo passes a "first impression" review — a random developer can land on the README, understand what the project does, and decide whether to use it in under 90 seconds.

---

## Phase 1 — Agent MVP ✅

**Goal:** a Go single-binary agent that tails a log file and pushes structured events to a server over WebSocket. No detection, no response — just transport.

**Status:** shipped as v0.1.0. The agent builds into a ~5 MB static binary, has end-to-end smoke coverage (HELLO + N EVENT frames), and ships with a hardened systemd unit. See [`docs/PHASE1.md`](docs/PHASE1.md) for the operator walkthrough.

**Deliverables:**

- [x] `agent/` directory with a Go module
- [x] `internal/event` — wire schema (UUID, RFC3339Nano UTC, snake_case)
- [x] `internal/tailer` — rotation-safe file tailing (ReOpen, SEEK_END, missing-file retry)
- [x] `internal/transport` — WebSocket client with reconnect (1s/2s/4s/…/30s) and heartbeat
- [x] `internal/config` — TOML loader with strict validation
- [x] `internal/logger` — slog wrapper, JSON/text format
- [x] `internal/app` + `cmd/zaqorin-agent` — wiring + signal handling
- [x] Systemd unit file (`packaging/zaqorin-agent.service`, hardened)
- [x] Config file format (TOML, see `agent.example.toml`)
- [x] `make build` producing a static binary for `linux/amd64` and `linux/arm64`
- [x] `make smoke` end-to-end: HELLO + 3 EVENT frames against a `websocat` echo server
- [x] CI: `go test -race`, `go vet`, build, smoke on push/PR (`.github/workflows/ci.yml`)
- [x] `docs/PHASE1.md` operator walkthrough
- [x] GitHub Release tagged `v0.1.0`

**Done when:** an operator can install the agent on a Linux host, point it at any WebSocket echo server, and see their `auth.log` lines arrive in real time.

---

## Phase 3 — Detector pipeline ✅

**Goal:** consume events from Redis Streams, run detector
plugins, persist alerts.

**Status:** shipped as v0.3.0. One detector
(`ssh_bruteforce`) ships in this phase; the framework is
plugin-friendly so adding the next one (web_attack,
network_scan, c2_beaconing) is a single new file.

**Architecture:**

- `server/detectors/base.py` — `Detector` protocol,
  `DetectorContext`, `DetectionResult`, `ParsedEvent`.
- `server/detectors/ssh_bruteforce.py` — sliding-window
  rule over failed SSH-login events. State in Redis
  sorted sets, fail-open on errors. Cooldown via
  `SET NX EX` on a separate key.
- `server/detectors/runner.py` — owns the XREADGROUP
  loop, runs in the FastAPI lifespan as a background
  task. Acks on success OR on error (otherwise a single
  bad message blocks the stream).
- `server/detectors/alert_service.py` — `write_alert`
  inserts one `Alert` row per `DetectionResult`.
- `GET /api/v1/alerts` — paginated, filterable by
  `host_id`, `detector`, `since`, `until`.

**Tunables (env vars):**
- `ZAQORIN_DETECTORS_ENABLED` (default `True`)
- `ZAQORIN_SSH_BRUTEFORCE_THRESHOLD` (default 5)
- `ZAQORIN_SSH_BRUTEFORCE_WINDOW_SEC` (default 60)
- `ZAQORIN_SSH_BRUTEFORCE_COOLDOWN_SEC` (default 300)

**Verified:** 28/28 pytest pass, E2E via
`scripts/smoke_detector.py` — 5 WS events with
`status=failed, source_ip=203.0.113.42` → exactly 1
`ssh_bruteforce` alert in DB, retrievable via
`/api/v1/alerts`.

## Phase 4 — Auto-response ✅

**Goal:** when a detector fires, queue a signed `COMMAND`
frame to the affected host. The agent applies
`iptables -I INPUT -s <ip> -j DROP` (or `nftables`) with
a TTL.

**Planned approach:**

- Add a `actions` queue inside the detector runner
  (after `write_alert` succeeds, the runner creates a
  pending `Action` row).
- A new background task (the **dispatcher**) reads
  pending actions, looks up the host's per-agent shared
  secret, signs the command frame (HMAC-SHA256 over the
  canonical JSON), and writes the command onto a
  per-host WebSocket (`ws://agent/cmd/<agent_id>`) or
  pushes it onto a per-host Redis list that the agent
  long-polls.
- The agent acks the command; the dispatcher marks the
  action as `applied` or `failed`.

**Risk:** we want the auto-block to be **opt-in per
host**. Default for a freshly registered host is
`auto_block: false`.

**Defer to:** Phase 5 if scope is too large. The
detector + alert loop is already useful without
auto-response.

**Goal:** a FastAPI server that accepts events from agents, persists them, and serves a minimal dashboard.

**Status:** shipped as v0.2.0. The server runs as a single uvicorn process, persists events to PostgreSQL 16, and publishes them to Redis Streams (`zaqorin:events`, consumer group `zaqorin-detectors` reserved for Phase 3). 17 unit + integration tests pass. End-to-end smoke (real `zaqorin-agent` v0.1.0 binary → server → DB) verified. See [`docs/PHASE2.md`](docs/PHASE2.md) for the operator walkthrough.

**Deliverables:**

- [x] `server/` directory with a Python project (PEP 621 `pyproject.toml`, src layout, src/zaqorincore_server/)
- [x] `WS /ws/agent` endpoint accepting the v0.1.0 wire contract (HELLO / EVENT / BYE)
- [x] PostgreSQL schema + migrations (alembic, 4 tables: hosts / events / alerts / actions)
- [x] Redis Streams publisher (XADD on every persisted event, consumer group pre-created)
- [x] `GET /healthz` (liveness) and `GET /readyz` (readiness: DB + Redis)
- [x] `GET /api/v1/hosts`, `GET /api/v1/hosts/{agent_id}`, `GET /api/v1/events` (filters: since, until, host_id, source), `GET /api/v1/alerts` (returns [] until Phase 3)
- [x] `docker-compose.yml` for full Phase 2.5+ production stack (postgres + redis + server)
- [x] `Dockerfile` (multi-stage, ~150 MB, non-root, HEALTHCHECK on /healthz)
- [x] `scripts/smoke.py` end-to-end WebSocket client
- [x] 17 tests, all green in ~4.5s
- [x] `docs/PHASE2.md` operator walkthrough
- [x] GitHub Release tagged `v0.2.0`

**Done when:** an agent from Phase 1 can be pointed at the Phase 2 server, and events arrive in the database in real time. ✅ achieved.

**Notes for Phase 2.5+:** the dashboard (`dashboard/`) is intentionally deferred — it will land alongside the first detector so it can show alerts in addition to events.

---

## Phase 3 — Detector: SSH brute-force ⏳

**Goal:** the first end-to-end detection. A detector plugin that catches a burst of failed SSH logins and raises an alert.

**Deliverables:**

- [ ] `server/detectors/ssh_bruteforce.py` plugin
- [ ] Sliding-window state in Redis (per source IP)
- [ ] Configurable threshold and window length
- [ ] Alert row in the dashboard
- [ ] Unit tests for the detector with a fixture `auth.log`

**Done when:** replaying a synthetic brute-force against a test host produces an alert in the dashboard within 1 second of the threshold being crossed.

---

## Phase 4 — Auto-response: block IP ✅

**Goal:** close the loop. When a detector fires, the server sends a signed `block_ip` command to the agent, and the agent drops the offender's traffic.

**Deliverables:**

- [ ] HMAC-signed command protocol (per-agent shared secret)
- [ ] `iptables` (and `nftables`) wrapper on the agent
- [ ] TTL handling: blocks auto-expire
- [ ] `dry_run` mode default-on for new agents
- [ ] Per-detector / per-action allowlist (operator can disable auto-response per detector)
- [ ] Action history in the dashboard

**Done when:** the SSH brute-force detector from Phase 3, when dry-run is off, causes the agent to block the offending IP within 2 seconds of the threshold being crossed. The block expires after the configured TTL.

---

## Phase 5 — More detectors ⏳

**Goal:** show the plugin architecture pays off by adding detectors without touching the core.

**Deliverables:**

- [ ] `web_attack` — SQLi / XSS / path-traversal / scanner signatures
- [ ] `network_scan` — port scan detection
- [ ] `c2_beaconing` — periodic outbound connection analysis (will need Zeek or netflow input — research spike first)
- [ ] Documentation: how to write a detector

**Done when:** three new detectors land without any changes to the core, and the dashboard shows alerts for all of them on a synthetic workload.

---

## Phase 6 — Auth, multi-user, RBAC ⏳

**Goal:** make the dashboard usable by a small team, not just a single operator.

**Deliverables:**

- [ ] Email + password login with argon2id
- [ ] Optional TOTP 2FA
- [ ] Roles: `admin`, `operator`, `viewer`
- [ ] Per-host ACLs (a user only sees the hosts they are assigned to)
- [ ] Audit log of operator actions

**Done when:** two users with different roles can be created, and a viewer cannot ack an alert or change a detector config.

---

## Phase 7 — Packaging ⏳

**Goal:** make the install path obvious for a fresh homelab user.

**Deliverables:**

- [ ] One-file `install.sh` for the server
- [ ] `apt` and `yum` repo (or `deb`/`rpm` packages if the operator network demands them — evaluate in this phase)
- [ ] Helm chart for Kubernetes-based installs
- [ ] Reference architecture docs: 1 host, 5 hosts, 50 hosts

**Done when:** a user with a single Linux box can have the server running in under 5 minutes following only the README.

---

## Phase 8 — Public launch ⏳

**Goal:** announce the project to the world.

**Deliverables:**

- [ ] Dedicated docs site (probably a sibling repo + GitHub Pages)
- [ ] Demo video (under 5 minutes) showing the full loop: trigger → detect → block
- [ ] Post on the relevant communities (HN, r/selfhosted, r/sysadmin, Lobsters, applicable Discords)
- [ ] First "stable" release tag (`v1.0.0`)

**Done when:** the GitHub repo shows organic stars / forks / issues from people who are not the maintainer.

---

## Non-goals (for now)

- Cloud-managed SaaS tier
- macOS / Windows agents
- Sharing ban lists between ZaqorinCore instances
- Commercial support contracts
- Auto-tuning detector thresholds with ML
- Mobile app

If you need one of these, open an issue and we will talk — but they are not in the plan.

## Feedback

Open an issue, or use the discussion board. Roadmap is a living document and we will update it as reality diverges from the plan.
