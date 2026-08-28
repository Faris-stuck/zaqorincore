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

**Status:** shipped as v0.1.0. The agent builds into a ~5 MB static binary, has end-to-end smoke coverage (HELLO + N EVENT frames), and ships with a hardened systemd unit. See [`docs/PHASE1.md`](PHASE1.md) for the operator walkthrough.

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

**Status:** shipped as v0.2.0. The server runs as a single uvicorn process, persists events to PostgreSQL 16, and publishes them to Redis Streams (`zaqorin:events`, consumer group `zaqorin-detectors` reserved for Phase 3). 17 unit + integration tests pass. End-to-end smoke (real `zaqorin-agent` v0.1.0 binary → server → DB) verified. See [`docs/PHASE2.md`](PHASE2.md) for the operator walkthrough.

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

## Phase 5 — Universal platform scope (multi-scale + 9 actions + detector library) ✅

**Goal:** turn ZaqorinCore from a single-host IDS into a **universal
cyber security platform** that scales from a Raspberry Pi 4 homelab
install to a multi-tenant MSSP deployment. Same code, runtime mode
flag selects the deployment scale.

**Status:** shipped as v0.5.0. ADRs in `docs/decisions/` capture the
scope, the tiered config, the action kinds, the rule engine, and the
deception strategy. One binary, three modes (`individual` /
`startup` / `enterprise`), nine action kinds, five detectors
(ssh_bruteforce + 4 new: port_scan, web_attack, dns_tunnel,
auth_anomaly), 145/145 tests pass.

**Deliverables:**

- [x] **Multi-scale deployment** (`server/deployment.py`): one
  binary, three modes via `ZAQORIN_DEPLOYMENT_MODE`. Each mode
  declares the default DB / Redis / pool / detector set so an
  operator on a 1 GB Pi gets sensible defaults without reading a
  thousand-line config.
- [x] **Nine action kinds** (`server/action_kinds.py`,
  `agent/internal/response/kinds/`). The dispatcher validates
  every action against the per-kind policy; the agent executors
  apply them.
- [x] **Four new detectors** in addition to `ssh_bruteforce`:
  `port_scan`, `web_attack`, `dns_tunnel`, `auth_anomaly`.
- [x] **Five ADRs** in `docs/decisions/`.
- [x] **Tests**: 118/118 server, 27/27 Go agent. E2E smoke
  unchanged (SSH brute force still closes the loop in <2s).

**Architecture:**

- `server/deployment.py` — `INDIVIDUAL` / `STARTUP` / `ENTERPRISE`
  presets, `apply_mode_to_settings(settings, mode)` mutates the
  settings in place.
- `server/action_kinds.py` — frozen registry of 9 kinds, each with
  target shape, default TTL, opt-in flag, allow-by-default policy.
- `server/dispatcher.py` — added per-kind validation before
  signing a command. Unknown kinds are rejected.
- `agent/internal/response/kinds/kinds.go` — uniform
  `(ctx, target, ttl, dryRun, log)` signature for all 9
  executors. Format gates (CIDR, PID>1, scheme check).

**Done when:** an operator on a Raspberry Pi 4 with no DB can run
`zaqorin-server --mode individual` and the server starts, applies
defaults, and the same binary works on a 100-host enterprise
deployment with `ZAQORIN_DEPLOYMENT_MODE=enterprise`. **Yes.**

---

## Phase 6 — Sigma-compatible rule engine + hunt query ⏳

**Goal:** stop hand-coding each detector. Operators write Sigma-style
YAML rules; the engine parses them and runs them against the event
stream. The built-in detectors become a starter pack of rules.

**Planned approach:**

- Parse Sigma rules in YAML — the same syntax used by SigmaHQ
  (MIT) and converted to Splunk/Elastic by `sigmac`. We don't
  depend on SigmaHQ; we just adopt the wire format.
- `server/rule_engine/` — `parse_rule(yaml) -> CompiledRule`,
  `CompiledRule.matches(event) -> bool`, `RuleRegistry` that the
  runner consults in addition to the Python detector plugins.
- Phase-5 detectors (`port_scan`, `web_attack`, etc.) become
  Sigma rules loaded from `rules/builtin/*.yml` at startup, with
  the Python helpers (`port_knock`, `is_http_event`, etc.)
  exposed as Sigma `match` functions if a rule needs them.
- **Hunt query**: an operator can save a Sigma rule as a "hunt"
  and the engine runs it on demand against historical events
  stored in the DB.
- **Backwards compatible**: existing detector plugins keep
  working. New rules are an additive path.

**Done when:** an operator drops a Sigma rule YAML into
`rules/custom/`, restarts the server, and sees alerts from it
without writing any Python.

---

## Phase 7 — Deception + forensics ⏳

**Goal:** close the proactive gap. ZaqorinCore plants canary
tokens, tarpits scanners, captures evidence, and builds a
chain-of-custody record for every alert.

**Planned approach:**

- **Canary tokens** (`canary_alert` action kind + a daemon that
  watches `~/.ssh/authorized_keys`, `/var/log/auth.log`, etc.).
  Any touch fires an alert with zero false positive risk.
- **Tarpit** (`tarpit_ip` action kind already exists; the agent
  executes it via `nft` rate-limit + Go net throttle).
- **Breadcrumbs**: `agent/` watches for access to known
  canary paths (`/etc/canary.passwd`, `~/.aws/canary`) and
  emits events the detector engine picks up.
- **Evidence locker** (`evidence_capture` action kind). On
  alert, agent snapshots the relevant files, tar+hashes them,
  and POSTs to the server. Server stores in
  `evidence/{alert_id}.tar.gz` with a `chain_of_custody.json`
  sidecar (sha256 of original → sha256 of tar → operator name
  → timestamp).

**Done when:** planting a canary token in `/tmp/canary.docx` and
opening it fires a `canary_alert` within 5 seconds with the
operator's username and timestamp.

---

## Phase 8 — Compliance pack (UU PDP, ISO 27001, PCI DSS) ⏳

**Goal:** out-of-the-box rules that map common controls
to specific event patterns. Operators in regulated industries
get a one-step install.

**Planned approach:**

- `rules/compliance/uupdp.yml` — Indonesia's UU PDP
  (Personal Data Protection). 13+ rules covering "data access
  by unauthorized user," "export of personal data outside
  perimeter," etc.
- `rules/compliance/iso27001.yml` — A.8 asset management,
  A.9 access control, A.12 operations security, A.16 incident
  management.
- `rules/compliance/pci_dss.yml` — Requirement 10 (logging),
  Requirement 11 (testing), Requirement 12 (security policy).
- A `GET /api/v1/compliance/{framework}/status` endpoint that
  reports per-control coverage: which rules fired, which
  didn't, which need tuning.

**Done when:** an Indonesian fintech operator runs
`zaqorin-server --compliance uupdp` and the server reports
"13/13 controls covered, 2 controls need attention."

---

## Phase 9 — Web UI (React) ⏳

**Goal:** a real operator UI — alerts, hunt, evidence, settings,
compliance dashboard. Replaces the placeholder `GET /api/v1/alerts`
JSON-only view.

**Planned approach:**

- React + TypeScript + Vite, no Redux (React Query for data).
- Pages: `Alerts` (paginated, filter by detector / host /
  severity / time), `Hosts` (list, per-host detail with
  per-host `auto_block` toggle), `Hunt` (write Sigma rules,
  run on demand, see results), `Evidence` (per-alert file
  viewer), `Compliance` (per-framework coverage),
  `Settings` (deployment mode, key rotation, SOAR webhook).
- Built and bundled into the same release artifact. No
  separate deploy step.
- Auth: API key header (same as `zaqorin`) — no login screen
  for v0. Operators put it behind their reverse proxy with
  basic auth or Cloudflare Access.

**Done when:** an operator opens the UI in a browser, sees
the last 24h of alerts, drills into one, sees the evidence
locker files, and toggles `auto_block` on a host.

---

## Phase 10 — Production launch ✅

**Goal:** announce the project to the world. The platform is
production-ready for individual, startup, and enterprise use.

**Status:** shipped as v1.0.0 (commit `e5b245e`, tag `v1.0.0`
+ GitHub Release live). Mkdocs docs site at
`https://faris-stuck.github.io/zaqorincore/`, 5-minute demo,
HN submission text, DB-free launch smoke + live-stack smoke.

**Done when:** GitHub repo shows organic stars / forks /
issues from people who are not the maintainer.

---

## Post-1.0.0 roadmap

### v1.1.0 — eBPF kernel telemetry ⏳

**Goal:** kernel-vouched signal for the things text logs
can't capture. Closes the largest detection gap (userspace
log tampering, missing process/file/connect events, short-
lived processes).

**ADR:** [ADR-006](decisions/ADR-006-ebpf-kernel-telemetry.md)

**Probes (one per slice):**

- [ ] `execve_monitor` — process exec (web shell, LOLBin,
      attacker tool)
- [ ] `openat_monitor` — file open (SSH key, /etc/shadow,
      /proc/*/mem)
- [ ] `connect_monitor` — outbound TCP/UDP connect (C2
      beaconing, lateral movement, exfil)
- [ ] `ptrace_monitor` — process injection / debugger attach
- [ ] `setuid_monitor` — SUID privilege escalation

**Cross-cutting:**

- [ ] Fallback to file-tail on kernel < 5.4 or no `CAP_BPF`
- [ ] Per-probe enable/disable in `agent.toml`
- [ ] Sigma rules for all 5 probes
- [ ] Operator guide update

### v1.2.0 — Multi-platform agents ⏳

**Goal:** Windows and macOS hosts participate in the same
fleet-wide detection and response.

**ADR:** [ADR-007](decisions/ADR-007-multi-platform-agents.md)

**Build matrix (5 targets, all compile in v1.0.0):**

- [ ] Linux amd64 (v1.0.0 baseline)
- [ ] Linux arm64 (v1.0.0 baseline)
- [ ] Windows amd64 (Event Log + ETW opt-in)
- [ ] Windows arm64 (same)
- [ ] macOS amd64 (Endpoint Security Framework)
- [ ] macOS arm64 (Apple Silicon; same)

**Per-platform slices:**

- [ ] Windows Event Log telemetry (4624/4625/4688/4698)
- [ ] Windows action applier (4 kinds via netsh/taskkill)
- [ ] macOS ESF telemetry (exec/open/connect/kextload)
- [ ] macOS action applier (4 kinds via pf/kill)
- [ ] MSI / DMG / WinSW / launchd packaging
- [ ] 10-20 new platform-specific Sigma rules

### v1.3.0 — SOAR webhook delivery ⏳

**Goal:** alerts reach humans where they already are, in
under a minute.

**ADR:** [ADR-008](decisions/ADR-008-soar-webhook-delivery.md)

**Backends (one per slice):**

- [ ] Generic Webhook (JSON template)
- [ ] Slack (Block Kit)
- [ ] Discord (embed)
- [ ] PagerDuty (Events API v2 + dedup_key)
- [ ] TheHive (alert create API)
- [ ] Jira (issue create API)

**Cross-cutting:**

- [ ] Per-backend `cooldown_sec` + `severity_min` + `tags_filter`
- [ ] Dead-letter persistence + replay endpoint
- [ ] `soar_deliveries` audit table + web console tab
- [ ] 4xx is not retried; 5xx is retried with exponential
      backoff (1s/5s/25s/125s/625s)

---

## Non-goals (for now)

- Cloud-managed SaaS tier
- Sharing ban lists between ZaqorinCore instances
- Commercial support contracts
- Auto-tuning detector thresholds with ML
- Mobile app

If you need one of these, open an issue and we will talk — but they are not in the plan.

## v1.1 — Kernel telemetry (eBPF) ⏳

**Goal:** extend the Go agent with eBPF probes that capture
syscall interrupts and process activity directly from the Linux
kernel — no longer rely solely on text log files.

**Why:** text logs can be **tampered with, truncated, or
forged** by a sophisticated attacker (log tampering is
ATT&CK T1070.002). Kernel-level telemetry is the only signal
the kernel itself vouches for: every `execve`, `open`, `connect`,
`ptrace`, `setuid` goes through it. eBPF lets us read these
without a kernel module (no recompile, no reboot, no GPL
exposure of the agent).

**Planned approach:**

- New Go package `agent/internal/ebpf/` using
  [`cilium/ebpf`](https://github.com/cilium/ebpf) for the
  Go-side loader + maps.
- C source in `agent/internal/ebpf/probes/` for the actual
  BPF programs:
  - `execve_monitor.c` — hooks `sys_enter_execve`, captures
    `{pid, uid, comm, argv[0..3]}` per process exec.
  - `open_monitor.c` — hooks `sys_enter_openat`, captures
    `{pid, uid, filename}` for sensitive paths
    (`/etc/passwd`, `/etc/shadow`, `~/.ssh/`, `~/.aws/`,
    `/proc/*/mem`).
  - `connect_monitor.c` — hooks `sys_enter_connect`, captures
    `{pid, uid, dst_ip, dst_port}` for outbound connections.
  - `ptrace_monitor.c` — hooks `sys_enter_ptrace`, captures
    `{pid, target_pid}` (process injection / debugging).
  - `setuid_monitor.c` — hooks `sys_enter_setuid`, captures
    `{pid, uid, new_uid}` (privilege escalation attempts).
- All events land in a BPF ring buffer → userspace reader in
  the Go agent → reuses the existing `internal/event` wire
  contract → sent via the same WebSocket transport.
- **Backwards compatible:** if the host has no BPF support
  (old kernel, BPF disabled, no CAP_BPF), the agent logs a
  warning and continues with the existing file-tail mode.
  No breakage.
- **No new dependencies** at runtime besides the kernel ≥ 5.4
  and `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels).
- **No AI in the probes.** Every captured event is a fact
  (syscall happened with these args), not an inference.

**Detection payoff:** new Sigma rules that were previously
impossible become trivial:

- "Process exec from a web server child" (web shell) →
  `execve` with `comm=httpd` and `comm=bash` parented in
  the same cgroup.
- "Reads of SSH private keys" → `openat` on `~/.ssh/id_*`.
- "Outbound connection to a non-RFC1918 IP from a server"
  → `connect` to a public IP from a host whose tag is
  `dmz=internal`.
- "Process injection" → `ptrace` on a process in another
  PID namespace.

**Done when:** the agent runs on Linux ≥ 5.4 with the BPF
probes loaded, captures 1,000 exec events without dropping,
ships them to the server, and the server's existing detector
pipeline can match them via the new Sigma rules added in
this phase.

## v1.2 — Multi-platform agents (Windows + macOS) ⏳

**Goal:** add first-class agents for Windows and macOS so a
homogeneous fleet (Linux servers + Windows workstations +
macOS laptops) reports through the same ZaqorinCore server.

**Why:** the v1.0.0 agent is Linux-only. Production fleets
are mixed. A security tool that only sees Linux is blind to
60-80% of typical enterprise endpoints.

**Planned approach:**

- **Windows agent** (Go, using the same module structure):
  - Telemetry source: **Event Log** via `wevtapi` (Go
    bindings via `github.com/0xrawsec/golang-winrt` or
    direct syscalls) for the existing categories:
    Security (4624/4625 logon, 4688 process create, 4698
    scheduled task), System, Application.
  - Optional kernel-level source: **ETW (Event Tracing for
    Windows)** via `github.com/bi-zone/etw` or Microsoft
    `xperf` consumers. ETW is the Windows equivalent of
    eBPF: same kernel-vouched guarantees, same "no
    tampering by userspace" property.
  - Reuses the existing wire contract (HELLO/EVENT/BYE/COMMAND).
  - Action kinds that apply: `kill_process`, `quarantine_file`,
    `isolate_host` (Windows Firewall rule), `revoke_credential`
    (cached Kerberos ticket purge).
  - Skipped on Windows: `block_ip` via nftables (Windows uses
    `netsh advfirewall` instead, implemented as
    `block_ip_win` action kind that maps to a firewall rule).

- **macOS agent** (Go):
  - Telemetry source: **Endpoint Security Framework** (ESF,
    the macOS equivalent of eBPF + ETW). Go bindings via
    [`github.com/groob/esext`](https://github.com/groob/esext)
    or `github.com/elastic/go-esext` style.
  - ESF events: `ES_EVENT_TYPE_AUTH_EXEC`,
    `ES_EVENT_TYPE_AUTH_OPEN`,
    `ES_EVENT_TYPE_AUTH_KEXTLOAD`,
    `ES_EVENT_TYPE_NOTIFY_CONNECT`, etc.
  - Requires **System Extension entitlement** and a
    notarized helper — documented in the operator guide.
  - Action kinds that apply: `kill_process`, `quarantine_file`
    (`.quarantine` xattr), `revoke_credential` (keychain
    entry removal via `security delete-generic-password`).

- **Build matrix:**
  - Linux: amd64 + arm64 (already shipped)
  - Windows: amd64 (`zaqorin-agent.exe` with WinSW
    service wrapper)
  - macOS: amd64 + arm64 (universal binary, notarized for
    distribution outside the App Store)

**Done when:** a Windows host and a macOS host each report
events to the same ZaqorinCore server, generate alerts via
the existing detector pipeline, and respond to COMMAND
frames with platform-appropriate action kinds.

## v1.3 — SOAR automations (webhook delivery) ⏳

**Goal:** push alerts (and optionally actions) to external
collaboration and ticketing systems so an existing SOC
workflow (Slack, Discord, Jira, ServiceNow, PagerDuty,
TheHive) gets notified without anyone having to leave
ZaqorinCore's web console.

**Why:** "the alert is in the system" is only useful if the
**right human sees it fast enough**. Email is too slow,
the web console needs an operator to be looking, and most
SOC teams already have on-call rotations in PagerDuty or
chat-ops in Slack. SOAR = **S**ecurity **O**rchestration
**A**utomation and **R**esponse.

**Planned approach:**

- New `server/src/zaqorincore_server/soar/` package with
  one router + N delivery backends.
- **Delivery contract:** POST JSON to a user-configured
  webhook URL, with a per-backend payload transformer.
  Example for Slack:
  ```json
  {
    "blocks": [
      {"type": "header", "text": {"type": "plain_text",
        "text": "🚨 ssh_bruteforce — 203.0.113.42"}},
      {"type": "section", "fields": [
        {"type": "mrkdwn", "text": "*Host:*\nserver-01"},
        {"type": "mrkdwn", "text": "*Severity:*\nhigh"}
      ]},
      {"type": "actions", "elements": [
        {"type": "button", "text": {"type": "plain_text",
          "text": "View in ZaqorinCore"},
          "url": "https://zaqorin.example.com/#/alerts/..."}
      ]}
    ]
  }
  ```
- **Backends shipped in v1.3:**
  - **Generic webhook** — raw JSON, user-defined template
    (Jinja2-style, server-side rendered, no user JS).
  - **Slack** — Slack Block Kit payload format.
  - **Discord** — Discord webhook embed format.
  - **PagerDuty** — Events API v2 (low/medium/high
    severity mapped from ZaqorinCore alert severity).
  - **TheHive** — alert create via TheHive v5 REST API.
  - **Jira** — issue create via Atlassian REST API v3.
- **Configuration:** TOML at
  `server/config/soar.toml` (gitignored, generated from
  `soar.toml.example`). Each backend has: `enabled`, `url`,
  `auth_header`, `severity_min`, `tags_filter` (only fire
  for alerts matching these tags), `cooldown_sec` (avoid
  storm — same alert ID won't re-fire within this window).
- **Retry + dead-letter:** exponential backoff (1s, 5s, 25s,
  125s, 625s) for 5xx, immediate drop for 4xx (config
  error). After exhaustion, write the payload to
  `server/var/soar/dead-letter/<timestamp>-<alert_id>.json`
  for manual replay.
- **New API endpoints:**
  - `GET  /api/v1/soar/backends` — list configured backends
    with their health (last 24h delivery stats).
  - `POST /api/v1/soar/backends/{name}/test` — fire a
    synthetic alert through the backend to verify config.
  - `GET  /api/v1/soar/dead-letter` — list dead-lettered
    payloads, with `POST /replay` to re-fire one.
- **Audit:** every delivery (success, fail, dead-letter) is
  logged to a new `soar_deliveries` table (alert_id,
  backend, status_code, attempt, timestamp). Web console
  shows a "SOAR" tab under each alert with the delivery
  history.

**Done when:** triggering an `ssh_bruteforce` alert fires a
formatted Slack message to a test channel within 2 seconds,
the message has a working "View in ZaqorinCore" button,
and the delivery is recorded in the audit log.

## Feedback

Open an issue, or use the discussion board. Roadmap is a living document and we will update it as reality diverges from the plan.
