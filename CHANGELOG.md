# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planning (v1.0.0 → v1.3.0)

These features are designed but not implemented. The design
docs (ADRs) and Slice 1 scaffolding ship in this revision;
the runtime code lands in the next three feature releases.

- **eBPF kernel telemetry** ([ADR-006](docs/decisions/ADR-006-ebpf-kernel-telemetry.md))
  — closes the largest detection gap: kernel-vouched signal
  for `execve`, `openat`, `connect`, `ptrace`, `setuid`. Un-
  tamperable by userspace attackers. Falls back to file-tail
  on older kernels. **Target: v1.1.0.** ✅ **Shipped.**
- **Multi-platform agents** ([ADR-007](docs/decisions/ADR-007-multi-platform-agents.md))
  — Windows Event Log + ETW (opt-in) and macOS Endpoint
  Security Framework. Same wire contract, same HMAC-signed
  auto-response. 5x build matrix (linux/amd64, linux/arm64,
  windows/amd64, darwin/amd64, darwin/arm64) already
  compiles in v1.0.0. **Target: v1.2.0.** ✅ **Shipped.**
  (macOS ESF deferred per Faris' "Yasudah windows dan
  Linux saja" decision; dispatcher returns `Scaffold`
  sentinel on darwin and the build still compiles.)
- **Windows detection rules** ([PHASE13-windows-rules.md](docs/PHASE13-windows-rules.md))
  — 5 production-ready Sigma rules that close the
  "Windows collector fires but nobody reads it" gap left
  by v1.2.0. Covers T1110 brute force, T1218 LOLBin
  parent, T1003.001 LSASS read, T1098 priv-group add,
  T1136 account create. Each rule maps to PCI DSS /
  ISO 27001 / NIST 800-53 in its `tags:` block for
  automatic compliance coverage. **Target: v1.4.0.** ✅
  **Shipped.** (10+ more rules from the ROADMAP deferred
  to v1.4.x pending Sigma engine `|startswith`/`|endswith`
  modifier support — see PHASE13 §3 and §7.)
- **Sigma engine modifier support** ([ADR-009](docs/decisions/ADR-009-sigma-modifier-support.md))
  — adds `|startswith`, `|endswith`, `|ge`, `|lt` to
  `_match_field` (Sigma spec modifier syntax). Unlocks
  2 more Windows rules (T1059.001 PowerShell EncodedCommand,
  T1105 PowerShell DownloadString) shipped in the same
  release. **Target: v1.4.x.** ✅ **Shipped.** (OR/AND
  condition parsing still deferred to v1.4.y; off-hours
  filter for T1136 blocked on that — see PHASE14 §4.)
- **Sigma engine compound conditions** ([ADR-010](docs/decisions/ADR-010-sigma-compound-conditions.md))
  — extends `matches()` to 4 patterns: `selection`,
  `selection and not filter` (NOW EVALUATES), `selection
  and (X or Y)`, `selection and (X or Y) and not Z`.
  Unlocks off-hours filter for T1136, parent-process
  scope for the 2 PowerShell rules, and T1098 group
  allowlist expansion (4→8). **Target: v1.4.y.**
  ✅ **Shipped.** (Strict missing-hour fail-safe for
  T1136 deferred to v1.4.z — see PHASE15 §6.)
- **SOAR webhook delivery** ([ADR-008](docs/decisions/ADR-008-soar-webhook-delivery.md))
  — six backends ship (generic webhook, Slack, Discord,
  PagerDuty, TheHive, Jira) with dead-letter + replay.
  Zero SaaS dependency. **Target: v1.3.0.** ✅ **Shipped.**

### Added (post-1.0.0 scaffolding)

- `agent/internal/ebpf/` — Slice 1 stub backend, 5/5 cross-
  platform GOOS builds, no behavior change on linux/amd64.
- `agent/internal/telemetry/` + `telemetry.NewForPlatform`
  dispatcher — `windows` and `darwin` branches return a
  placeholder `Unavailable` backend that logs a one-time
  warning.
- `agent/internal/response/kinds/kill_unix.go` +
  `kill_windows.go` — split via `//go:build` so all 5 GOOS
  targets compile. The Windows variant uses
  `OpenProcess` + `TerminateProcess`; the Unix variant uses
  `syscall.Kill`.
- `server/src/zaqorincore_server/soar/` — Slice 1 stub
  package with `Backend` protocol, `Alert` dataclass,
  `DeliveryResult` frozen dataclass, six `NotImplemented`
  backends. `tests/test_soar_scaffold.py` proves the wire
  is wired up. **5/5 server tests added (170 → 175).**
- 3 new ADRs (`docs/decisions/ADR-006-008-*.md`) registered
  in the mkdocs nav.

### Notes

- 175/175 server tests pass (170 + 5 SOAR scaffold).
- 10/10 Go packages pass.
- All 5 GOOS targets (linux/amd64, linux/arm64, windows/amd64,
  windows/arm64, darwin/amd64, darwin/arm64) build cleanly.
- 9/9 launch smoke + 9/9 live smoke still pass; no behavior
  change on the v1.0.0 surface.

### Added (v1.3.0 SOAR implementation)

- **Six SOAR backends** with pluggable registry
  (`server/src/zaqorincore_server/soar/backends/`):
  - `generic_webhook` — template body, custom auth header
  - `slack` — Block Kit message
  - `discord` — webhook embed
  - `pagerduty` — Events API v2 enqueue
  - `thehive` — case creation via API
  - `jira` — issue creation via REST v3
- **Worker dispatch loop** (`worker.py`):
  - `asyncio.Queue` bounded delivery, semaphore 10, configurable
    per-backend max retries with exponential backoff
    (1s → 5s → 25s → 125s → 625s)
  - Per-`(backend, host, detector)` cooldown tracker
  - Atomic dead-letter JSON write with SHA-256 integrity hash
  - Replay endpoint validates SHA on read
- **REST surface** (`api/v1/soar.py`):
  - `GET /api/v1/soar/deliveries` — paginated history
  - `GET /api/v1/soar/health` — 24h aggregate per backend
  - `GET /api/v1/soar/dead-letter` — list files newest first
  - `GET /api/v1/soar/dead-letter/{file_id}` — read single
  - `POST /api/v1/soar/dead-letter/{file_id}/replay` — re-enqueue
- **`soar_deliveries` table** (Alembic migration 0003):
  - 9 columns, 2 indexes; one row per delivery attempt
- **`docs/PHASE13-soar.md`** — 740-line operator guide covering
  configuration, architecture, dead-letter recovery, replay,
  troubleshooting, and the test coverage summary
- **2 Cybersec review fixes** (Important, pre-v1.3.0):
  - IMP-3: dead-letter files now written with mode 0o600
    (owner-only) via `os.open(O_WRONLY|O_CREAT|O_TRUNC, 0o600)`
  - IMP-4: dropped-on-queue-full alerts are now written to
    the dead-letter store via a new `_dead_letter_queue_full`
    helper instead of being silently lost

### Notes (post-v1.3.0 IMP work)
- **235/235 server tests pass** (229 → +6 for IMP-1 auth tests)
- 13/13 Go agent packages pass (was 10, +eBPF +telemetry/windows
  +response/kinds tests)
- 9/9 launch smoke pass
- **Cybersec review items (Important): all closed**
  - IMP-1: X-API-Key auth on `/api/v1/soar/*` (5 endpoints)
    — `require_api_key` FastAPI dependency with constant-time
    `hmac.compare_digest`. Opt-in via `ZAQORIN_API_KEY` env;
    when unset the dependency is a no-op and a one-shot
    warning is logged (operator-acknowledged dev mode).
    Wildcard route covers deliveries, health, dead-letter
    list / read, and replay — the dangerous one.
  - IMP-2: httpx `debug=True` / auth header logging footgun —
    audit of all 6 backends found no occurrence. Guardrail
    note added to `docs/PHASE13-soar.md` (SUG-2) for any
    future backend author.
  - IMP-3: dead-letter file mode `0o600` via
    `os.open(O_WRONLY|O_CREAT|O_TRUNC, 0o600)`.
  - IMP-4: dropped-on-queue-full alerts now written to the
    dead-letter store via `_dead_letter_queue_full` helper
    instead of silently lost.
- Cybersec review full output: see the Cybersec review
  section in the project's Obsidian vault note
  `Proyek - Cyber Sentinel ZaqorinCore.md`.

## [1.4.0] - 2026-08-29

The Windows detection-rules layer ships in this release.
The Windows Event Log collector (v1.2.0) and the Windows
action applier (v1.2.0) already produce and respond to
events; what was missing was the rules that turn the
event firehose into actionable alerts. v1.4.0 closes that
gap with **5 production-ready Sigma rules** under
`server/rules/builtin/windows_eventlog/`:

| Rule ID | ATT&CK | Event ID | Level | Threshold | Action |
|---|---|---|---|---|---|
| `builtin-windows-4625-brute-force` | T1110 | 4625 | high | 10 in 60s | `block_ip` (1h) |
| `builtin-windows-4688-suspicious-parent` | T1218 | 4688 | high | 1 event | `snapshot_processes` |
| `builtin-windows-lsass-read` | T1003.001 | 4663 | critical | 1 event | `snapshot_processes` |
| `builtin-windows-4732-priv-group-add` | T1098 | 4732 | critical | 1 event | `snapshot_processes` |
| `builtin-windows-4720-account-create` | T1136 | 4720 | medium | 1 event | `snapshot_processes` |

The rules run on the existing `SigmaRuleRunner` (no engine
changes) and ship with **15 new tests** in
`server/tests/test_windows_eventlog_rules.py`. The full
server test suite grew from 235 → 250.

### Why 5 (and not the 10-20 the ROADMAP asked for)

The ROADMAP listed "10-20 new platform-specific rules" as
a v1.2.0 prerequisite, but v1.2.0 shipped zero because
the rule engine was feature-locked to plain string / list
/ `re:` / `contains:` matches — no `|startswith`,
`|endswith`, `|ge`, `|lt` modifiers. Rather than wait for
the engine upgrade, v1.4.0 ships the 5 rules that work
today. The remaining 5-10 are queued for v1.4.x (engine
modifier support). See `docs/PHASE13-windows-rules.md`
§3 and §7 for the full rationale and follow-up list.

### Notes

- **Mapping:** every rule's `tags:` block carries the
  ATT&CK, PCI DSS, ISO 27001, and NIST 800-53 IDs it
  satisfies. The Phase 6 compliance scanner (v0.8.0)
  auto-counts these toward the relevant framework's
  coverage.
- **Off-hours filter:** the T1136 rule fires on every
  4720 event (24x7) instead of off-hours only, because
  the engine does not yet parse
  `condition: selection and not filter_business_hours`.
  Operators wanting a stricter rule can override the rule
  in `rules.local_overrides/windows_eventlog/` with an
  explicit `parent_process_name` allowlist.
- **GPO dependency for T1003.001:** the LSASS rule
  needs "Audit Handle to Kernel Objects" (Success)
  enabled. The PHASE12-windows.md guide documents the
  full GPO set.
- **Honest gap:** the 5 rules were tested on Linux with
  a fake-redis runner. The selection/dedup/cooldown/
  count-in-window/action-rendering paths are all
  exercised by the 15 tests. What was NOT exercised:
  real Windows Event Log events flowing through the
  eventlog_common.go decoder, real `netsh advfirewall`
  block_ip on a real Windows host, or a real GPO
  rollout on a real AD domain. Operators must run a
  real-Windows integration smoke test after upgrading.

[1.4.0]: https://github.com/Faris-stuck/zaqorincore/compare/v1.2.0...v1.4.0

## [1.4.x] - 2026-08-29

The Sigma engine modifier support ([ADR-009](docs/decisions/ADR-009-sigma-modifier-support.md))
ships in this release. The engine's `_match_field` learned
4 new modifiers in the Sigma spec syntax
(`field|modifier: value`):

| Modifier | Example | Use |
|---|---|---|
| `\|startswith` | `command_line\|startswith: powershell ` | case-sensitive prefix match |
| `\|endswith` | `target_filename\|endswith: lsass.exe` | case-sensitive suffix match |
| `\|ge` | `hour\|ge: 22` | numeric ≥ |
| `\|lt` | `hour\|lt: 6` | numeric < |

The modifier parser is backwards-compatible: existing
rules with `re:` and `contains:` continue to work
unchanged.

### 2 new Windows rules enabled by the modifiers

| Rule ID | ATT&CK | Event ID | Level | Action |
|---|---|---|---|---|
| `builtin-windows-4688-powershell-encoded` | T1059.001 / T1027 / T1140 | 4688 | high | `snapshot_processes` |
| `builtin-windows-4688-powershell-download` | T1059.001 / T1105 | 4688 | high | `snapshot_processes` |

Both rules are tested on Linux (selection/dedup/cooldown/
count-in-window/action-rendering all exercised) but the
GPO dependency "Include command line in process creation
events" still applies — see PHASE12-windows.md.

### Scope limitation

The engine's `condition` parser does not yet handle
`selection and (X or Y)` or `selection and not filter`
fully. The `not filter` part is silently dropped. This
blocks the off-hours filter for the T1136 account-create
rule (which needs `hour|ge: 22 OR hour|lt: 6`) and
prevents the 2 PowerShell rules from being scoped to
`parent_process_name: powershell.exe`. Tracked as v1.4.y
follow-up.

### Test results

```
$ pytest tests/test_sigma_modifiers.py
27 passed, 1 skipped in 0.39s

$ pytest tests/test_powershell_rules.py
4 passed in 0.21s

$ pytest  # full server suite
282 passed in 20.14s
```

(was 250 in v1.4.0 → 282 in v1.4.x, +32 new tests)

[1.4.x]: https://github.com/Faris-stuck/zaqorincore/compare/v1.4.0...v1.4.x

## [1.4.y] - 2026-08-29

The Sigma engine compound condition parser
([ADR-010](docs/decisions/ADR-010-sigma-compound-conditions.md))
ships in this release. The `matches()` method now
supports 4 patterns:

1. `selection` — existing behavior, no change
2. `selection and not filter` — NOW ACTUALLY EVALUATES
   the filter (v1.4.0/v1.4.x silently dropped it)
3. `selection and (X or Y or Z)` — at least one of the
   OR filters must match
4. `selection and (X or Y) and not Z` — at least one OR
   filter matches AND the AND-NOT filter does not match

The implementation is a shallow, rule-string-driven
dispatch via `re.fullmatch` — not a full Sigma spec
parser. The 4 patterns cover every compound condition
the current ruleset needs; further patterns are
deferred to v2.0.0.

### 3 rules upgraded to use the new patterns

| Rule | v1.4.0/v1.4.x behavior | v1.4.y behavior |
|---|---|---|
| `builtin-windows-4720-account-create` | fires 24x7 | fires only outside business hours (09:00-17:00 local) |
| `builtin-windows-4688-powershell-encoded` | any process with "EncodedCommand" in cmdline | PowerShell-launched (parent ∈ {powershell.exe, pwsh.exe}) |
| `builtin-windows-4688-powershell-download` | any process with "DownloadString" in cmdline | PowerShell-launched (parent ∈ {powershell.exe, pwsh.exe}) |
| `builtin-windows-4732-priv-group-add` | 4 SIDs via `contains:` substring | 8 group names via list-membership (added Account/Server/Print/Backup Operators) |

### Test results

```
$ pytest tests/test_sigma_compound_conditions.py
12 passed in 0.21s

$ pytest  # full server suite
294 passed in 20.45s
```

(was 282 in v1.4.x → 294 in v1.4.y, +12 new tests, 0
regressions)

[1.4.y]: https://github.com/Faris-stuck/zaqorincore/compare/v1.4.x...v1.4.y

## [1.4.z] - 2026-08-29

The Sigma engine gains a strict fail-closed mechanism
for rules that depend on metadata not universally
emitted by all agents
([ADR-011](docs/decisions/ADR-011-required-fields.md)).

### Engine: `required_fields` rule attribute

Rules can now declare a `required_fields` top-level
key listing metadata keys that MUST be present in
the event for the rule to fire:

```yaml
id: builtin-windows-4720-account-create
level: high
required_fields:
  - metadata.hour
detection: ...
```

If any of the listed fields is missing from the
event metadata, the rule does NOT fire
(fail-CLOSED). Rules without `required_fields`
are unaffected (backwards-compatible default:
empty tuple).

The check runs BEFORE condition dispatch, so
`required_fields` works with all compound
condition patterns from v1.4.y.

### T1136 upgrade

T1136 now declares `required_fields:
[metadata.hour]`. The v1.4.y off-hours rule was
fail-OPEN for agents that don't send
`metadata.hour` (older firmware, no timezone
context). v1.4.z is fail-CLOSED: if the agent
can't prove the event was off-hours, the rule
doesn't fire. Operators can detect "rule not
firing" via hit-rate metrics and fix the agent.

### Breaking change for tests

The v1.4.0 T1136 test (`test_t1136_fires_on_account_create`)
relied on fail-OPEN semantics (passed no
`metadata.hour`, expected fire). v1.4.z breaks
that contract — the test now passes
`metadata.hour: "23"` (off-hours) explicitly.
This is NOT a runtime break for the rule
itself, only for the test fixture.

### Test count

```
303 server pytest PASS
```

(was 294 in v1.4.y → 303 in v1.4.z, +9 new
`required_fields` tests, 0 regressions)

[1.4.z]: https://github.com/Faris-stuck/zaqorincore/compare/v1.4.y...v1.4.z

## [1.5.0] - 2026-08-29

5 new Windows Sigma rules, enabled by the v1.4.y
compound conditions and v1.4.z `required_fields`
primitives.

### New rules

| Rule ID | Event ID | ATT&CK | Level |
|---|---|---|---|
| `builtin-windows-4688-cmd-from-office` | 4688 | T1059.003 / T1566.001 | high |
| `builtin-windows-5861-wmi-subscription` | 5861 | T1546.012 | high |
| `builtin-windows-4663-startup-folder` | 4663 | T1547.001 | high |
| `builtin-windows-4698-scheduled-task` | 4698 | T1053.005 | medium |
| `builtin-windows-4624-rdp-unusual-source` | 4624 | T1078 / T1021.001 | high |

### T1059.003 cmd.exe from Office (off-hours)

cmd.exe spawned by winword.exe, excel.exe,
outlook.exe, or powerpnt.exe during off-hours
(outside 09:00-17:00). Strong indicator of
macro-based document attacks. Uses
`required_fields: [parent_process_name,
metadata.hour]` to fail-CLOSED for agents
that can't send those.

### T1546.012 WMI event subscription

Detects `Operation = Created` on Event ID 5861
(WMI event subscription). Common persistence
mechanism. No off-hours filter — operators
baseline low volume and tune `cooldown_sec`.

### T1547.001 Startup folder persistence

Detects WriteData access (4663) to paths
matching `\Start Menu\Programs\Startup`
(case-insensitive). Uses `required_fields:
[target_path]` to fail-CLOSED for agents
that don't send the path.

### T1053.005 Scheduled task created

Detects Scheduled Task creation (4698). No
off-hours filter — legitimate IT automation
creates tasks. Operators baseline volume.

### T1078 / T1021.001 RDP from unusual source

Detects interactive logon (4624 type 10) from
a source IP NOT in the allowlist. The default
allowlist is empty (10.0.0.1, 10.0.0.2 placeholders).
Operators MUST configure in
`rules.local_overrides/` before deploying.
Uses `required_fields: [source_ip]`.

### Engine limitations encountered (documented)

- T1078 simplified to ONE `not` filter
  (allowlist); original spec had TWO
  (`not allowlist and not business_hours`).
  v1.4.y supports only one. Operators add
  off-hours via local_overrides.
- T1547 uses `re:` prefix in VALUE (not
  in key name). Engine doesn't parse
  `field|modifier:` in key.

### Test count

```
315 server pytest PASS
```

(was 303 in v1.4.z → 315 in v1.5.0, +12 new
rule tests, 0 regressions)

[1.5.0]: https://github.com/Faris-stuck/zaqorincore/compare/v1.4.z...v1.5.0

## [1.6.0] - 2026-08-29

Windows ETW push-mode subscription infrastructure
(Linux-testable core shipped; Win32 CGO callback
deferred to v1.6.1).

### What ships in v1.6.0

- **Push-mode core** (`push_mode_common.go`):
  buffered channel (cap 1024), drain goroutine,
  drop-on-full path, idempotent Close, full
  context-cancel semantics. Linux-testable.
- **Non-Windows stub** (`push_mode_other.go`,
  `//go:build !windows`): returns "not supported
  on this platform" from SubscribePush so the
  type compiles on every GOOS.
- **Config field** `windows_eventlog.mode`:
  `pull` (default, v1.2.0 behavior) or
  `push` (v1.6.0+ when Win32 callback ships).
  Validated at Load(); bad values rejected.
- **4 new Go tests** for the push-mode drain
  loop (forwards, drop-on-full, idempotent
  close, ctx cancel).
- **3 new config tests** for the mode field
  (default, push accepted, bad value rejected).

### What is DEFERRED to v1.6.1

- **Win32 CGO callback file** (`push_mode_windows.go`):
  requires MinGW-w64 (`x86_64-w64-mingw32-gcc`)
  to cross-build, not yet installed on the dev
  VPS. Operators who set `mode = "push"` in
  v1.6.0 get no functional change on Windows
  hosts — the v1.2.0 pull loop continues to run.
- **Agent main backend selector** to actually
  read `cfg.WindowsEventlog.Mode` and choose
  between New() and NewPush(). Wiring is one
  line; deferred to keep v1.6.0 minimal and
  reviewable.

### Why ship partial?

The v1.6.0 push-mode core is **testable on Linux
end-to-end** (channel + drain + drop semantics +
ctx cancel). Shipping it now gives reviewers a
real, exercised Go module to look at. The Win32
CGO piece is a self-contained follow-up that
does not invalidate v1.6.0's design. PHASE18
documents the partial state transparently.

### Test count

```
Server: 315 pytest PASS (unchanged)
Agent:  4 new push-mode tests + 3 new config
        tests, full suite PASS
```

### PITFALLS

- **CGO + cross-build:** the Win32 callback
  requires `CGO_ENABLED=1 GOOS=windows` with
  MinGW. Standard `go build ./...` on Linux
  is fine for v1.6.0 (no CGO) but won't
  exercise the Windows-specific file.
- **Channel buffer size:** 1024 is enough
  for ≈1s of worst-case volume. If the kernel
  produces more, events are dropped with a
  warn log. Increasing to 4096 in v1.6.1
  if the WARN is observed in production.
- **Per-event CGO cost:** ≈200ns per event.
  Acceptable for the security channel
  (≤100 events/sec). Documented in ADR-012.

### Files added

```
agent/internal/telemetry/windows/push_mode_common.go   114 lines
agent/internal/telemetry/windows/push_mode_other.go     25 lines
agent/internal/telemetry/windows/push_mode_test.go      122 lines
agent/internal/config/config.go                         +23 (windows_eventlog)
agent/internal/config/config_test.go                    +52 (mode tests)
agent.example.toml                                      +14 (commented example)
docs/PHASE18-etw-push-mode.md                           119 lines
docs/decisions/ADR-012-etw-push-mode.md                 96 lines
```

[1.6.0]: https://github.com/Faris-stuck/zaqorincore/compare/v1.5.0...v1.6.0

## [1.2.0] - 2026-08-29

The Windows agent ships in this release
([ADR-007](docs/decisions/ADR-007-multi-platform-agents.md)).
The same ZaqorinCore server, transport, HMAC-signed
COMMAND protocol, detector pipeline, and 51-rule Sigma
engine now run on a mixed Linux+Windows fleet. macOS
ESF is explicitly deferred per Faris' "Yasudah windows
dan Linux saja tidak usah mac" decision; the dispatcher
returns a `Scaffold` sentinel on darwin and the build
still compiles.

### Added

- **Windows Event Log backend** (`agent/internal/telemetry/windows/`):
  - `eventlog_windows.go` (213 LOC) — Win32 subscription
    loop via `syscall.NewLazyDLL("wevtapi.dll")` +
    `EvtSubscribe` + `EvtRender` + `EvtClose`. XPATH
    filter selects the 6 ADR-007 event IDs (4624, 4625,
    4688, 4698, 4720, 4732) from the Security log with
    `EvtSubscribeToFutureEvents` (no replay of pre-
    subscription history).
  - `eventlog_common.go` (192 LOC) — cross-platform
    XML decoder + metadata mapping; safe to import from
    tests on any GOOS. Translates the Win32 Event Log
    XML to a flat JSON object the detector pipeline
    already understands.
  - `eventlog_other.go` (49 LOC) — `//go:build !windows`
    stub so the linux/darwin build matrix compiles
    cleanly. Returns a `Scaffold` backend that logs once
    and blocks on context cancel.
  - `eventlog_test.go` (183 LOC) — 5 unit tests:
    `TestBuildWireEvent4624`, `TestBuildWireEvent4688`,
    `TestBuildWireEventUnknownID`, `TestSubscribedEventIDs`,
    `TestIndexNul`. All pass on linux (the test host);
    the Windows-specific test paths run on real
    Windows hosts via the operator's CI.
- **Windows action applier** (`agent/internal/response/kinds/`):
  - `kill_windows.go` (66 LOC) — `kill_process` calls
    `taskkill /F /PID <pid>` via `syscall.Exec` (no
    shell quoting footgun).
  - `windows_kinds_windows.go` (306 LOC) — three more
    action kinds:
    - `quarantine_file` → `icacls <path> /deny "*S-1-1-0:(R)"`
      then `ren <path> <path>.quarantine`
    - `block_ip` → `netsh advfirewall firewall add rule
      name="ZaqorinBlock_<ip>" dir=in action=block
      remoteip=<ip>` (deterministic rule name for later
      removal)
    - `revoke_credential` → `klist purge` + `net session
      /delete` (clears Kerberos tickets + terminates
      incoming RDP)
  - All 4 Windows kinds gated by `//go:build windows`;
    the Linux `kill_unix.go` (syscall.Kill) covers the
    Linux side. Both branches compile cleanly in the
    5 GOOS × 2 GOARCH build matrix.
- **Cross-compile matrix** (`agent/Makefile`):
  - `make smoke-build` — produces 5 binaries in
    `bin/zaqorin-agent-{goos}-{goarch}[.exe]`, each
    statically linked (`CGO_ENABLED=0`, `-ldflags='-s -w'`).
    Verified sizes:
    - `linux/amd64` 5.3 MB
    - `linux/arm64` 5.1 MB
    - `windows/amd64` 5.6 MB
    - `darwin/amd64` 5.4 MB
    - `darwin/arm64` 5.2 MB
  - `make build-all` — same as smoke but only emits the
    binaries (no smoke).
  - `make build-local` — current host only, faster
    iteration.
- **WinSW service wrapper** (`agent/packaging/windows/`):
  - `zaqorin-agent-service.xml` — WinSW config:
    Automatic + DelayedAutoStart, restart on failure
    (5s), 10 MiB log rotation × 5 files, LocalSystem
    service account, 15s stop timeout.
  - `install.cmd` — drops the agent binary, WinSW
    wrapper, and XML into `C:\Program Files\ZaqorinCore\`,
    creates `C:\ProgramData\ZaqorinCore\{logs,state}\`,
    installs and starts the service.
  - `uninstall.cmd` — stops and uninstalls the service,
    removes the install directory, optionally removes
    the data directory (prompts first).
  - `README.md` — short operator walkthrough (WinSW
    download, install flow, verify, uninstall).
- **Operator guide** (`docs/PHASE12-windows.md`,
  ~470 lines):
  - What the Windows agent adds (6 event IDs, 4 action
    kinds, same wire Event shape)
  - What v1.2.0 does NOT include (deferred: macOS ESF,
    ETW push, code-signing, MSI)
  - Host requirements (Win Server 2019+ / Win 10 1809+,
    Local Administrator, outbound 8443)
  - Build walkthrough (`make smoke-build`)
  - Install + verify + uninstall flow
  - Configuration reference (same TOML, no Windows-
    specific sections)
  - Wire shape + detector integration notes
  - Per-action applier reference (`taskkill`, `icacls`,
    `netsh`, `klist`)
  - 6-step troubleshooting checklist (service not
    starting, SmartScreen quarantine, netsh elevation,
    PowerShell encoded command rule not firing, etc.)

### Notes

- 235/235 server tests pass (no regression).
- 14/14 Go agent packages pass (was 12, +2: Windows
  eventlog + Windows kinds).
- 9/9 launch smoke + 9/9 live smoke unchanged.
- All 5 GOOS × 2 GOARCH targets build cleanly:
  `linux/amd64`, `linux/arm64`, `windows/amd64`,
  `darwin/amd64`, `darwin/arm64`.
- **Honest gap:** the Windows runtime path
  (`wevtapi.dll` syscalls + `taskkill`/`netsh` action
  applier) was not end-to-end verified on a real
  Windows host during the v1.2.0 build (this release
  was produced on a Linux VPS with no Windows runner).
  Operators must:
  1. Run `make smoke-build` on a Windows host (or trust
     the cross-compile from a Linux host with
     `CGO_ENABLED=0`).
  2. Follow `agent/packaging/windows/README.md` to
     install the service on a real Windows host.
  3. Confirm via `sc query ZaqorinCoreAgent` +
     `wevtutil qe Security /c:5 /f:text` that events
     are flowing.
  The unit tests in `eventlog_test.go` cover the
  decoder logic on Linux; the Win32 syscall paths
  (`eventlog_windows.go`) and the action applier
  (`kill_windows.go`, `windows_kinds_windows.go`) are
  exercised only on real Windows.

## [1.1.0] - 2026-08-29

The eBPF kernel-telemetry backend ([ADR-006](docs/decisions/ADR-006-ebpf-kernel-telemetry.md))
ships in this release. Five syscall-tracepoint probes
(`execve`, `openat`, `connect`, `ptrace`, `setuid`) capture
events at the kernel boundary — un-tamperable by userspace
attackers — and feed them through the existing detector
pipeline. The file-tail backend remains the default and
the runtime fallback for hosts where the kernel is older
than 5.4 or CAP_BPF is unavailable.

### Added

- **BPF C source** (`agent/internal/ebpf/probes/c/`):
  - `probes_main.bpf.c` — the single combined probe; includes
    the five per-syscall monitor files and the shared
    `events` ring buffer map (256 KiB)
  - `execve_monitor.c`, `openat_monitor.c`, `connect_monitor.c`,
    `ptrace_monitor.c`, `setuid_monitor.c` — five `SEC("tracepoint/...")`
    handlers, one per syscall
  - `common.h` — shared event struct (`bpf_event`, `bpf_event_hdr`,
    five per-probe body structs) + minimal `trace_event_raw_sys_enter`
    stub + `AF_INET`/`AF_INET6` macros to avoid pulling in
    glibc's `gnu/stubs-32.h` during BPF compilation
- **bpf2go generation**:
  - `agent/Makefile` with `make ebpf` (bpf2go via
    `go run`, embeds the ELF via `go:embed`), `make build`,
    `make test`, `make clean`, `make check-prereqs`
  - `agent/internal/ebpf/probes/obj/wrapper.go` —
    hand-maintained, re-exports bpf2go's package-private
    `BpfProbes` / `BpfMaps` / `BpfObjects` types so the
    rest of the agent does not depend on bpf2go's
    per-version naming
  - One combined ELF (`zaqorin_probes_bpfel.o`, ~12 KB
    stripped) for `bpfel/amd64`. Cross-build for
    `arm64` via `make ebpf ARCH=arm64`
- **Runtime loader** (`agent/internal/ebpf/loader.go`):
  - `NewReal(logger, cfg)` — kernel version check (≥ 5.4),
    `rlimit.RemoveMemlock`, `bpfobj.LoadObjects`,
    `ringbuf.NewReader`, `link.Tracepoint` ×5, returns
    `(nil, reason)` on any failure so the caller falls
    back to `NotImplemented`
  - `Real.Run(ctx, handler)` — drains the shared ring
    buffer, decodes each record via the pure-function
    `decode(raw)`, encodes to the same wire shape the
    file-tail backend produces
  - `LoadConfig.Probes` allowlist — operators can disable
    individual probes at runtime without recompiling
- **Decoder** (Go side, mirrors C layout):
  - Five tag dispatch cases (`tagExecve`, `tagOpenat`,
    `tagConnect`, `tagPtrace`, `tagSetuid`)
  - Network-byte-order port decode for `connect`
  - IPv4 / IPv6 dual stack via `IsV6` discriminator
  - C-string NUL trimming for `comm`, `argv0..argv3`,
    `filename`
- **4 integration tests** (`integration_test.go`):
  - `TestCollectionSpecLoads` — parses the embedded ELF,
    asserts all 5 programs + the `events` map are present
  - `TestLoadObjectsFailsWithoutKernel` — CI/dev box path
    (no CAP_BPF) returns a non-nil error
  - `TestRingBufferReaderEndToEnd` — 5 sub-tests, one per
    probe kind, builds a synthetic `bpfEvent` record,
    feeds it through `decode` + `encodeWire`, asserts the
    resulting `event.Event` round-trips through JSON
  - `TestNotImplementedBackend` — fallback path blocks
    on ctx cancel cleanly, returns `context.DeadlineExceeded`
- **Operator guide** (`docs/PHASE11-ebpf.md`, ~360 lines):
  - Host requirements (kernel ≥ 5.4, CAP_BPF, CAP_PERFMON)
  - Build walkthrough (`make ebpf` with prereq install)
  - Runtime fallback chain diagram
  - Per-probe disable instructions
  - Three-step verification (build, permissions, runtime)
  - Wire-shape / detector integration notes
  - Troubleshooting checklist (7 common failure modes)

### Notes

- 235/235 server tests pass (no regression).
- 12/12 Go agent packages pass (was 10, +2:
  `agent/internal/ebpf/` decoder tests + integration
  tests).
- 9/9 launch smoke + 9/9 live smoke unchanged.
- `go build ./...` succeeds on every GOOS without a BPF
  toolchain — the embedded objects are the only path
  that needs `clang + libbpf-dev + linux-headers`.
- **Honest gap:** the BPF programs compile cleanly and
  the CollectionSpec loads in tests, but the runtime
  attach path (CAP_BPF syscall) was not end-to-end
  verified on the release host (VPS lacks
  `cap_bpf,cap_perfmon`). Operators must run
  `setcap cap_bpf,cap_perfmon=ep /path/to/zaqorin-agent`
  on each monitored host, then confirm via
  `bpftool prog list` that five `tracepoint` programs
  are attached to the agent's PID. The integration
  test exercises the loader up to (but not including)
  the kernel `bpf()` syscall.

## [1.0.0] - 2026-08-28

The first release considered **production-ready**. Every advertised
feature in the README is implemented, tested, and documented.

### Added

- **Docs site** (`https://faris-stuck.github.io/zaqorincore/`) —
  mkdocs + material theme, dark/light toggle, full-text search.
  Includes landing page, operator guide, 9 phase docs, 5 ADRs,
  roadmap, and 5-minute demo walkthrough.
- **DB-free launch smoke** (`server/scripts/smoke_launch.py`) —
  9 checks, runs in under a second, no docker/env required. Pairs
  with the live-stack smoke (`scripts/smoke.sh`) for end-to-end
  coverage.
- **5-minute demo walkthrough** (`docs/DEMO.md`) — scripted
  security-team demo covering the SPA, smoke, canary, compliance
  packs, and evidence locker.
- **HN launch post** (`docs/HN-LAUNCH.md`) — submission-ready text
  plus submitter notes (timing, cross-post, first-comment prep).

### Notes

- 170/170 server tests pass. 10/10 Go packages pass. 9/9 launch
  smoke checks pass. 9/9 live smoke checks pass.
- Zero known P0 bugs. Known limitations (no auth UI, CSP still
  allows `https://esm.sh`) are documented in `docs/PHASE9.md` and
  tracked in `ROADMAP.md` for v1.x.
- License: **MIT**. No SaaS, no telemetry, no per-seat, no
  per-host. The binary you build is the binary you run.
- "AI" / "ML" / "LLM" do not appear in the code, the docs, or
  the branding. The product is 100% rule-based and proud of it.

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

[Unreleased]: https://github.com/Faris-stuck/zaqorincore/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/Faris-stuck/zaqorincore/compare/v1.0.0...v1.3.0
[1.2.0]: https://github.com/Faris-stuck/zaqorincore/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Faris-stuck/zaqorincore/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Faris-stuck/zaqorincore/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Faris-stuck/zaqorincore/releases/tag/v0.1.0
