# ADR-007: Multi-platform agents (Windows + macOS) — v1.2

**Status:** Accepted
**Date:** 2026-08-28
**Authors:** ZaqorinCore maintainers
**Supersedes:** none
**Related:** ADR-006 (eBPF on Linux), v0.4.0 (HMAC-signed auto-response)

## Context

The v1.0.0 Go agent runs on **Linux only** (amd64 + arm64).
This covers servers but not the majority of enterprise
endpoints, which are typically a mix of:

- Linux servers (web, db, app, k8s nodes)
- **Windows** servers and workstations (Active Directory,
  file shares, Office, Outlook, RDS hosts)
- **macOS** laptops and desktops (developer machines,
  executive staff, design teams)

A security tool that sees only the Linux half of this
fleet has a 50-80% detection-coverage gap. v1.2 closes it.

## Decision

Ship Windows + macOS agents in the same Go module
(`agent/`) using the same wire contract, the same HMAC-
signed auto-response, and a per-platform telemetry backend
that produces events with the same shape.

The agents are *not* forks — they share `internal/event`,
`internal/transport`, `internal/crypto`, `internal/logger`,
`internal/config`, `internal/app` with the Linux agent.
Only the `internal/telemetry` backend and the
`internal/response` action applier are platform-specific.

## Telemetry source per platform

| Platform | Primary source | Kernel-level source | Backend package |
|---|---|---|---|
| Linux | file tail (v1.0.0) | eBPF (v1.1) | `agent/internal/telemetry/linux/` |
| Windows | Windows Event Log (Security, System, Application) | ETW (optional) | `agent/internal/telemetry/windows/` |
| macOS | Unified Log (sysdiag) + FSEvents | Endpoint Security Framework (ESF) | `agent/internal/telemetry/darwin/` |

### Windows — Windows Event Log via wevtapi

The minimum viable Windows telemetry covers the same
security events the Linux auth.log covers:

| Event ID | Meaning | Linux analog |
|---|---|---|
| 4624 | Successful logon | `Accepted password` |
| 4625 | Failed logon | `Failed password` |
| 4688 | Process created | (eBPF `execve` in v1.1) |
| 4698 | Scheduled task created | cron job create |
| 4720 | User account created | `useradd` |
| 4732 | Member added to security group | `usermod -aG` |
| 5145 | Network share access checked | file access audit |

Subscription is via the `EvtSubscribe` API
(`wevtapi.dll`), with a pull model (5s poll) for v1.2.
ETW push-based is a v1.x optimization.

### Windows — ETW (kernel-level, optional)

ETW providers in the Kernel category cover:

- `Microsoft-Windows-Kernel-Process` → process exec, exit
- `Microsoft-Windows-Kernel-File` → file open/read/write
- `Microsoft-Windows-Kernel-Network` → TCP/UDP connect
- `Microsoft-Windows-Kernel-Power` → sleep/wake
- `Microsoft-Windows-Threat-Intelligence` → AMSI,
  ETW-TI, the same source EDR products use

The Go binding is via `github.com/bi-zone/etw` (pure Go,
no CGo). This is a v1.2.x add-on behind a config flag
because ETW consumer privilege is `SE_DEBUG_NAME`-level
and not every operator wants to grant it.

### macOS — Endpoint Security Framework

ESF is the macOS kernel-level framework (the eBPF/ETW
equivalent). It provides event types:

| ESF event | Captured | Use |
|---|---|---|
| `ES_EVENT_TYPE_AUTH_EXEC` | path, argv, env subset | web shell, LOLBin, attacker tool |
| `ES_EVENT_TYPE_AUTH_OPEN` | path, flags | SSH key, keychain, TCC-protected file |
| `ES_EVENT_TYPE_NOTIFY_CONNECT` | src/dst ip+port, proto | C2, exfil, lateral |
| `ES_EVENT_TYPE_AUTH_KEXTLOAD` | bundle id, team id | unsigned kext (rootkit) |
| `ES_EVENT_TYPE_NOTIFY_MMAP` | path, protection | suspicious memory map (injection) |
| `ES_EVENT_TYPE_NOTIFY_FORK` | parent/child pid | process tree |

ESF requires a **System Extension** with the
`com.apple.developer.endpoint-security.client` entitlement
and a **notarized** helper. This is a one-time notarization
cost (Apple Developer Program, $99/year) and the binary
must be signed with a Developer ID.

The Go binding is `github.com/groob/esext` (or
`github.com/elastic/go-esext` style). Both wrap the
`EndpointSecurity` Objective-C framework.

## Action kinds per platform

The 9 action kinds from v0.5.0 map to platform-specific
implementations:

| Action | Linux | Windows | macOS |
|---|---|---|---|
| `block_ip` | nftables set element | `netsh advfirewall firewall add rule` | `pf` table add |
| `kill_process` | `kill -SIGKILL <pid>` | `taskkill /F /PID <pid>` | `kill -SIGKILL <pid>` |
| `quarantine_file` | `chmod 000` + rename | `icacls deny` + `.quarantine` | `chmod 000` + xattr `com.apple.quarantine` |
| `isolate_host` | nftables drop-all outbound | `netsh` block all | `pf` block all + mDNS off |
| `snapshot_processes` | `ps auxf` + `/proc/*/maps` | `tasklist /v` + WMI | `ps auxf` + `vmmap` |
| `canary` | (any kind) | (any kind) | (any kind) |
| `throttle_service` | `tc qdisc` | `netsh` throttling | `pf` throttling |
| `trip_wire` | (any kind) | (any kind) | (any kind) |
| `revoke_credential` | `pkill -u <user>` | `klist purge` + `net session /delete` | `security delete-generic-password` |

Each platform implements only the kinds that make sense
there. The server's dispatcher already runs an
`applies_to(action_kind, host_platform)` check (new in
v1.2) before signing the COMMAND; unsupported kinds fail
in the server with HTTP 422, never in the agent.

## Build matrix

```makefile
# agent/Makefile (additions for v1.2)
build:
    GOOS=linux  GOARCH=amd64 go build -o bin/zaqorin-agent-linux-amd64       ./cmd/zaqorin-agent
    GOOS=linux  GOARCH=arm64 go build -o bin/zaqorin-agent-linux-arm64       ./cmd/zaqorin-agent
    GOOS=windows GOARCH=amd64 go build -o bin/zaqorin-agent-windows-amd64.exe ./cmd/zaqorin-agent
    GOOS=darwin  GOARCH=amd64 go build -o bin/zaqorin-agent-darwin-amd64      ./cmd/zaqorin-agent
    GOOS=darwin  GOARCH=arm64 go build -o bin/zaqorin-agent-darwin-arm64      ./cmd/zaqorin-agent
```

Service wrappers:

- Linux: systemd unit (already shipped)
- Windows: WinSW (`zaqorin-agent.exe` + `zaqorin-agent.xml`)
- macOS: `launchd` plist in `~/Library/LaunchDaemons/`

## Distribution

- **Linux:** Homebrew tap, apt repo, raw tarball (already
  shipped in v0.1.0).
- **Windows:** MSI installer built with `wix` + a code
  signing certificate (a separate question; the
  release-time cost is a code-signing cert, ~$200-400/yr).
- **macOS:** DMG with the notarized System Extension;
  requires the user to approve in
  System Settings → Privacy & Security after install.

## Wire contract impact

**None.** The wire schema is platform-agnostic. The
`source` field is per-platform:

- `auth.log` (Linux)
- `windows.security` / `windows.system` / `windows.application`
  (Windows)
- `darwin.esf.exec` / `darwin.esf.open` / `darwin.esf.connect`
  (macOS)

The server's detector pipeline doesn't care about the
`source` value as long as it's a string. New rules just
need to be added.

## Sigma rule impact

51 compliance rules + 5 baseline = 56 today. v1.2 ships
with 10-20 new platform-specific rules:

- "PowerShell encoded command" (Windows 4688 metadata)
- "Lsass memory read" (Windows 4688 + file open of
  `lsass.exe` or `/proc/*/maps` for `lsass`)
- "Suspicious launchd plist create" (macOS FSEvents on
  `~/Library/LaunchAgents/`)
- "Unsigned kext load" (macOS ESF ES_EVENT_TYPE_AUTH_KEXTLOAD)
- "User added to Domain Admins" (Windows 4728/4732/4756)

## Consequences

- **Positive:** the same server protects a mixed fleet.
  The v1.0.0 detector pipeline + Sigma rule engine + 9
  action kinds + evidence locker are 100% reused.
- **Positive:** ZaqorinCore becomes a credible replacement
  for a fleet-wide EDR for a typical SMB.
- **Negative:** macOS notarization adds a $99/year cost
  and a build-step that depends on Apple infrastructure.
  Acceptable; same cost as any macOS distribution.
- **Negative:** Windows code-signing is a separate concern
  (cost + key management). Out of scope for v1.2;
  v1.2 ships the binaries **unsigned** with a clear
  operator warning, with a follow-up ADR for signing.
- **Negative:** test surface explodes. CI must now run
  Windows (3 unit-test jobs) and macOS (3 unit-test jobs)
  in addition to Linux (already 3 jobs). A self-hosted
  runner is the cheapest path; GitHub Actions Windows +
  macOS runners add ~$0.08/min.
- **Negative:** the ETW provider for the kernel is
  partially restricted on Windows 10 1903+ (requires
  `SeSystemProfilePrivilege` or running as SYSTEM).
  Documented in the operator guide; v1.2 ships
  Event-Log-only by default, ETW opt-in.

## Implementation plan (vertical slices)

1. **Slice 1 — design + scaffolding** *(this ADR + the empty
   `agent/internal/telemetry/windows/` and
   `agent/internal/telemetry/darwin/` packages with
   `telemetry.go` returning "platform not yet implemented"
   at startup). Land in main with no behavior change on
   Linux.*
2. **Slice 2 — Windows Event Log telemetry.** Windows
   agent builds, runs, ships 4624/4625/4688/4698 to
   server. SSH-brute-force-equivalent rule ships.
3. **Slice 3 — Windows action applier.** The 4 Windows
   action kinds (`kill_process`, `quarantine_file`,
   `block_ip` via `netsh`, `revoke_credential` via
   `klist purge`) work end-to-end with HMAC.
4. **Slice 4 — macOS ESF telemetry.** macOS agent builds,
   runs, ships exec/open/connect events. One Sigma rule.
5. **Slice 5 — macOS action applier.** 4 macOS action
   kinds.
6. **Slice 6 — build matrix + packaging.** Makefile,
   WinSW wrapper, launchd plist, MSI/DMG, CI.
7. **Slice 7 — docs.** Operator guide update, ROADMAP
   bump, ADRs.

## Decision outcome

Accepted. Implementation begins with Slice 1.
