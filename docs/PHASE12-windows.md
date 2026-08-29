# ZaqorinCore v1.2.0 — Windows Agent (Operator Guide)

**ADR-007** · **PHASE-12**

This document is the deployment reference for the Windows
agent that ships in ZaqorinCore v1.2.0. It covers the
telemetry source, the action applier, the host
requirements, the build path, the service install, and a
troubleshooting checklist for the most common failure
modes on Windows.

If you only need the minimum to get started: see
`agent/packaging/windows/README.md` for the WinSW install
flow, and the cross-build `make smoke-build` target for
producing the binary.

---

## What the Windows agent adds

ZaqorinCore v1.1.0 shipped a Linux-only agent (file-tail
+ eBPF). v1.2.0 adds a **Windows agent** that covers the
same detection surface from the Windows Event Log:

| Event ID | Meaning | Linux analog            |
| -------- | ------- | ----------------------- |
| 4624     | Successful logon | `Accepted password` |
| 4625     | Failed logon    | `Failed password`  |
| 4688     | Process created | (eBPF `execve`)    |
| 4698     | Scheduled task created | cron job create |
| 4720     | User account created   | `useradd`         |
| 4732     | Member added to security-enabled group | `usermod -aG` |

The Windows agent subscribes to the **Security** log
via the Win32 `EvtSubscribe` API (`wevtapi.dll`) and
renders each matching record as XML. The same XML
decoder (`eventlog_common.go`) parses the record into
the same wire `Event` shape the Linux file-tail backend
produces, so the server, transport, and detector
pipelines do not change.

The Windows agent also implements the **Windows
auto-response action kinds** for the four operations that
make sense on Windows:

| Action | Windows implementation |
| ------ | ---------------------- |
| `kill_process`  | `taskkill /F /PID <pid>` |
| `quarantine_file` | `icacls deny` + rename to `.quarantine` |
| `block_ip` | `netsh advfirewall firewall add rule` |
| `revoke_credential` | `klist purge` + `net session /delete` |

The HMAC-signed COMMAND frame protocol (v0.4.0) works
the same way on every platform: the agent verifies the
signature, checks `applies_to(action_kind, host_platform)`
on the server side, applies the action if authorised,
and returns the result. The agent never holds the
shared secret in plaintext on disk.

---

## What v1.2.0 does NOT include (deferred)

- **macOS agent.** Per Faris' explicit decision
  ("Yasudah windows dan Linux saja tidak usah mac")
  during the v1.0.0 cycle, the macOS Endpoint Security
  Framework backend is out of scope. The dispatcher
  returns a `Scaffold` backend on darwin that logs once
  and blocks on context cancel. The build target still
  compiles cleanly; operators on macOS will see a
  one-time warning at startup.
- **ETW (Event Tracing for Windows) push-mode
  subscription.** The current Windows agent uses a
  pull model (`EvtQuery` every 5s). ETW is a v1.x
  follow-up behind a config flag because ETW consumer
  privilege is `SE_DEBUG_NAME`-level and not every
  operator wants to grant it.
- **Windows code-signing certificate.** The agent
  binary ships **unsigned** in v1.2.0. Operators
  should sign their build with their own cert before
  wide deployment. SmartScreen will warn on first run
  for unsigned binaries.
- **MSI installer.** The install flow is a `cmd` script
  + WinSW XML. A `wix`-built MSI is a v1.2.x follow-up
  for organisations that need Group Policy push.

---

## Host requirements

1. **Windows Server 2019+ or Windows 10 1809+.** Older
   versions lack the `wevtapi` rendering flags we use
   and are out of support.
2. **Local Administrator on the host.** The service
   runs as `LocalSystem` (required to read the
   Security event log). WinSW install requires the
   user running `install.cmd` to be Administrator.
3. **Outbound HTTPS/WSS to the ZaqorinCore server.**
   Port 8443 by default; the agent does not need any
   inbound port.
4. **Windows Event Log readers.** The `LocalSystem`
   account has this by default. If you scope the
   service to a different account, add it to the
   **Event Log Readers** local group.

## Build

The agent cross-compiles from any host with Go 1.22+
and the agent source tree. The Windows binary is
statically linked (no CGO, no external runtime
dependencies).

```bash
cd agent/
make smoke-build
# Produces:
#   bin/zaqorin-agent-linux-amd64       (5.0 MB)
#   bin/zaqorin-agent-linux-arm64       (5.0 MB)
#   bin/zaqorin-agent-windows-amd64.exe (5.3 MB)
#   bin/zaqorin-agent-darwin-amd64      (5.2 MB)
#   bin/zaqorin-agent-darwin-arm64      (5.0 MB)
```

The Windows build is a 5.3 MB `exe` that runs on any
Windows 10/Server 2019 host without further
dependencies. No DLLs to ship, no Visual C++ runtime
to install.

## Install

See `agent/packaging/windows/README.md` for the full
walkthrough. The short version:

```cmd
:: 1. Place these four files in a temp dir:
zaqorin-agent.exe
zaqorin-agent-service.exe          (WinSW, renamed)
zaqorin-agent-service.xml
agent.example.toml

:: 2. Right-click install.cmd → "Run as administrator"
install.cmd

:: 3. Edit the config
notepad C:\ProgramData\ZaqorinCore\agent.toml

:: 4. Restart the service
sc stop ZaqorinCoreAgent
sc start ZaqorinCoreAgent
```

## Verify

Three checks, in order:

1. **Service is running:**
   ```cmd
   sc query ZaqorinCoreAgent
   ```
   The `STATE` field should be `RUNNING`.

2. **WinSW log shows clean start:**
   ```cmd
   type "C:\Program Files\ZaqorinCore\zaqorin-agent-service.out.log"
   ```
   Look for `Service ZaqorinCoreAgent started` and no
   subsequent `Failed`.

3. **Agent log shows platform + probes:**
   ```cmd
   type "C:\ProgramData\ZaqorinCore\logs\agent.log"
   ```
   Look for JSON lines containing
   `"msg":"agent started"` and
   `"platform":"windows"`. The `windows.security.4688`
   source will start emitting within seconds of any
   new process.

4. **Server-side:** the host's `host_id` appears in
   the server's `/api/v1/hosts` endpoint within 10s
   of the WebSocket connect.

---

## Configuration reference

The Windows agent reads the same TOML config file the
Linux agent uses. There are no Windows-specific
sections. The relevant fields:

```toml
[agent]
id = "win-host-01"        # stable agent identity
server_url = "wss://zaqorin.example.com:8443/api/v1/events"
auth_token = "***"        # from server admin

[tailer]
# The Windows agent ignores the [tailer] file paths
# entirely. It always tails the Windows Event Log.
# The fields are kept for cross-platform config
# compatibility so a single config file can be
# shared across the fleet.

[response]
# Same HMAC shared-secret handling as the Linux agent.
# The agent refuses to apply a COMMAND frame if the
# signature does not verify.
```

---

## Wire shape and detector integration

The Windows agent produces events with the same
`event.Event` shape the Linux agent produces. The only
difference is the `event.Source` field:

| Backend                   | Source                       |
| ------------------------- | ---------------------------- |
| Linux file-tail           | `auth.log`, `syslog`, etc.   |
| Linux eBPF                | `ebpf/execve`, `ebpf/connect`, ... |
| Windows Event Log         | `windows.security.4624`, `windows.security.4625`, `windows.security.4688`, `windows.security.4698`, `windows.security.4720`, `windows.security.4732` |

Detectors that match on `source == "auth.log"` continue
to work. Detectors that want both can use
`source.startswith("windows.security.")` or the explicit
`source == "windows.security.4688"` form.

The metadata fields per event ID mirror the Win32 Event
Log schema. For example, a 4624 (Successful logon) event
exposes:

```json
{
  "event_id": 4624,
  "source": "windows.security.4624",
  "metadata": {
    "target_user_name": "alice",
    "target_domain_name": "EXAMPLE",
    "logon_type": 3,
    "workstation_name": "WIN-CLIENT-01",
    "ip_address": "10.0.0.42",
    "ip_port": 49152
  }
}
```

The metadata is the raw Win32 Event Log XML translated
to a flat JSON object. Detector rules that need
structured access (e.g. "logon_type == 10 (RemoteInteractive)")
should match on the field directly.

---

## Action applier reference

The four Windows action kinds map to platform-native
tools. Each is a thin wrapper around the matching
command-line tool, called with HMAC-signed arguments
over the WebSocket COMMAND channel.

### `kill_process`

```cmd
taskkill /F /PID <pid>
```

The agent calls `taskkill` with the `pid` from the
detector. If the process is protected
(`IsProcessCritical`-style), the call returns non-zero
and the COMMAND frame is marked failed. The agent
reports the exit code and stderr to the server.

### `quarantine_file`

```cmd
icacls "<path>" /deny "*S-1-1-0:(R)"
ren "<path>" "<path>.quarantine"
```

The agent first denies the `Everyone` SID read
permission via `icacls`, then renames the file to add a
`.quarantine` suffix. Reversing the quarantine requires
`icacls /reset` and a manual rename; the v0.7.0 canary
evidence locker stores the original path and hash.

### `block_ip`

```cmd
netsh advfirewall firewall add rule ^
  name="ZaqorinBlock_<ip>" ^
  dir=in action=block ^
  remoteip=<ip>
```

The rule name is deterministic (`ZaqorinBlock_<ip>`)
so a follow-up `delete rule` can remove it later. The
firewall rule persists across reboots. Removing a rule
requires an explicit `netsh advfirewall firewall delete
rule` (not yet wired into the agent; v1.2.x follow-up).

### `revoke_credential`

```cmd
klist purge
net session /delete
```

The `klist purge` clears all Kerberos tickets for the
current user. The `net session /delete` terminates
incoming RDP connections. Note that `klist purge` only
affects the current logon session; for service accounts
running under `LocalSystem`, the equivalent is
`klist -li 0x3e7 purge` to target the service session.

---

## Troubleshooting

- **`Service cannot start. The system cannot find the
  file specified.`**
  WinSW cannot find `zaqorin-agent.exe` next to the
  XML. Confirm all three files are in
  `C:\Program Files\ZaqorinCore\` (the install script
  handles this; the error usually means the script was
  not run as Administrator).

- **`Service started, then stopped.`**
  Open the agent log at
  `C:\ProgramData\ZaqorinCore\logs\agent.log`. Look
  for `"level":"ERROR"` lines. The most common
  causes:
  - `failed to load config: open agent.toml: no such
    file` — the install script did not find
    `agent.example.toml` in the working directory, or
    the config was not placed in
    `C:\ProgramData\ZaqorinCore\`.
  - `failed to connect to server: dial tcp: lookup
    zaqorin.example.com: no such host` — the server
    URL is wrong or the host cannot reach the server.
  - `unauthorized: invalid auth_token` — the token in
    `agent.toml` does not match the server.

- **No `windows.security.*` events in the server's
  alerts dashboard, but the service is running.**
  Three checks:
  1. The Security event log is enabled and has
     auditable events. From an elevated `cmd`:
     ```cmd
     auditpol /get /category:*
     ```
     Confirm `Logon/Logoff` and `Account Management`
     are `Success and Failure`.
  2. The host actually generates events. From an
     elevated `cmd`:
     ```cmd
     wevtutil qe Security /c:5 /rd:true /f:text
     ```
     You should see recent 4624/4625/4688 events.
  3. The agent's WebSocket is connected. The agent log
     shows `transport: connected to <url>` and a
     periodic `transport: heartbeat`. If you see
     `transport: reconnecting` repeatedly, the server
     is unreachable from the host.

- **Windows Defender quarantines the agent binary.**
  The agent binary is unsigned in v1.2.0. Windows
  Defender SmartScreen will warn on first run, and
  some Defender policies will quarantine unsigned
  binaries outright. To resolve:
  1. Add an exclusion for the install directory via
     Group Policy, or
  2. Sign the binary with your organisation's
     code-signing certificate (recommended for
     production).

- **`netsh` returns "The requested operation requires
  elevation (Run as administrator)" for `block_ip`.**
  WinSW runs the service as `LocalSystem`, which has
  full local privileges. If you have scoped the service
  to a different account (e.g. a gMSA), that account
  must be in the local Administrators group for
  `netsh advfirewall` to succeed.

- **PowerShell encoded command rule never fires.**
  The 4688 metadata only contains the command line
  if Process Command Line auditing is enabled:
  ```cmd
  auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
  ```
  And:
  ```reg
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
  ProcessCreationIncludeCmdLine_Enabled = 1
  ```
  The agent log does not warn about this; the metadata
  field is just silently empty.

---

## See also

- `agent/packaging/windows/zaqorin-agent-service.xml` —
  the WinSW config
- `agent/packaging/windows/install.cmd` and
  `uninstall.cmd` — the install / uninstall scripts
- `agent/packaging/windows/README.md` — short install
  walkthrough
- `agent/Makefile` — `make smoke-build` (5 GOOS×2 GOARCH)
- `agent/internal/telemetry/windows/` — the Event Log
  runtime (Win32 syscalls + XML decoder)
- `agent/internal/response/kinds/kill_windows.go` and
  `windows_kinds_windows.go` — the Windows action
  applier
- `docs/decisions/ADR-007-multi-platform-agents.md` —
  the architectural decision
- `CHANGELOG.md` — v1.2.0 release entry
- `docs/PHASE11-ebpf.md` — the v1.1.0 Linux eBPF
  operator guide (sister document)
