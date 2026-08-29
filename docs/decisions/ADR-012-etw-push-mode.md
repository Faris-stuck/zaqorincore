# ADR-012: ETW push-mode subscription (Win32 EvtSubscribe callback)

## Status
Proposed → **Partial Acceptance** (Linux-testable core
shipped; Win32 CGO callback deferred to v1.6.1)

## Date
2026-08-29

## Context

The v1.2.0 Windows Event Log backend uses
EvtSubscribe in pull mode with a 1s poll loop. The
v1.2.0 design doc acknowledged that push mode (a
real Win32 callback invoked as events arrive) would
drop latency to sub-millisecond, but noted the
CGO trampoline as a barrier to testing on Linux.

Detection latency matters for high-fidelity rules:
a T1059.003 cmd.exe-from-Office rule that fires
1s after the event loses attribution context
(parent process is gone, command line buffer
rolled over). A sub-millisecond delivery preserves
both for the alert payload.

## Decision

Ship a v1.6.0 push-mode backend that consists of:

1. **Cross-platform core** (`push_mode_common.go`)
   — the buffered channel, drain goroutine, drop-on-full
   logic, and Close lifecycle. Fully testable on
   Linux.
2. **Non-Windows stub** (`push_mode_other.go`,
   `//go:build !windows`) — returns "not supported
   on this platform" so the type compiles on every
   GOOS.
3. **Win32 callback file** — **DEFERRED to v1.6.1**
   because cross-building requires MinGW-w64
   (`x86_64-w64-mingw32-gcc`), which is not yet
   installed on the development VPS.
4. **Config field** `windows_eventlog.mode =
   "pull"|"push"`, default `"pull"` (back-compat).

The push-mode drain goroutine and config plumbing
are shipped in v1.6.0 with the Linux test suite
fully green. The Win32 callback file is documented
in PHASE18 as the next increment.

## Consequences

Positive:
- Detection latency for Windows security events
  drops from 1s (poll) to sub-millisecond
  (callback) when push mode is enabled and
  the Win32 callback is wired up in v1.6.1.
- Linux-testable infrastructure (channel,
  drain loop, drop-on-full, Close) gives us
  the safety net: even if the Win32 file
  is buggy, the Go side cannot deadlock the
  kernel callback because the channel is
  bounded.

Negative:
- The v1.6.0 push-mode config knob
  (`mode = "push"`) is parseable but does
  nothing useful yet on Windows hosts until
  v1.6.1 ships the CGO callback. Operators
  who set `mode = "push"` in v1.6.0 get
  no functional change.
- The Win32 callback crosses a CGO boundary
  on every event; the syscall cost (≈200ns)
  is paid per event. Acceptable for the
  ≤100 events/sec security channel volume.

## Alternatives considered

- **Keep pull mode forever.** Rejected:
  1s latency is too long for high-fidelity
  process-create attribution.
- **Use eBPF on Linux, kernel ETW on
  Windows directly from Go via syscall.** Rejected:
  the CGO callback IS the standard pattern; the
  cost is paid by every ETW consumer.

## Follow-up (v1.6.1)

1. Install `gcc-mingw-w64-x86-64` on the
   development VPS.
2. Write `push_mode_windows.go` with:
   - `//go:build windows` + `import "C"`
   - `//export goPushCallback` CGO trampoline
   - `SubscribePush` (Win32 EvtSubscribe with
     callback) + `Close` (EvtClose)
3. Wire `cfg.WindowsEventlog.Mode == "push"`
   into the agent's main backend selector in
   `internal/app/app.go`.
4. Verify with a real Windows VM: enable push
   mode, log a fake 4688, confirm event arrives
   in <100ms.
