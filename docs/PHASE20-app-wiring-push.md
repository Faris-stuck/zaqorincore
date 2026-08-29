# PHASE20 — app wiring for Windows eventlog push-mode (v1.6.2)

Status: **Shipped** in v1.6.2
Owner: Agent / Detection Engineering
Reviewers: Code Review

## 1. Why this slice exists

v1.6.1 shipped the Win32 CGO callback but the
`internal/app/app.go` main loop still only knew
about file-tail `log_source` entries. v1.6.2 adds
the wiring: when `cfg.WindowsEventlog.Mode ==
"push"` AND we're on Windows, start the
push-mode subscription and fan its events into the
same dispatcher that handles tailer lines.

## 2. What ships in v1.6.2

- **`internal/app/windows_eventlog_other.go`**
  (//go:build !windows): factory that returns
  `(nil, nil)`. The agent runs fine on Linux/macOS.
- **`internal/app/windows_eventlog_windows.go`**
  (//go:build windows): factory that builds a real
  `windows.NewPush(...)` backend, subscribes it,
  and returns the `WindowsEventlogBackend` adapter.
- **`internal/app/app.go`**:
  - New `WindowsEventlogBackend` interface
    (Run + Close).
  - `Dependencies` gained
    `NewWindowsEventlogBackend` field (overridable
    in tests).
  - `Run` checks `cfg.WindowsEventlog.Mode ==
    "push"`, calls the factory, defers `Close()`,
    launches the backend in a goroutine.
  - Dispatcher: extended the `select` to consume
    from BOTH `lines` (tailers) AND `pushEventOut`
    (Windows eventlog). Uses the
    "set channel to nil to disable a case" pattern
    so the loop exits cleanly when BOTH close.
- **1 new test** (`TestRun_ForwardsWindowsEventlogEvents`):
  injects a `fakeWinBackend`, asserts 2 events
  arrive at the transport and `Close()` is called
  on shutdown.
- **Windows cross-build verified**: `cmd/...` builds
  cleanly with `CGO_ENABLED=1 GOOS=windows
  GOARCH=amd64 CC=x86_64-w64-mingw32-gcc`.

## 3. Design choices

- **Build-tag-dispatched factory** (`NewWindowsEventlogBackend`)
  instead of `if runtime.GOOS == "windows" { ... }`
  in `app.go`. Reason: avoids pulling in
  `telemetry/windows` package on non-Windows
  builds (would break the cross-build of
  the agent for Linux/macOS hosts).
- **Interface in app.go, impl in build-tag files**
  keeps `app.go` platform-neutral. Tests inject
  a fake without touching the build tag.
- **"nil channel" shutdown pattern** in the
  dispatcher. Standard Go idiom: setting a
  channel to `nil` makes that case of `select`
  never fire. We use this to exit when BOTH
  tailers AND push backend have closed.

## 4. Verification

```
$ go test -v ./internal/app/ -run TestRun_
=== RUN   TestRun_RejectsNilDeps
--- PASS
=== RUN   TestRun_ForwardsTailerLinesAsEvents
--- PASS
=== RUN   TestRun_ForwardsWindowsEventlogEvents
--- PASS
=== RUN   TestRun_PropagatesContextCancel
--- PASS

$ go test ./...   # full Go agent suite
ok  all packages

$ CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
  CC=x86_64-w64-mingw32-gcc \
  go build ./cmd/...   # Windows cmd builds
$ ls -la /tmp/wintest
-rwxr-xr-x 1 ubuntu ubuntu 7707591   # 7.7 MB Windows test binary
```

## 5. PITFALLS (recorded for next session)

1. **Build-tag method conflict (recap)**: defining
   the same method in both common.go and a
   build-tag file = compile error. Define ONLY in
   build-tag files.
2. **`PushBackend.Run` signature**: takes
   `func([]byte) error` NOT `func(string)`.
   Returning `ctx.Err()` from inside the handler
   stops the drain loop cleanly.
3. **`NewPush(hostID, logger)` not `NewPushBackend(...)`**.
4. **Build-tag factory in package app**: must
   return `WindowsEventlogBackend` interface
   defined in the package — the `other.go` build
   fails to compile if the interface is
   in build-tag-specific files.
5. **`go vet` on single file = false `undefined`**
   for symbols from other files in the package.
   Use `go vet ./...` or `go test -c`.
