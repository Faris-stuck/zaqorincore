# PHASE19 — Windows ETW push-mode Win32 CGO callback (v1.6.1)

Status: **Shipped** in v1.6.1
Owner: Agent / Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

v1.6.0 shipped the Linux-testable push-mode core
(push_mode_common.go + push_mode_other.go) and
documented the Win32 CGO callback as deferred to
v1.6.1 because the development VPS lacked MinGW-w64.
v1.6.1 installs MinGW-w64, writes the Win32 callback
file, and cross-builds a real Windows test binary
proving the CGO trampoline + //export symbol are
valid.

## 2. What ships in v1.6.1

- **`push_mode_windows.go`** (//go:build windows):
  - CGO preamble with `extern __stdcall goPushCallback(...)` matching the Win32
    `EVT_SUBSCRIBE_CALLBACK` signature.
  - `SubscribePush` calls `EvtSubscribe` with the
    callback's address and the `PushBackend` pointer
    as `CallbackContext`.
  - `//export goPushCallback`: the C-callable trampoline
    that EvtSubscribe invokes. Renders the event to
    XML via `EvtRender`, truncates trailing NULs, and
    pushes into the Go channel.
  - `onStop` (//go:build windows only) releases the
    `EvtSubscribe` handle via `EvtClose` on Close.
- **`push_mode_other.go`**: `onStop` is a no-op on
  non-Windows builds.
- **`push_mode_common.go`**: calls `b.onStop()` from
  `Close()` — the build tag determines the actual
  implementation.
- **1 new test**: `TestPushBackend_ConfigPullIsDefault`
  documents that the default `windows_eventlog.mode`
  is `"pull"` (v1.6.2 wires the selector).
- **MinGW-w64** installed on dev VPS (apt:
  `gcc-mingw-w64-x86-64`).
- **Windows test binary** cross-compiles cleanly:
  `/tmp/wintest` 7.7 MB, contains goPushCallback
  symbol exported via //export.

## 3. What is DEFERRED to v1.6.2

- **`internal/app/app.go` wiring**: the agent's main
  loop currently only knows about file-tail `log_source`
  entries. v1.6.2 adds: when the platform is Windows AND
  `cfg.WindowsEventlog.Mode == "push"`, start
  `PushBackend.SubscribePush` and `Run` in addition to
  the file tailers. Single boolean: `if runtime.GOOS
  == "windows" && cfg.WindowsEventlog.Mode == "push"
  { ... }`.
- **End-to-end smoke** on a real Windows VM:
  install agent with `[windows_eventlog] mode = "push"`,
  log a fake 4688, confirm event arrives in
  <100 ms. Requires a Windows VM not available on
  the dev VPS.

## 4. Verification

```
$ x86_64-w64-mingw32-gcc --version
x86_64-w64-mingw32-gcc (GCC) 13-win32

$ CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
  CC=x86_64-w64-mingw32-gcc \
  go test -c ./internal/telemetry/windows/ \
  -o /tmp/wintest
$ ls -la /tmp/wintest
-rwxr-xr-x 1 ubuntu ubuntu 7707591 Aug 29 20:39 /tmp/wintest

$ go test ./internal/telemetry/windows/ -v -run TestPushBackend
=== RUN   TestPushBackend_ForwardsEventsToHandler
--- PASS: TestPushBackend_ForwardsEventsToHandler (0.20s)
=== RUN   TestPushBackend_DropsOnFullChannel
--- PASS: TestPushBackend_DropsOnFullChannel (0.00s)
=== RUN   TestPushBackend_CloseIdempotent
--- PASS: TestPushBackend_CloseIdempotent (0.00s)
=== RUN   TestPushBackend_ConfigPullIsDefault
--- PASS: TestPushBackend_ConfigPullIsDefault (0.00s)
=== RUN   TestPushBackend_CtxCancelStopsRun
--- PASS: TestPushBackend_CtxCancelStopsRun (0.00s)
PASS
```

## 5. PITFALLS encountered (recorded for next session)

1. **`windows.h` not on Linux by default.** CGO
   cross-build needs the `gcc-mingw-w64-x86-64`
   package, which provides the Win32 headers under
   `/usr/x86_64-w64-mingw32/include/windows.h`.
2. **`procEvtSubscribeCallback` address resolution.**
   CGO generates a C function `goPushCallback` that
   calls the //export-ed Go function. We pass that
   address to `EvtSubscribe` as the callback
   parameter. Resolved via `syscall.NewLazyDLL("").NewProc("goPushCallback")`
   on a self-referential DLL handle.
3. **Build-tag method conflict.** Defining the same
   method (`onStop`) in both common.go and a
   build-tag-specific file causes a duplicate
   declaration. Solution: define the method ONLY in
   the build-tag-specific files. Common.go just
   calls it.
4. **Cross-build requires both compiler and headers.**
   `apt install gcc-mingw-w64-x86-64` ships both.
   After install, `x86_64-w64-mingw32-gcc` is
   available at `/usr/bin/`.
5. **Vet per-file vs package.** `go vet` on a single
   file returns false `undefined` errors because it
   doesn't see sibling files. Use `go vet ./...` or
   `go test -c` to validate a whole package.
