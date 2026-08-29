# ZaqorinCore v1.1.0 — eBPF Kernel Telemetry (Operator Guide)

**ADR-006** · **PHASE-11**

This document is the deployment reference for the eBPF
backend that ships in ZaqorinCore v1.1.0. It covers the
host requirements, the build path, the runtime fallback
chain, the operational surface, and a troubleshooting
checklist for the most common failure modes.

If you only need the minimum to get started: see
`agent/Makefile` (`make ebpf`) and the one-line loader
contract in `internal/ebpf/ebpf.go` (`NewBackend`).

---

## What the eBPF backend adds

ZaqorinCore v1.0.0 shipped a file-tail backend that reads
auth/syslog/journal entries from disk and ships them to
the server. That is the v1.0.0 default and remains the
fallback in v1.1.0.

v1.1.0 adds a second, kernel-level telemetry source: a
collection of eBPF programs attached to syscall
tracepoints. They capture events that never touch the
log files the file-tail backend watches:

| Probe    | Syscall                | What you see                                     |
| -------- | ---------------------- | ------------------------------------------------ |
| execve   | sys_enter_execve       | every process execution (pid, uid, comm, argv)   |
| openat   | sys_enter_openat       | every file open (path, pid, uid)                 |
| connect  | sys_enter_connect      | every outbound TCP/UDP connect (dst IP, port)    |
| ptrace   | sys_enter_ptrace       | every debugger attach / process inspection       |
| setuid   | sys_enter_setuid       | every privilege escalation attempt               |

All five probes write to a single shared ring buffer
(`events` map, 256 KiB). The Go loader drains the buffer
and converts each record to the same wire Event shape the
file-tail backend produces, so the server, transport,
and detector pipelines do not change.

The five probes plus their shared ring buffer compile
into **one** BPF ELF object. The object is embedded in
the agent binary at build time via `go:embed`; the agent
itself never needs the BPF toolchain at runtime.

---

## Host requirements

The eBPF backend is opt-in. The agent runs without it on
any Linux (or non-Linux) host — `NewBackend` falls back
to the file-tail backend. To activate the eBPF backend
the host must satisfy:

1. **Linux kernel ≥ 5.4**
   `BPF_PROG_TYPE_TRACING` was added in 5.4 and is what
   the five probes use. The runtime loader checks
   `/proc/version` and refuses to initialise on older
   kernels; check the agent log for `ebpf: kernel X.Y <
   5.4`.

2. **CAP_BPF and CAP_PERFMON on the agent process**
   The kernel grants the ability to load BPF programs
   and create perf events to processes that hold both
   capabilities. Two practical ways to get them:

   - **Run the agent as root** in a container. Simplest,
     but you inherit root's full attack surface.
   - **Use `setcap` to grant only the two capabilities**:

     ```bash
     sudo setcap cap_bpf,cap_perfmon=ep /usr/local/bin/zaqorin-agent
     ```

     The capabilities are inherited across `execve` (the
     `e` flag) and are file-scoped (the `p` flag), so
     they do not leak to every process on the host.

3. **BPF and perf_event_open syscalls unblocked**
   Some hardened distros (RHEL 9+, certain GKE/Ubuntu
   Pro configurations) restrict the `bpf()` syscall to
   specific UID ranges or block it via `seccomp`. If the
   loader logs `ebpf: loadAndAssign: permission denied`,
   check the agent's seccomp profile and the kernel
   `kernel.unprivileged_bpf_disabled` sysctl.

---

## Build the BPF objects

The agent is shipped as a Go binary that embeds the
compiled BPF ELF. The ELF is **not** in the public source
repository (regenerating it is part of the release
process, and committing 11 KB of stripped BPF object
would muddy diffs). To produce the embedded object from
the C source:

```bash
cd agent/

# Install the build prereqs (Ubuntu 22.04+ / Debian 12+).
sudo apt-get install -y --no-install-recommends \
    clang libbpf-dev linux-headers-generic

# `make check-prereqs` exits non-zero with install
# instructions for anything missing.
make check-prereqs

# `make ebpf` compiles probes/c/*.c → probes/obj/*.o +
# the bpf2go Go wrapper. Then `make build` links the
# agent binary with the embedded objects.
make ebpf
make build
```

Cross-build for `arm64`:

```bash
make ebpf ARCH=arm64
make build
```

What `make ebpf` does, in order:

1. `check-prereqs` verifies `clang`, `go`, `libbpf-dev`,
   and the kernel-headers package are present.
2. Stashes the hand-maintained `wrapper.go` (the
   bpf2go-emitted Go helpers are package-private; the
   wrapper re-exports the embedded bytes through
   `BpfProbes` / `BpfMaps` types so the rest of the
   agent can use them).
3. Runs bpf2go (`cilium/ebpf/cmd/bpf2go`) on
   `probes/c/probes_main.bpf.c`. The C file
   `#include`s the five per-syscall monitor files and
   the single `events` ring buffer map, so one
   compilation produces one ELF.
4. Restores `wrapper.go` and removes the
   alternate-architecture copies bpf2go may also
   generate (e.g. `_x86_bpfel.go` on x86 hosts — we
   embed only the host target).

---

## Runtime fallback chain

The agent's `NewBackend` constructor is the entry point
for the eBPF backend. It tries the loader in order and
falls back gracefully:

```
   NewBackend(logger, cfg)
        │
        ▼
   NewReal(logger, cfg)
        │  - runtime.GOOS == "linux"?   ──no──▶  NotImplemented
        │  - kernel ≥ 5.4?             ──no──▶  NotImplemented
        │  - rlimit.RemoveMemlock()    warn-only
        │  - bpfobj.LoadObjects()      ──err─▶  NotImplemented
        │  - ringbuf.NewReader         ──err─▶  NotImplemented
        │  - link.Tracepoint(×5)       ──err─▶  NotImplemented
        │
        ▼
   Real (active)
```

If `NewReal` returns a non-empty reason, the agent logs
it once at startup and uses the file-tail backend
unchanged. Operators can grep for the substring
`ebpf: BPF backend unavailable` to see the reason.

Reasons the loader may decline (in order of frequency):

| Reason                              | Fix                                     |
| ----------------------------------- | --------------------------------------- |
| `not linux (GOOS=...)`              | Run on a Linux host                     |
| `kernel X.Y < 5.4`                  | Upgrade the kernel                      |
| `remove memlock rlimit failed`      | Check `/etc/security/limits.conf`       |
| `loadAndAssign: ...`                | Check CAP_BPF, seccomp, sysctl          |
| `open ringbuf: ...`                 | Check `RLIMIT_MEMLOCK`                  |
| `attach execve/openat/...: ...`     | Check `kernel.yama.ptrace_scope` / 5.4+ |
| `no probes selected`                | Operator config filtered every probe    |

---

## Disabling individual probes

`LoadConfig.Probes` is an allowlist of probe names. If
empty, all five ship. To disable a probe (e.g. noisy
`execve` on a chatty host), list the others:

```go
cfg := ebpf.LoadConfig{
    Probes: []string{"openat", "connect", "ptrace", "setuid"},
    AgentID: "host-1",
}
```

Disabled probes are never attached; the kernel never
runs them. The ring buffer and decoder are unaffected
because all probes share the same map.

---

## Verifying the backend on a target host

Three checks, in order:

1. **Build-time** — `make ebpf` and `go test ./internal/ebpf`
   both pass. The `TestCollectionSpecLoads` integration
   test parses the embedded ELF and confirms all five
   programs and the `events` map are present. This is
   what CI runs.

2. **Permissions check** — `sudo setcap cap_bpf,cap_perfmon=ep
   /path/to/zaqorin-agent && getcap /path/to/zaqorin-agent`
   should print `cap_bpf,cap_perfmon=ep`.

3. **Runtime smoke** — start the agent on a host where
   you can run a `execve` (e.g. `ls /tmp`). The agent
   log should show:

   ```
   ebpf: probe attached probe=execve source=ebpf/execve
   ebpf: probe attached probe=openat source=ebpf/openat
   ...
   ebpf: runtime started probes=5
   ```

   Then run `bpftool prog list` (from the `linux-tools-common`
   package) and confirm five `tracepoint` programs are
   loaded by the agent's PID.

---

## Wire shape and detector integration

The eBPF backend produces events with the same
`event.Event` shape the file-tail backend produces. The
only difference is `event.Source`:

| Backend    | Source             |
| ---------- | ------------------ |
| file-tail  | `file:/var/log/auth.log`, etc. |
| eBPF execve| `ebpf/execve`      |
| eBPF openat| `ebpf/openat`      |
| eBPF connect| `ebpf/connect`    |
| eBPF ptrace| `ebpf/ptrace`      |
| eBPF setuid| `ebpf/setuid`      |

Detectors that match on `source == "file:*"` continue
to work. Detectors that want both, or want to match
eBPF-only, can use `source.startswith("ebpf/")` or the
explicit `source == "ebpf/execve"` form.

Metadata fields per probe are documented in
`internal/ebpf/loader.go` (`decode` function). They
mirror the file-tail metadata shape (`pid`, `uid`,
`comm`, plus probe-specific fields like `argv0`,
`filename`, `dst_ip`, `target_pid`, `new_uid`).

---

## Troubleshooting checklist

- **`agent: ebpf: loadAndAssign: failed to load program
  handle_execve: permission denied`**
  The agent does not have CAP_BPF. Re-run `setcap` or
  run the agent as root (not recommended for production).

- **`agent: ebpf: loadAndAssign: failed to load program
  handle_execve: cannot load BTFs`**
  The kernel does not have BTF info. Install
  `linux-modules-extra-$(uname -r)` or
  `linux-image-debug-$(uname -r)`.

- **`agent: ebpf: attach execve: tracepoint not found`**
  The host has `tracefs` not mounted, or the agent is
  running inside a container without `--privileged` (or
  the equivalent `--cap-add SYS_ADMIN` +
  `--security-opt seccomp=unconfined`).

- **`agent: ebpf: open ringbuf: cannot allocate memory`**
  Increase the per-process memlock limit. Edit
  `/etc/security/limits.conf`:
  ```
  zaqorin  hard  memlock  unlimited
  zaqorin  soft  memlock  unlimited
  ```
  Or set the kernel sysctl:
  `sysctl -w vm.unprivileged_userfaultfd=0` (only on
  kernels where memlock cannot be increased).

- **`agent: ebpf: kernel 5.4 < 5.4`** (typo in agent log)
  Yes, this can happen on patched kernels where the
  reported version is below 5.4 even though the BPF
  features are present. The runtime check is strict on
  purpose. Workaround: set `LoadConfig.RingBufferBytes`
  and patch the version check locally.

- **CPU usage spikes on a chatty host**
  The `execve` probe sees every process start. On a
  host that runs thousands of short-lived processes per
  second (build farms, CI runners, busy web servers),
  disable it via `LoadConfig.Probes`.

- **Agent starts but no events reach the server**
  The BPF backend is attached (check `bpftool prog
  list`) but the ring buffer is not being drained. This
  usually means the event dispatcher goroutine is
  blocked. Check the agent log for
  `ebpf: ringbuf read` warnings, and the dispatcher log
  for `queue full` errors.

---

## What v1.1.0 does NOT include (deferred)

- **USDT probes** (user-space statically defined
  tracepoints). Useful for MySQL/Postgres/Nginx
  instrumentation but adds a second bpf2go invocation
  and a second ring buffer. Tracked in ROADMAP.md.
- **USDT-driven library tracepoints** for `libcrypto`
  and `libssl` (visibility into TLS handshake and
  cipher negotiation). Same reason.
- **A WebAssembly / Lua filter layer** to drop
  uninteresting events at the agent. The detector
  pipeline already filters downstream; a per-host
  filter would only help at very high event rates.
- **Per-probe rate limiting.** When the host generates
  more events than the ring buffer can hold, the
  kernel drops records. The decoder already logs
  `dropped` count. Building adaptive rate limits in
  the kernel requires more verifier-friendly code
  and is a v1.2.0 candidate.
- **Windows.** WSL2 kernel supports eBPF but Windows
  hosts do not. The eBPF backend is Linux-only by
  design.

---

## See also

- `agent/internal/ebpf/loader.go` — the runtime loader
  (kernel check, attach loop, ring-buffer drain, decoder)
- `agent/internal/ebpf/probes/c/probes_main.bpf.c` — the
  combined BPF program and its rationale
- `agent/internal/ebpf/ebpf.go` — the `Backend` interface
  and `NewBackend` fallback chain
- `agent/Makefile` — `make ebpf`, `make build`, `make test`
- `agent/internal/ebpf/integration_test.go` — 4
  integration tests (CollectionSpec load, no-kernel
  error path, ring-buffer decoder happy path,
  NotImplemented shutdown)
- `docs/decisions/ADR-006-ebpf-kernel-telemetry.md` —
  the architectural decision
- `CHANGELOG.md` — v1.1.0 release entry
