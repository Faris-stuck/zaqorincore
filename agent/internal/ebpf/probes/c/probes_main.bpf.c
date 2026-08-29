// SPDX-License-Identifier: GPL-2.0
//
// probes_main.bpf.c — ZaqorinCore v1.1 eBPF combined probe
// (ADR-006). The single BPF object that the Go loader
// loads. The five per-syscall monitor files
// (execve_monitor.c, openat_monitor.c, connect_monitor.c,
// ptrace_monitor.c, setuid_monitor.c) are #included here
// so they all share the same "events" ring buffer map
// and the same license declaration.
//
// Source layout note: this file lives in ./c/ so that the
// Go toolchain does not try to compile it as a regular Go
// source. bpf2go (via `make ebpf`) is invoked with the
// path to this file; the generated .o is placed in
// ./obj/ by bpf2go's -output-dir flag.
//
// Why one combined object (not five separate)?
// 1. All five probes push to the same ring buffer map. The
//    BPF loader requires map definitions to be in a single
//    object when programs are attached to the same map FD.
//    Splitting them would either need five separate rings
//    (waste, more syscalls) or a pinned shared map (extra
//    filesystem surface).
// 2. The kernel BPF verifier runs once per ELF, not per
//    source file. One ELF = one verifier pass, regardless
//    of how many SEC() entries it contains.
// 3. The Go side loads one collection, iterates the
//    programs map, and attaches each program. bpf2go
//    generates a typed programs struct with one method
//    per SEC() — same ergonomics, less code.

#include "common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Shared ring buffer map. Populated by every probe in this
// file; the Go loader (loader.go) reads from the same FD.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);  // 256 KiB
} events SEC(".maps");

// Per-probe monitor implementations. Each file declares one
// SEC("tracepoint/...") handler that pushes one bpf_event to
// the shared ring buffer.
#include "execve_monitor.c"
#include "openat_monitor.c"
#include "connect_monitor.c"
#include "ptrace_monitor.c"
#include "setuid_monitor.c"

char _license[] SEC("license") = "GPL";
