// SPDX-License-Identifier: GPL-2.0
//
// execve_monitor.c — ZaqorinCore v1.1 eBPF probe
// (ADR-006). Attached to tracepoint/syscalls/sys_enter_execve.
//
// Captures: pid, uid, comm, argv[0..3] (each up to 256 bytes
// truncated). One event per exec call, pushed to the shared
// "events" ring buffer.
//
// Why execve? ATT&CK T1059 (Command and Scripting Interpreter)
// is the single most common attacker primitive. Catching every
// exec at the kernel boundary — even for sub-200ms processes
// that never make it into any log file — is the primary
// detection win the v1.0.0 file-tail agent cannot deliver.

#include "common.h"
#include <bpf/bpf_helpers.h>

// Ring buffer map. Populated by every probe in this directory;
// the Go loader reads from the same FD.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);  // 256 KiB, matches v1.1.0 default
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    // bpf_event + body lives on the BPF stack.
    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;  // ring full; drop. The loader logs drop counts.
    }

    e->hdr.tag = ZAQORIN_TAG_EXECVE;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hdr.pad = 0;
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    // Read the argv pointer (second arg to sys_execve).
    const char *const *argv = (const char *const *)ctx->args[1];

    // Copy up to 4 argv entries. The BPF verifier requires
    // bounded loops with a known trip count; we unroll.
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        const char *p = NULL;
        int rc = bpf_probe_read(&p, sizeof(p), &argv[i]);
        if (rc != 0 || !p) {
            continue;
        }
        char *dst = NULL;
        switch (i) {
            case 0: dst = e->body.execve.argv0; break;
            case 1: dst = e->body.execve.argv1; break;
            case 2: dst = e->body.execve.argv2; break;
            case 3: dst = e->body.execve.argv3; break;
        }
        if (dst) {
            bpf_probe_read_str(dst, ZAQORIN_BPF_STR_MAX, p);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
