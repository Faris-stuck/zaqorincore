// SPDX-License-Identifier: GPL-2.0
//
// ptrace_monitor.c — ZaqorinCore v1.1 eBPF probe
// (ADR-006). Attached to tracepoint/syscalls/sys_enter_ptrace.
//
// Captures: pid, target_pid, request. One event per ptrace(2)
// call. Pushed to the shared "events" ring buffer.
//
// Why ptrace? ATT&CK T1055 (Process Injection) and T1003
// (OS Credential Dumping) frequently piggy-back on ptrace to
// attach to a victim process and read its memory. The classic
// indicator is ptrace targeting a privileged daemon (sshd,
// ssh-agent, lsass on Linux: a process holding in-memory
// credentials).

#include "common.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    // ptrace args (from man ptrace): request, pid, addr, data.
    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->hdr.tag = ZAQORIN_TAG_PTRACE;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hdr.pad = 0;
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    e->body.ptrace.request  = (__u32)ctx->args[0];
    e->body.ptrace.target_pid = (__u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
