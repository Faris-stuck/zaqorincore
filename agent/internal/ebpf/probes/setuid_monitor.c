// SPDX-License-Identifier: GPL-2.0
//
// setuid_monitor.c — ZaqorinCore v1.1 eBPF probe
// (ADR-006). Attached to tracepoint/syscalls/sys_enter_setuid.
//
// Captures: pid, uid, new_uid. One event per setuid(2) call.
// Pushed to the shared "events" ring buffer.
//
// Why setuid? ATT&CK T1548.001 (Setuid and Setgid) is the
// classic Linux local privilege escalation primitive. A
// process transitioning from a non-root uid to uid 0
// almost always indicates a privilege escalation, especially
// if the caller is not a known root-holding daemon (sudo,
// pkexec, su, etc.).

#include "common.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->hdr.tag = ZAQORIN_TAG_SETUID;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hdr.pad = 0;
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    e->body.setuid.new_uid = (__u32)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
