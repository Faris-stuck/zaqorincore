// SPDX-License-Identifier: GPL-2.0
//
// openat_monitor.c — ZaqorinCore v1.1 eBPF probe
// (ADR-006). Attached to tracepoint/syscalls/sys_enter_openat.
//
// Captures: pid, uid, filename (up to 256 bytes truncated).
// One event per openat(2) call. Pushed to the shared "events"
// ring buffer.
//
// Why openat? ATT&CK T1003 (OS Credential Dumping) and T1552
// (Unsecured Credentials) almost always touch a sensitive
// file. The classic indicators are reads of:
//   /etc/shadow
//   ~/.ssh/id_rsa
//   /proc/*/mem (process memory of other PIDs)
// File-tail cannot see these — the file is read by a process
// via syscall, never written to a log.

#include "common.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->hdr.tag = ZAQORIN_TAG_OPENAT;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hdr.pad = 0;
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    // 2nd arg of sys_openat is the pathname pointer.
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_str(e->body.openat.filename,
                       ZAQORIN_BPF_STR_MAX, pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
