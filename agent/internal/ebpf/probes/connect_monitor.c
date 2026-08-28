// SPDX-License-Identifier: GPL-2.0
//
// connect_monitor.c — ZaqorinCore v1.1 eBPF probe
// (ADR-006). Attached to tracepoint/syscalls/sys_enter_connect.
//
// Captures: pid, uid, dst_ip (v4 or v6, 16 bytes packed),
// dst_port. One event per connect(2) call. Pushed to the
// shared "events" ring buffer.
//
// Why connect? C2 callback (ATT&CK T1071) and lateral movement
// (T1021) both begin with a TCP connect(2) to a non-local
// address. Catching this at the syscall layer catches:
//   - short-lived C2 clients that never log
//   - "fileless" reverse shells over a raw socket
//   - cross-host pivots that have no log trail at the
//     application layer
// The classic tell is a connect to a high port (4444, 5555,
// 31337) from a process that's not a long-running server.

#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/socket.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    // 1st arg: int fd. 2nd arg: const struct sockaddr __user *addr.
    // 3rd arg: addrlen.
    struct sockaddr_in6 sa = {};
    bpf_probe_read(&sa, sizeof(sa), (void *)ctx->args[1]);

    // We only care about AF_INET (2) and AF_INET6 (10).
    if (sa.sin6_family != AF_INET && sa.sin6_family != AF_INET6) {
        return 0;
    }

    struct bpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->hdr.tag = ZAQORIN_TAG_CONNECT;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hdr.pad = 0;
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    // Zero the body so unused bytes don't leak stack data.
    __builtin_memset(&e->body.connect, 0, sizeof(e->body.connect));

    if (sa.sin6_family == AF_INET) {
        // sockaddr_in is a strict prefix of sockaddr_in6 with
        // sin6_family/sin6_port/sin6_addr matching the first
        // 8 + 4 = 12 bytes. We copy the v4 address into the
        // first 4 bytes of the 16-byte buffer.
        struct sockaddr_in s4 = {};
        bpf_probe_read(&s4, sizeof(s4), (void *)ctx->args[1]);
        __builtin_memcpy(e->body.connect.dst_ip, &s4.sin_addr.s_addr, 4);
        e->body.connect.dst_port = s4.sin_port;
        e->body.connect.is_v6 = 0;
    } else {
        __builtin_memcpy(e->body.connect.dst_ip, &sa.sin6_addr, 16);
        e->body.connect.dst_port = sa.sin6_port;
        e->body.connect.is_v6 = 1;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
