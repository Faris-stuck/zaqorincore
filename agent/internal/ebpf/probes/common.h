// SPDX-License-Identifier: GPL-2.0
//
// common.h — shared ring buffer event layout for all ZaqorinCore
// eBPF probes (v1.1, see ADR-006).
//
// All probes push a `bpf_event` to a single
// BPF_MAP_TYPE_RINGBUF map named "events". The Go loader
// (agent/internal/ebpf/loader.go) reads them out and emits
// them on the wire with a source prefix derived from the
// probe name (e.g. "ebpf/execve").
//
// LAYOUT INVARIANT: this struct's binary layout MUST match
// the `bpfEvent` Go struct in loader.go byte-for-byte. If you
// change a field here, change it there too.
//
// BPF programs that load this file are derivative works of
// the Linux kernel's BPF runtime; the kernel is GPL-2.0. We
// therefore license the C sources in this directory under
// GPL-2.0 to remain compatible. The Go loader is MIT (see
// LICENSE at the repo root).

#ifndef ZAQORIN_BPF_COMMON_H
#define ZAQORIN_BPF_COMMON_H

// Max length of a captured string field. 256 bytes is enough
// for argv[0] (PATH_MAX-trimmed) and absolute path names
// without bloating the ring buffer.
#define ZAQORIN_BPF_STR_MAX 256

// Common header prepended to every event. The probe name
// ("execve", "openat", "connect", "ptrace", "setuid") is
// stored as a short ASCII tag so the userspace loader can
// stamp the wire source without a separate map.
typedef struct {
    __u32 tag;       // 4 ASCII bytes identifying the probe
    __u32 pid;       // tgid of the calling task
    __u32 uid;       // real uid (KUID -> u32 in BPF context)
    __u32 pad;       // explicit padding so the body is 8-byte aligned
    char  comm[16];  // current->comm (truncated)
} bpf_event_hdr;

// Per-probe event types. `bpf_event_hdr` is the universal
// prefix; the body below is probe-specific.
//
// All bodies are flat C structs (no pointers, no unions of
// variable length) so the Go binary.Read decoder is trivial.

struct execve_event {
    char argv0[ZAQORIN_BPF_STR_MAX];
    char argv1[ZAQORIN_BPF_STR_MAX];
    char argv2[ZAQORIN_BPF_STR_MAX];
    char argv3[ZAQORIN_BPF_STR_MAX];
};

struct openat_event {
    char filename[ZAQORIN_BPF_STR_MAX];
};

struct connect_event {
    __u8  dst_ip[16];   // v4 stored as-is; v6 in full
    __u32 dst_port;     // network byte order
    __u8  is_v6;        // 0 = ipv4, 1 = ipv6
    __u8  _pad[3];
};

struct ptrace_event {
    __u32 target_pid;
    __u32 request;
};

struct setuid_event {
    __u32 new_uid;
};

// Top-level event published on the ring buffer. The `hdr`
// discriminates which `body` field is populated; the Go
// decoder uses `hdr.tag` to pick the right layout.
typedef struct {
    bpf_event_hdr hdr;
    union {
        struct execve_event  execve;
        struct openat_event  openat;
        struct connect_event connect;
        struct ptrace_event  ptrace;
        struct setuid_event  setuid;
    } body;
} bpf_event;

// Probe tag constants. The Go loader has an identical table.
#define ZAQORIN_TAG_EXECVE  0x78656500  // "xee\0"
#define ZAQORIN_TAG_OPENAT  0x786f6600  // "xof\0"
#define ZAQORIN_TAG_CONNECT 0x78636e00  // "xcn\0"
#define ZAQORIN_TAG_PTRACE  0x78707400  // "xpt\0"
#define ZAQORIN_TAG_SETUID  0x78737500  // "xsu\0"

#endif // ZAQORIN_BPF_COMMON_H
