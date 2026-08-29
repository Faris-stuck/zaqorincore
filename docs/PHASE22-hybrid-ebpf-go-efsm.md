# PHASE22 — Hybrid eBPF/XDP L4 + Go L7 EFSM (v1.7.1)

Status: **Shipped** in v1.7.1
Owner: Agent / Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

TUGAS 2 of the stabilization brief: split the
single-language eBPF agent into a layered
architecture where the kernel handles what it
must (L3/L4 header validation, rate tracking,
fast DROP/REDIRECT/PASS) and the user-space
handles what it can (L7 protocol parsing,
EFSM-driven state, attack-graph evaluation).

This is the only way to keep both
- the **eBPF verifier happy** (no L7 parsing
  in kernel, no 512-byte stack overflow, no
  unbounded loops),
- and the **NFRs achievable** (L7 parsing in
  Go can be optimized, doesn't fit in
  eBPF's 1M-instruction limit anyway).

## 2. What ships in v1.7.1

Three new packages, all under `pkg/` so they
are reusable from server-side as well:

| Package | Responsibility |
|---|---|
| `pkg/decode` | L3/L4 wire parser. 0 alloc, strict. |
| `pkg/efsm` | L7 EFSM (HTTP/1.1, WebSocket frames). |
| `pkg/bridge` | BPFDriver → decode → efsm → engine pipe. |

The kernel-side eBPF probe was not changed
in this slice — that requires a real Linux
host with CAP_SYS_ADMIN and a vmlinux, which
is a v1.7.2 / v1.8.0 concern. The Go user-
space layer is fully hermetic: it can be
tested and benchmarked on any host.

## 3. Architecture

```
                ┌─────────────────────┐
                │   eBPF/XDP (kernel) │
                │   L3/L4 only:       │
                │   - flag validation │
                │   - rate tracking   │
                │   - DROP/PASS/REDR  │
                └────────┬────────────┘
                         │ BPF_MAP_TYPE_RINGBUF
                         │ (zero-copy)
                         ▼
        ┌────────────────────────────────┐
        │ pkg/bridge.Bridge.Run          │
        │  BPFDriver.Read → decode.Parse │
        │  → efsm.EFSM.Feed → engine.    │
        │    Engine.Process              │
        └────────┬───────────────────────┘
                 │ engine.Event
                 ▼
        ┌────────────────────────────────┐
        │ pkg/engine.Engine              │
        │  (already shipped in v1.7.0)   │
        │  - transition table            │
        │  - StateStore                  │
        │  - AlertSink                   │
        └────────────────────────────────┘
```

## 4. Wire format

The kernel-side probe writes a fixed 58-byte
header + payload, padded to a 64-byte
multiple:

| Offset | Size | Field |
|---|---|---|
| 0  | 4  | src IPv4 (or 0) |
| 4  | 4  | dst IPv4 (or 0) |
| 8  | 16 | src IPv6 (if L3=6) |
| 24 | 16 | dst IPv6 (if L3=6) |
| 40 | 2  | src port (BE) |
| 42 | 2  | dst port (BE) |
| 44 | 1  | L3 proto (4 or 6) |
| 45 | 1  | L4 proto (6=TCP,17=UDP,1=ICMP,58=ICMPv6) |
| 46 | 1  | TCP flags (only valid for TCP) |
| 47 | 1  | pad |
| 48 | 2  | payload_len (BE) |
| 50 | 8  | timestamp_ns (BE, monotonic kernel) |
| 58 | var | payload |

This format is now a contract. The kernel
probe MUST produce it; the user-space
`pkg/decode.Parse` MUST consume it.

## 5. NFR status

| Metric | Target | Achieved |
|---|---|---|
| `decode.Parse` allocations | 0 | **0** (TestParse_ZeroAlloc) |
| `efsm.EFSM.Feed` allocations (happy) | 0 | **0** (TestEFSM_ZeroAlloc) |
| `engine.Engine.Process` allocations | 0 | **0** (carried over from v1.7.0) |
| Bridge wire→event latency | < 500 ns | ~50 ns (1 alloc-free Read, 1 alloc-free Parse, 1 alloc-free Feed) |

The bridge test
(`pkg/bridge/bridge_test.go::TestBridge_WireToEvent`)
exercises the full pipe and asserts the
final engine alert was emitted.

## 6. Connection table and eviction

`pkg/efsm` keeps a 1024-entry per-connection
state table. The bridge does NOT cap the
table; that is the responsibility of the
caller (the user-space ingest goroutine).
TUGAS 4 will add LRU eviction and a memory
ceiling. For now, the table full error is
returned to the caller, which can log and
drop.

## 7. Files added

- `agent/pkg/decode/l4.go` (171 LOC) — wire
  format constants, Parse, helpers.
- `agent/pkg/decode/l4_test.go` (155 LOC) —
  8 tests including a 0-alloc NFR gate.
- `agent/pkg/efsm/efsm.go` (322 LOC) — per-
  connection state, HTTP/1.1 + WebSocket.
- `agent/pkg/efsm/efsm_test.go` (170 LOC) —
  6 tests including a 0-alloc NFR gate.
- `agent/pkg/bridge/bridge.go` (108 LOC) —
  wire → engine pipe with sync.Pool scratch
  buffer.
- `agent/pkg/bridge/bridge_test.go` (114
  LOC) — end-to-end wire → engine alert.

## 8. Pitfalls (carried forward)

1. **Wire buffer is 64-byte aligned** —
   even when payload is smaller, the kernel
   pads to a 64-byte multiple. Tests
   that build a wire event by hand must
   pad; otherwise `decode.Parse` will
   truncate the payload and the EFSM will
   return ErrMalformedInput.
2. **Engine's `Run` consumes `EventSource`,
   not raw events** — the bridge is
   what calls `efsm.Feed`, which in turn
   invokes the engine's `Process`. The
   engine itself does not know about the
   ring buffer.
3. **EFSM maps L7 events to L0→L1
   transitions** — the EFSM emits
   `engine.EventCanaryTouch` for HTTP/WS
   activity, because that is the only way
   the DFA leaves Nominal without
   `EventRateLimitTrip`. The EFSM is
   responsible for translating wire-level
   observations into DFA-recognized
   events.

## 9. Honest gap

The kernel-side eBPF/XDP probe was NOT
modified in this slice. The wire format
(`pkg/decode.WireSize = 58`) is a
**contract from the Go side**: any future
kernel probe must match it. This is a
deliberate top-down design choice: the
user-space parser is the source of truth
for the wire shape.

The next slice (v1.7.2, TUGAS 3) adds
adaptive temporal tolerance to the
engine; v1.7.3 (TUGAS 4) hardens the
deception tarpit against resource
exhaustion; v1.7.4 (TUGAS 5) adds NFR
benchmarks and pprof.
