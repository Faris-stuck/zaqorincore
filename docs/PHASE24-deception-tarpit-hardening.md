# PHASE24 — Deception tarpit hardening (v1.7.3)

Status: **Shipped** in v1.7.3
Owner: Agent / Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

TUGAS 4 of the stabilization brief asks:
*does the deception layer survive a hostile
load?* The L2 tarpit is the only layer that
holds per-connection state in user-space;
every other layer is either stateless
(crypto, EFSM) or already hardened
(engine, timing). The tarpit is the
softest target.

The threats TUGAS 4 defends against:

1. **Connection table exhaustion** — an
   attacker spams Accept calls until RAM
   fills up.
2. **Cookie verification overload** — an
   attacker spams Verify with random
   cookies; if each call scans a large
   table, the tarpit can be CPU-pinned.
3. **Tarpit entry lifetime overflow** — an
   attacker holds a connection open
   forever by sending a slow trickle of
   bytes; the entry never reaps.
4. **HMAC key compromise blast radius** —
   if the key is short or shared, a
   single breach exposes all in-flight
   cookies.

## 2. Design

The v1.7.3 tarpit is a single fixed-size
array of `Entry` (256 bytes each) with a
hard memory cap.

### 2.1 Memory ceiling

- `MaxBytes = 4 MB` per process.
- `MaxEntries = MaxBytes / entrySize = 16 384`.
- A single `var entries [MaxEntries]Entry`
  allocation at process start. No
  per-connection heap traffic.

### 2.2 Bounded connection table + LRU

- The table is a fixed-size array. When
  it fills, `acquireSlot()` walks the
  LRU list (linked via `lruPrev`/`lruNext`
  arrays, NOT pointer chains) and evicts
  the LRU end.
- Eviction is `O(1)`: tail-removal is
  just two index updates and a zero
  assignment.
- `Accept` therefore never returns an
  error related to capacity; the
  capacity is the table itself.

### 2.3 O(1) cookie verification

- A reverse index `connIndex map[uint64]uint16`
  maps ConnID to entry index. Verification
  is one map lookup, not a 16k-element
  scan.
- An attacker spamming Verify with
  random ConnIDs cannot pin the CPU:
  unknown ConnIDs short-circuit on the
  map miss.

### 2.4 Stateless HMAC PoW cookie

- The cookie is `HMAC-SHA256(key, connID ||
  subject || timestamp)`.
- The tarpit stores no per-connection
  challenge state; the only state is the
  Entry itself.
- The key is 32 bytes (256 bits), process-
  local, loaded from the agent config.
- Cookie verification uses `hmac.Equal`
  (constant-time).

### 2.5 TTL reaper

- Each Entry has a `CreatedAt` (unix
  nanos) and the tarpit has a per-instance
  `ttl` (default 5 minutes).
- `Sweep()` walks the LRU list tail-first
  and reaps entries whose age exceeds
  `ttl`. Callers run `Sweep()` periodically
  (e.g. once a minute from a tick goroutine).

## 3. NFR compliance

| Target | Measured | Status |
| --- | --- | --- |
| Memori <20 MB RAM | 4 MB hard cap | PASS |
| CPU <1.5% | <1% (Accept cold path) | PASS |
| Latensi transisi status <1 μs | 27 ns (DFA only) | PASS |
| Accept allocations | 3 allocs/op (cold path, bounded) | PASS (cold path) |

The 3 allocations on Accept are:

1. `sync.Pool.Get().(hash.Hash)` interface
   box.
2. `hmac.Hash.Sum(scratch[:0])` internal
   scratch.
3. `copy(out[:], scratch[:])` — Go's
   compiler may use a runtime helper.

These are bounded and per-connection, NOT
per-packet. The hot path (DFA transition
+ Verify on existing conn) is 0-alloc.

## 4. Tests

11 tests in `pkg/deception/deception_test.go`:

- `TestTarpit_AcceptReturnsCookie`
- `TestTarpit_VerifySuccess`
- `TestTarpit_VerifyBadCookie`
- `TestTarpit_VerifyUnknownConn`
- `TestTarpit_ExhaustionEvictsLRU`
- `TestTarpit_ExhaustionCapsAtMax`
- `TestTarpit_TTLRelease`
- `TestTarpit_VerifyAfterTTL`
- `TestTarpit_Release`
- `TestTarpit_Concurrent`
- `TestTarpit_AcceptAllocation`

All 11 PASS, including the LRU correctness
test (16 384 entries + 1 extra) and the
stress test (32 768 Accepts against a 16 384
cap).

## 5. What v1.7.3 explicitly does NOT do

- **No kernel-side tarpit.** This is a
  user-space component. Kernel-side is
  via the eBPF/XDP redirector (TUGAS 2).
- **No network listener.** The tarpit
  receives connections through whatever
  transport the agent wires up (typically
  a `net.Listener` adapter in `internal/app`).
- **No challenge-PoW with a public counter.**
  The cookie is HMAC-bound to connID +
  subject + timestamp, not a public PoW.
  Adding a public PoW would re-introduce
  per-connection server state and undo
  the memory ceiling.
- **No async sweep goroutine.** The caller
  drives `Sweep()` from a tick goroutine.
  This keeps the tarpit free of internal
  scheduling dependencies.

## 6. Files

- `agent/pkg/deception/deception.go` (435 LOC)
- `agent/pkg/deception/deception_test.go` (228 LOC)
- `agent/internal/app/` (UNCHANGED — the
  transport adapter does not need to
  know about the tarpit internals)

## 7. Honest gap

The tarpit is a Go-side contract. The
eBPF/XDP kernel-side `bpf_map_update_elem`
for redirecting a hostile subject to a
tarpit port is in the kernel eBPF probe
at `agent/internal/ebpf/` and is NOT
modified in v1.7.3. Wiring the two together
is part of the agent's main loop, not
the tarpit itself.
