# PHASE21 — DFA engine, mock layer, and CI hardening (v1.7.0)

Status: **Shipped** in v1.7.0
Owner: Agent / Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

The original CI was a single "go test -race" job
that failed at the **2-3 second mark** because:

- (a) the eBPF integration test (`internal/ebpf`)
  needs CAP_SYS_ADMIN and a real kernel probe to
  even parse correctly. On hosted runners
  without CAP_SYS_ADMIN, the test would silently
  hang or fail.
- (b) there was no interface between the kernel
  driver and the user-space engine, so the engine
  could not be unit-tested at all.
- (c) there was no NFR gate. The engine could
  regress to 1000 transitions/sec silently and
  no CI step would catch it.

v1.7.0 fixes all three.

## 2. What ships in v1.7.0

### 2.1 Deterministic state engine — `pkg/engine/`

A 4-state DFA covering the L0→L1→L2→L3
progression:

```
        canaryTouch        challengeFail
Nominal ───────────► Challenge ───────────► Deception
   ▲                    │                      │
   │                    │   canaryTouch/CFIExit│
   └───── no transition ─┘                      ▼
                                       Containment (terminal)
```

- **Status** = `uint8` enum: `Nominal`,
  `Challenge`, `Deception`, `Containment`.
  Ordered so numeric comparisons work.
- **Event** = 24-byte value type, no pointers,
  no slices. Designed for the kernel->user
  zero-copy handoff.
- **Engine** = fixed-size transition table
  (`[4 * 16]transitionFn`) indexed by
  `(state, eventKind)`. Hot path is one table
  load + one function call + one store write.
- **`Engine.Process(ev)`** is the hot path.
  0 B/op, 0 allocs/op, 27 ns/op (SameSubject)
  / 37 ns/op (rotating) on a Xeon 8255C.
- **`Engine.Run(ctx, src)`** drives the engine
  from any `EventSource`. Uses `sync.Pool` for
  the read scratch buffer.
- **Containment is terminal** — no event moves
  a subject out of `StatusContainment` until
  an operator manually resets the StateStore.

### 2.2 Mock layer — `internal/mock/`

Three mocks, all concurrency-safe, all
hermetic:

- **`BPFDriverMock`** — implements
  `BPFDriver`. `PushEvent`/`PushBatch` enqueue,
  `Read(dst)` blocks until data is available or
  Close. No ring buffer, no kernel — just a
  mutex + cond.
- **`NetworkStreamMock`** — implements
  `NetworkStream`. Same pattern, L3/L4 packet
  shape. Convenience method `PushTCP(...)` for
  tests.
- **`CanaryStoreMock`** — implements
  `CanaryStore`. `Touch` returns true on first
  touch, false on subsequent touches (the
  signal the engine uses for the L0→L1
  transition).

### 2.3 CI split — `.github/workflows/ci.yml`

Four jobs, ordered, with explicit NFR gates:

1. **unit** (Go 1.22 + 1.23 matrix)
   - `go mod verify`
   - `go vet ./...`
   - `go test -race -count=1 -short -timeout=180s ./...`
     (`-short` skips tests gated by the
     `integration` build tag — those need
     CAP_SYS_ADMIN)
   - Coverage profile uploaded as artifact
2. **bench** (after unit, NFR gate)
   - Runs `BenchmarkDFAStateTransition`
   - **Fails the job** if the output contains
     `[1-9][0-9]* allocs/op` — the
     deterministic 0-alloc NFR
3. **build** (after unit)
   - `make build`
   - Asserts `bin/zaqorin-agent` ≤ 15 MB
4. **smoke** (after build)
   - WebSocket end-to-end via websocat
5. **integration** (only on main pushes, not PRs)
   - `-tags integration` to opt in
   - `linux-tools-generic` + sudo for eBPF
   - Non-fatal: warning on failure (hosted
     runners often lack the right kernel)

## 3. Verification

```
$ go test -race -count=1 -short ./...
ok  all packages

$ go test -bench=BenchmarkDFAStateTransition \
    -benchmem -benchtime=1s -run=^$ ./pkg/engine/
BenchmarkDFAStateTransition-2               16,651,309   37.42 ns/op   0 B/op   0 allocs/op
BenchmarkDFAStateTransition_SameSubject-2   21,819,103   27.99 ns/op   0 B/op   0 allocs/op
```

26M transitions/sec sustained, 0 heap
allocations, deterministic.

## 4. PITFALLS (recorded for next session)

1. **`Status` is a typed `uint8`** — table
   index arithmetic needs explicit `uint8(cur) * 16`.
2. **Engine is explicitly single-caller**;
   the StateStore is what needs to be
   concurrency-safe, not the engine. Tests
   that called `e.Process(...)` from
   multiple goroutines in parallel failed
   because the engine owns the alert sink.
   Replaced with a StateStore-only
   concurrency test.
3. **`errEOF` sentinel** must be in the same
   package as the mock to avoid `undefined`
   errors at `go vet`.
4. **`-short` flag** must be honored by tests
   that need `integration` tag. The CI
   `unit` job uses `-short` so that the eBPF
   tests don't try to load a real kernel
   probe.
5. **`go tool cover -func=coverage.out`**
   gives one-line coverage stats; the
   per-function breakdown is in the file
   itself.
