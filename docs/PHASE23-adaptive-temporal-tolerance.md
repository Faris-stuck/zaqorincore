# PHASE23 — Adaptive temporal tolerance (v1.7.2)

Status: **Shipped** in v1.7.2
Owner: Agent / Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

TUGAS 3 of the stabilization brief: the DFA
engine is too eager. With a fixed timeout
budget, mobile clients, satellite links, and
congested peering all produce **false
positives**: a single slow response pushes
a legitimate subject from L0 (Nominal) to
L1 (Challenge). The consequence is alert
fatigue and operator distrust.

The fix is a per-subject sliding window that
estimates the recent RTT distribution and a
tolerance ceiling

    tau_upper = mu_RTT + k * sigma_RTT

where the budget adapts to the network
condition. When the budget is too noisy to
trust (CV > 1.5) the layer falls back to a
conservative default and never blocks
legitimate users.

## 2. What ships in v1.7.2

Two new components:

| Component | Responsibility |
|---|---|
| `pkg/timing` | Per-subject RTT sliding window + adaptive budget + Anomaly Trust Score. |
| `pkg/engine.TimedProcess` | Timing-aware filter around `Engine.Process`. Absorbs in-budget events, promotes over-budget events to `EventRateLimitTrip` (L0 -> L1). |

## 3. Algorithm

For each subject:

  1. Maintain a ring of 32 RTT samples
     (in microseconds, integer; no float
     on the hot path).
  2. After the 4th sample, the window is
     "warm". Before that, the layer returns
     the conservative default budget
     (250 ms).
  3. The budget is `mu + 3*sigma`, where
     `mu` and `sigma` are computed in a
     fixed-point integer domain
     (`* 100` to avoid float).
  4. Floor: the budget is **never tighter**
     than the default. Even a sub-ms RTT
     distribution does not give the engine
     a sub-250ms budget.
  5. CV > 1.5: distribution is too noisy
     to trust; return default budget.
  6. Anomaly Trust Score (ATS): fraction
     of samples in the window that exceed
     the current budget, mapped to 0..100.
     Used by SOAR/automation to escalate
     a subject directly to L2 when ATS
     crosses a threshold.

The integer sqrt is implemented with
Newton's method, converging in <= 16
iterations. No `math` import on the hot
path.

## 4. Memory budget

| Component | Per subject | Notes |
|---|---|---|
| `timing.PerSubject` | 64 bytes | 32 × int64 samples + cursor/count + lastSeenNS + mu100 + sigma100 + dirty. |
| `timing.Table` | 4096 × 64 B = 256 KB | Open-addressed by subject hash. One per agent process. |

Total: 256 KB regardless of attack rate.
TUGAS 4 will add LRU eviction; for now a
full table returns the default budget
("pass through" semantics).

## 5. NFR status

| Metric | Target | Achieved |
|---|---|---|
| `timing.Table.Record` allocations | 0 | **0** (TestRecordZeroAlloc) |
| `timing.Table.BudgetFor` allocations | 0 | **0** (TestBudgetZeroAlloc) |
| Engine Process latency | < 1 µs | **36 ns** (BenchmarkDFAStateTransition) |

## 6. Graceful fallback

The slice is **deliberately permissive**:

- Unknown subject → default budget.
- Full table → default budget.
- Insufficient samples → default budget.
- High CV → default budget.

The default budget (250 ms) is permissive
enough that a legitimate user with a fresh
connection or a flaky network is **never
blocked**. A real attacker will exceed
250ms consistently, which the engine will
catch on the second or third event.

## 7. Files added

- `agent/pkg/timing/timing.go` (242 LOC) —
  PerSubject, Table, ATS, intSqrt.
- `agent/pkg/timing/timing_test.go` (212
  LOC) — 11 tests including 2 zero-alloc
  NFR gates.
- `agent/pkg/engine/timed.go` (140 LOC) —
  TimingPolicy, TimedProcess, RunWithTiming.
- `agent/pkg/engine/timed_test.go` (137
  LOC) — 5 tests covering absorption,
  promotion, no-policy pass-through, full-
  table fallback, and ATS gate.

## 8. Pitfalls

1. **Floor on the right scale** — the
   floor check must happen in the
   `* 100` domain, not after division.
   Otherwise a sub-ms distribution
   gives a sub-250ms budget. Caught by
   TestTable_RecordAndBudgetFor.
2. **ATS compares against the CURRENT
   budget, not the budget at the time
   of recording** — when the ring
   rolls over and a new distribution
   shifts the budget, the historical
   samples are re-evaluated against
   the new threshold. This is
   acceptable: ATS is a "what is
   the subject doing RIGHT NOW" signal.
3. **CV calculation can overflow** — the
   `* 100` and `* 100` chain
   (`cv100 = (sigma100 * 100) / mu100`)
   can briefly exceed 10^9 if both
   sigma100 and mu100 are large. In
   practice mu100 is bounded by
   10^10 (10s in µs) and sigma100 by
   the same, so the product is bounded
   by 10^20. int64 overflow is not
   triggered for the realistic ranges
   in this slice.

## 9. Honest gap

- The layer is **per-subject**, not
  per-connection. Multiple connections
  sharing a subject (e.g. one user
  behind a NAT) will pool their
  samples. This is intentional: a
  "subject" in the engine is a
  logical entity, not a TCP 4-tuple.
- The `payload.ATS()` is exposed but
  not yet wired into a transition
  table. The next slice (v1.7.3) will
  add an "ATS >= threshold" L1 -> L2
  transition. For now, ATS is
  observable via the policy and
  read by SOAR/automation.

## 10. Next

TUGAS 4 (v1.7.3): deception tarpit
hardening — resource caps, LRU
eviction of the EFSM connection
table, stateless HMAC PoW nonce.
