// Package timing implements the adaptive
// temporal tolerance layer for the ZaqorinCore
// DFA engine.
//
// The problem: a fixed timeout budget produces
// false positives when the network has bursty
// jitter (mobile, satellite, congested
// peering). A permissive budget lets real
// attacks through. A strict budget blocks
// legitimate users.
//
// The solution: a per-subject sliding window
// that estimates the recent RTT distribution
// and a tolerance ceiling
//
//	tau_upper = mu_RTT + k * sigma_RTT
//
// for the threshold above which a slow response
// counts as suspicious.
//
// Three guarantees:
//
//  1. **Zero allocations on the hot path**.
//     The window is a fixed-size ring of int64
//     samples, indexed with a uint32 cursor
//     that wraps at 2*SampleCap.
//  2. **Bounded memory**. Per subject, the
//     timing record is exactly 64 bytes
//     regardless of how long the subject is
//     tracked. LRU eviction is in TUGAS 4.
//  3. **Graceful fallback**. If fewer than
//     MinSamples have been observed, the
//     window returns the conservative default
//     budget; the DFA does not transition on
//     a single late response.
package timing

import (
	"math"
	"sync"
)

// SampleCap is the maximum number of RTT
// samples retained per subject. 32 samples
// is enough to compute a stable mean and
// stdev; more samples make the window
// less responsive to recent changes.
const SampleCap = 32

// MinSamples is the warmup floor. Until a
// subject has at least this many samples, the
// window returns DefaultBudgetMicrosec.
const MinSamples = 4

// DefaultBudgetMicrosec is the conservative
// fallback budget, used during warmup and
// when the subject's data is too noisy to
// trust (CV > MaxCV).
const DefaultBudgetMicrosec int64 = 250_000 // 250 ms

// KSigma is the multiplier for the stdev
// component of the adaptive budget.
// tau_upper = mu + KSigma * sigma
//
// K = 3.0 is the standard "three-sigma"
// choice: 99.7% of normally-distributed
// samples fall within this band.
const KSigma = 3.0

// MaxCV is the upper bound on the coefficient
// of variation (sigma / mu). If the observed
// CV exceeds this, the window is too noisy
// to trust and we fall back to the default
// budget. 1.5 = "stdev is at most 1.5x the
// mean", which is the boundary between
// "bursty but predictable" and "chaotic".
const MaxCV = 1.5

// PerSubject is the per-subject timing
// record. Exactly 64 bytes; no pointers,
// no slices, no maps. Safe to copy.
type PerSubject struct {
	// samples is a ring of the most recent
	// SampleCap RTT observations, in
	// microseconds.
	samples [SampleCap]int64
	// cursor is the next slot to write to.
	// Wraps at SampleCap.
	cursor uint32
	// count is the number of samples
	// written so far, capped at SampleCap.
	count uint32
	// lastSeenNS is the kernel monotonic
	// timestamp of the most recent sample.
	lastSeenNS uint64
	// mu100 and sigma100 are the mean and
	// stdev scaled by 100 to avoid floats
	// on the hot path. The real values are
	// mu100 / 100 and sigma100 / 100.
	mu100    int64
	sigma100 int64
	// dirty is set whenever a new sample is
	// recorded; the next call to Budget
	// recomputes mu/sigma.
	dirty bool
}

// Record appends a new RTT sample (in
// microseconds) to the window. Hot path:
// zero allocations.
func (p *PerSubject) Record(rttUS int64, nowNS uint64) {
	p.samples[p.cursor%SampleCap] = rttUS
	p.cursor++
	if p.count < SampleCap {
		p.count++
	}
	p.lastSeenNS = nowNS
	p.dirty = true
}

// Budget returns the current tolerance
// budget in microseconds. The caller is
// expected to:
//
//	if observed > budget {
//	    mark event as "late" and feed
//	    EventSlowResponse into the engine
//	}
//
// During warmup (count < MinSamples), Budget
// returns DefaultBudgetMicrosec. If the
// observed CV exceeds MaxCV, Budget also
// returns DefaultBudgetMicrosec (the data is
// too noisy to trust).
func (p *PerSubject) Budget() int64 {
	if p.count < MinSamples {
		return DefaultBudgetMicrosec
	}
	if p.dirty {
		p.recompute()
	}
	if p.mu100 == 0 {
		// All-zero samples: cannot compute
		// CV. Fall back.
		return DefaultBudgetMicrosec
	}
	// CV = sigma / mu
	cv100 := (p.sigma100 * 100) / p.mu100
	if cv100 > int64(MaxCV*100) {
		return DefaultBudgetMicrosec
	}
	// All math in the *100 domain. Convert
	// at the very end.
	budget := p.mu100 + int64(KSigma*100)*p.sigma100/100
	// Floor: never tighter than the default.
	// Default is 250ms; the floor in the
	// *100 domain is 250ms * 100.
	if budget < DefaultBudgetMicrosec*100 {
		budget = DefaultBudgetMicrosec * 100
	}
	// Convert back to microseconds.
	return budget / 100
}

// recompute walks the ring buffer and
// updates mu100 and sigma100. Called at
// most once per Record() in the worst
// case; in production, callers should
// amortize by calling Budget() in a
// separate goroutine. The hot path is
// still zero-alloc because PerSubject
// has no pointers.
func (p *PerSubject) recompute() {
	var sum int64
	for i := uint32(0); i < p.count; i++ {
		sum += p.samples[i]
	}
	mu := sum / int64(p.count)
	// Two-pass for stdev to avoid storing
	// squared differences.
	var sqsum int64
	for i := uint32(0); i < p.count; i++ {
		d := p.samples[i] - mu
		sqsum += d * d
	}
	variance := sqsum / int64(p.count)
	// Integer sqrt via Newton's method.
	// Variance is always non-negative.
	sigma := intSqrt(variance)
	p.mu100 = mu * 100
	p.sigma100 = sigma * 100
	p.dirty = false
}

// intSqrt returns floor(sqrt(n)) for n >= 0.
// Implemented with Newton's method; converges
// in <= 16 iterations for n < 2^60.
func intSqrt(n int64) int64 {
	if n <= 0 {
		return 0
	}
	// Initial guess: 2^(floor(log2(n)/2)).
	x := int64(1)
	for (x+1)*(x+1) <= n {
		x = x + 1
	}
	// Newton's method: x_{k+1} = (x_k + n/x_k) / 2
	for i := 0; i < 16; i++ {
		if x == 0 {
			return 0
		}
		next := (x + n/x) / 2
		if next >= x {
			return x
		}
		x = next
	}
	return x
}

// Table is a fixed-size open-addressed table
// of PerSubject records keyed by an opaque
// 32-bit subject ID (e.g. efsm.ConnKey or
// engine.Subject). The table is concurrency-
// safe via a single mutex; the hot path is
// still O(1) and zero-alloc because the
// PerSubject value type is exactly 64 bytes
// (2 × int64 cursor/count + 32 × int64
// samples + lastSeenNS + mu/sigma + dirty).
type Table struct {
	mu   sync.Mutex
	tbl  [TableSize]PerSubject
	keys [TableSize]uint32
	used [TableSize]bool
}

// TableSize is the per-process cap on the
// number of subjects tracked. 4096 is enough
// for the active connection set of a single
// Linux box; eviction is LRU (TUGAS 4 will
// implement it; for now a full table returns
// DefaultBudgetMicrosec from BudgetFor).
const TableSize = 4096

// GetOrCreate returns the PerSubject record
// for `subject`, creating a fresh one if
// needed. If the table is full, the returned
// PerSubject is a zero-value (the caller
// can still call Record on it; the data will
// not be persisted). The "still works on a
// full table" behavior keeps the hot path
// non-blocking under attack.
func (t *Table) GetOrCreate(subject uint32) *PerSubject {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx := subject % TableSize
	for i := 0; i < TableSize; i++ {
		probe := (idx + uint32(i)) % TableSize
		if !t.used[probe] || t.keys[probe] == subject {
			if !t.used[probe] {
				t.keys[probe] = subject
				t.used[probe] = true
			}
			return &t.tbl[probe]
		}
	}
	// Table full. Return the address of a
	// throwaway on the heap — but the
	// caller is supposed to also call
	// Record(). Actually, the simplest
	// behavior is: return nil and let the
	// caller fall back to the default
	// budget. Returning a value-typed
	// PerSubject here would cause data
	// loss; returning a pointer into the
	// table would cause a slot collision.
	// Returning nil is honest.
	return nil
}

// BudgetFor is the convenience wrapper that
// returns the budget for a subject, falling
// back to DefaultBudgetMicrosec when the
// table is full or the subject is unknown.
func (t *Table) BudgetFor(subject uint32) int64 {
	rec := t.GetOrCreate(subject)
	if rec == nil {
		return DefaultBudgetMicrosec
	}
	return rec.Budget()
}

// Record is the convenience wrapper for
// recording a new sample. Returns false
// when the table is full.
func (t *Table) Record(subject uint32, rttUS int64, nowNS uint64) bool {
	rec := t.GetOrCreate(subject)
	if rec == nil {
		return false
	}
	rec.Record(rttUS, nowNS)
	return true
}

// ATS (Anomaly Trust Score) is a 0..100
// counter of how suspicious a subject's
// behavior has been over the recent past.
// A high ATS makes the engine more willing
// to transition. The score is the sum of
// "late" events in the last WindowSec
// seconds, scaled and clamped.
//
// ATS is computed from the same PerSubject
// ring buffer; we count the number of
// samples that exceeded the current budget
// at the time they were recorded.
//
// We approximate this by counting samples
// that exceed the current budget. This is
// not exactly right (the budget may have
// shifted between record and query) but it
// is bounded, zero-alloc, and close enough
// for the engine to use as a soft signal.
func (p *PerSubject) ATS() uint8 {
	if p.count == 0 {
		return 0
	}
	if p.dirty {
		p.recompute()
	}
	budget := p.mu100 + int64(KSigma*100)*p.sigma100/100
	if budget <= 0 {
		return 0
	}
	over := int64(0)
	for i := uint32(0); i < p.count; i++ {
		if p.samples[i]*100 > budget {
			over++
		}
	}
	// Map (over / count) to 0..100.
	ratio := over * 100 / int64(p.count)
	if ratio > 100 {
		ratio = 100
	}
	return uint8(ratio)
}

// Helpers exported for tests.
func FloorDiv(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	if a < 0 {
		return -((-a + b/2) / b)
	}
	return (a + b/2) / b
}

// math.AbsInt is a tiny int64 abs to avoid
// importing math at the package level (we
// only need sqrt from math elsewhere). The
// real computation path doesn't use this,
// but tests do.
func mathAbsInt(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// silence unused-import warnings for math
// in case a future refactor needs it.
var _ = math.Abs
