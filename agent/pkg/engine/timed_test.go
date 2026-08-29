package engine

import (
	"sync"
	"testing"

	"github.com/Faris-stuck/zaqorincore/agent/pkg/timing"
)

// captureSink is a per-test alert sink that
// records every transition. It lives in this
// file because mockStore / recordingSink in
// engine_test.go are not designed to be
// reused across packages, and TimedProcess
// needs a fresh sink to inspect.
type captureSink struct {
	mu       sync.Mutex
	statuses []Status
	subjects []uint32
}

func (c *captureSink) Emit(sub uint32, from, to Status, _ Event, _ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if from != to {
		c.statuses = append(c.statuses, to)
		c.subjects = append(c.subjects, sub)
	}
}

func TestTimedProcess_AbsorbsWithinBudget(t *testing.T) {
	tbl := &timing.Table{}
	// Warmup with stable 100ms RTT.
	for i := 0; i < timing.MinSamples; i++ {
		_ = tbl.Record(1, 100_000, uint64(i))
	}
	// Budget is the floor: 250ms. An event
	// with rttUS = 200_000 (200ms) is within
	// budget.
	pol := NewTimingPolicy(tbl, func() uint64 { return 0 })
	sink := &captureSink{}
	e := New(newMockStore(), sink)
	ns, tx, absorbed := TimedProcess(e, pol, Event{
		Kind:    EventHTTPRequest,
		Subject: 1,
		Payload0: 200_000,
	})
	if !absorbed {
		t.Error("expected absorption (within budget)")
	}
	if tx {
		t.Error("expected no transition (absorbed)")
	}
	if ns != StatusNominal {
		t.Errorf("status = %v, want Nominal", ns)
	}
	if len(sink.statuses) != 0 {
		t.Errorf("sink got %d alerts, want 0", len(sink.statuses))
	}
}

func TestTimedProcess_PromotesOverBudgetToRateLimitTrip(t *testing.T) {
	tbl := &timing.Table{}
	// Stable 500ms RTT. After 32 samples,
	// mean is 500ms, sigma tiny, budget =
	// 500ms (above the 250ms floor).
	for i := 0; i < timing.SampleCap; i++ {
		_ = tbl.Record(1, 500_000, uint64(i))
	}
	pol := NewTimingPolicy(tbl, func() uint64 { return 0 })
	sink := &captureSink{}
	e := New(newMockStore(), sink)
	// rttUS = 2_000_000 (2s) — way over
	// 500ms budget.
	ns, tx, absorbed := TimedProcess(e, pol, Event{
		Kind:    EventHTTPRequest,
		Subject: 1,
		Payload0: 2_000_000,
	})
	if absorbed {
		t.Error("expected NOT absorbed (over budget)")
	}
	if !tx {
		t.Error("expected transition (over budget)")
	}
	if ns != StatusChallenge {
		t.Errorf("status = %v, want Challenge", ns)
	}
	if len(sink.statuses) != 1 || sink.statuses[0] != StatusChallenge {
		t.Errorf("sink = %v, want [Challenge]", sink.statuses)
	}
}

func TestTimedProcess_NoPolicyPassesThrough(t *testing.T) {
	sink := &captureSink{}
	e := New(newMockStore(), sink)
	ns, tx, absorbed := TimedProcess(e, nil, Event{
		Kind:    EventCanaryTouch,
		Subject: 1,
	})
	if absorbed {
		t.Error("expected pass-through without policy")
	}
	if !tx || ns != StatusChallenge {
		t.Errorf("tx = %v, ns = %v, want true / Challenge", tx, ns)
	}
}

func TestTimedProcess_GracefulFallbackOnFullTable(t *testing.T) {
	tbl := &timing.Table{}
	for i := uint32(0); i < timing.TableSize; i++ {
		_ = tbl.Record(i, 100_000, uint64(i))
	}
	pol := NewTimingPolicy(tbl, func() uint64 { return 0 })
	// ShouldCountAsLate should return true
	// when the table is full (graceful
	// fallback: never block legitimate users).
	if pol.ShouldCountAsLate(99999, 999_999) != true {
		t.Error("ShouldCountAsLate should be true when table is full (graceful fallback)")
	}
}

func TestATSGate(t *testing.T) {
	tbl := &timing.Table{}
	pol := NewTimingPolicy(tbl, func() uint64 { return 0 })
	if ATSGate(pol, 1, 50) {
		t.Error("empty table should give ATS=0, gate false")
	}
}
