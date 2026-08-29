package engine

import (
	"context"

	"github.com/Faris-stuck/zaqorincore/agent/pkg/timing"
)

// TimingPolicy gates the engine's transitions
// on the adaptive temporal tolerance layer.
//
// The contract:
//
//   - Late responses (event_kind =
//     EventSlowResponse) below the per-subject
//     budget are absorbed: the engine does
//     NOT transition. They are recorded in the
//     timing window so the budget adapts.
//
//   - Late responses above the budget are
//     passed through to the engine as a
//     EventRateLimitTrip signal, which the
//     engine's default table maps to
//     L0 -> L1 (Challenge).
//
//   - If the timing table is full or the
//     subject is unknown, the policy
//     falls back to "allow all" so that a
//     legitimate user behind a freshly-
//     observed subject is never blocked.
type TimingPolicy struct {
	tbl *timing.Table
	// NowNS returns the current monotonic
	// time in nanoseconds. Indirected
	// through a function so tests can
	// inject a fake clock.
	NowNS func() uint64
}

// NewTimingPolicy builds a policy backed by
// the given timing table. If tbl is nil, the
// policy behaves as "no timing — pass
// everything through".
func NewTimingPolicy(tbl *timing.Table, nowNS func() uint64) *TimingPolicy {
	if nowNS == nil {
		nowNS = defaultNowNS
	}
	return &TimingPolicy{tbl: tbl, NowNS: nowNS}
}

func defaultNowNS() uint64 {
	// Default to 0 — the caller can wire a
	// real clock. Production wires the
	// kernel monotonic clock via the eBPF
	// probe's timestamp_ns field.
	return 0
}

// Observe feeds an RTT sample into the
// timing table. Returns false if the table
// is full (graceful degradation).
func (p *TimingPolicy) Observe(subject uint32, rttUS int64) bool {
	if p.tbl == nil {
		return false
	}
	return p.tbl.Record(subject, rttUS, p.NowNS())
}

// ShouldCountAsLate returns true if the given
// observed RTT is suspicious for this subject.
// A return of false means "absorb it — do not
// transition the engine".
func (p *TimingPolicy) ShouldCountAsLate(subject uint32, rttUS int64) bool {
	if p.tbl == nil {
		return true
	}
	budget := p.tbl.BudgetFor(subject)
	return rttUS > budget
}

// ATS returns the Anomaly Trust Score for
// the subject, or 0 if the table is full.
func (p *TimingPolicy) ATS(subject uint32) uint8 {
	if p.tbl == nil {
		return 0
	}
	rec := p.tbl.GetOrCreate(subject)
	if rec == nil {
		return 0
	}
	return rec.ATS()
}

// TimedProcess is the timing-aware variant
// of Engine.Process. Use this in production
// when a per-subject timing policy is wired.
//
// Returns (newStatus, transitioned,
// absorbedByTiming). `absorbedByTiming=true`
// means the event was within budget and
// the engine was NOT advanced.
func TimedProcess(
	e *Engine,
	p *TimingPolicy,
	ev Event,
) (Status, bool, bool) {
	if p == nil || p.tbl == nil {
		// No policy: pass through.
		ns, tx := e.Process(ev)
		return ns, tx, false
	}
	// Only L7 events with a meaningful
	// Payload0 are timing-bearing. We
	// treat Payload0 as rttUS.
	//
	// Convention: the EFSM sets Payload0
	// to the L7 frame length for the
	// generic "saw a request" event,
	// and to the RTT in microseconds for
	// the dedicated "slow response"
	// event (kind=EventRateLimitTrip
	// is the wrong choice here because
	// it is already a state transition;
	// we use a separate event with
	// Payload0=rttUS).
	//
	// For the slice-3 implementation we
	// assume that any L7 event with
	// Subject != 0 carries rttUS in
	// Payload0. This is documented in
	// PHASE23-timed-engine.md.
	if ev.Subject != 0 && isTimingEvent(ev.Kind) {
		p.tbl.Record(ev.Subject, int64(ev.Payload0), p.NowNS())
		if !p.ShouldCountAsLate(ev.Subject, int64(ev.Payload0)) {
			return StatusNominal, false, true
		}
		// Over budget: convert to a
		// RateLimitTrip so the engine's
		// default table transitions
		// L0 -> L1.
		ev.Kind = EventRateLimitTrip
	}
	ns, tx := e.Process(ev)
	return ns, tx, false
}

// isTimingEvent returns true for the event
// kinds that carry a timing measurement in
// Payload0. Today only EventHTTPRequest is
// routed this way; future slices can add
// more (EventHTTP2Frame, EventWebSocketFrame).
func isTimingEvent(k uint8) bool {
	switch k {
	case EventHTTPRequest, EventHTTP2Frame, EventWebSocketFrame:
		return true
	}
	return false
}

// ATSGate returns true if the subject's ATS
// is at or above the threshold. Callers can
// use this to escalate a transition directly
// to L2 (Deception) when the ATS is high
// enough, skipping the L1 stage.
func ATSGate(p *TimingPolicy, subject uint32, threshold uint8) bool {
	if p == nil {
		return false
	}
	return p.ATS(subject) >= threshold
}

// RunWithTiming is the timing-aware variant
// of Engine.Run. It mirrors the signature
// and adds the same filter as TimedProcess.
func RunWithTiming(
	ctx context.Context,
	e *Engine,
	p *TimingPolicy,
	src EventSource,
) error {
	if src == nil {
		return nil
	}
	defer src.Close()
	buf := make([]Event, 256)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := src.Read(ctx, buf)
		for i := 0; i < n; i++ {
			_, _, _ = TimedProcess(e, p, buf[i])
		}
		if err != nil {
			return nil
		}
	}
}
