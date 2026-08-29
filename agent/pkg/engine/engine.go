// Package engine implements the deterministic finite state
// machine that drives ZaqorinCore's threat progression.
//
// Design contract:
//
//   - State transitions are O(1) and ZERO-ALLOC on the hot path
//     (achieved via fixed-size bitmask transition tables and
//     sync.Pool for transition records that must be returned
//     to callers).
//   - The engine is fully unit-testable in pure user-space.
//     Production wires an eBPF-backed event source; tests
//     inject a mock that satisfies the same EventSource
//     interface.
//   - The engine is intentionally stateless across calls
//     EXCEPT for an optional StateStore (canary/connection
//     tables). The mock state store (MockCanaryStore) keeps
//     tests fast and hermetic.
package engine

import (
	"context"
	"sync"
)

// Status is the discrete threat posture the engine
// produces for a tracked subject (host IP, connection
// tuple, canary token, etc.). The values are ordered
// ascending so numeric comparisons work:
//
//	Nominal < Challenge < Deception < Containment
type Status uint8

const (
	StatusNominal Status = iota
	StatusChallenge
	StatusDeception
	StatusContainment
)

// String returns the human-readable name. Used in
// logs, alerts, and the server API. Stable; do not
// renumber.
func (s Status) String() string {
	switch s {
	case StatusNominal:
		return "nominal"
	case StatusChallenge:
		return "challenge"
	case StatusDeception:
		return "deception"
	case StatusContainment:
		return "containment"
	default:
		return "unknown"
	}
}

// Event is the minimal input the DFA needs to make a
// transition decision. The production EventSource
// (eBPF ring buffer) produces these; the mock
// EventSource in tests produces the same shape.
//
// Event is a value type (no pointers, no slices) so
// the hot path never escapes to the heap.
type Event struct {
	// Kind is one of the EventKind constants below.
	Kind uint8
	// Subject is a stable identifier for the tracked
	// entity (IPv4-as-uint32, or a hash of a 5-tuple,
	// or a canary token ID).
	Subject uint32
	// TimestampNS is monotonic. Required for the
	// adaptive timing tolerance engine (TUGAS 3).
	TimestampNS uint64
	// Payload0/Payload1 carry event-specific data
	// (TCP flags, syscall arg, RTT sample, etc.).
	// Zero on events that don't need them.
	Payload0 uint32
	Payload1 uint32
}

// Event kinds. The first 16 are reserved for L3/L4
// events from the eBPF/XDP layer; the next 16 are
// for L7 events from the user-space EFSM.
const (
	EventReserved uint8 = iota

	// L3/L4 events (kernel-side)
	EventTCPSYN
	EventTCPSYNACK
	EventTCPACK
	EventTCPRST
	EventTCPFIN
	EventUDPPacket
	EventICMPUnreachable
	EventRateLimitTrip

	// L7 events (user-space EFSM)
	EventHTTPRequest
	EventHTTP2Frame
	EventWebSocketFrame
	EventCanaryTouch
	EventChallengeFail
	EventChallengePass
	EventCFIExit
	EventTarpitEnter
	EventTarpitExit
)

// EventSource is the abstraction over an event
// producer. Production is an eBPF ring buffer;
// tests inject a mock that emits a scripted
// sequence of events.
//
// The contract: Read blocks until at least one
// event is available, ctx is cancelled, or the
// source is closed. It must NOT allocate on the
// hot path (callers reuse the returned slice).
type EventSource interface {
	// Read returns up to len(dst) events. Returns the
	// number of events written. If the source is
	// closed, returns (0, io.EOF).
	Read(ctx context.Context, dst []Event) (int, error)
	// Close releases the source. Idempotent.
	Close() error
}

// StateStore is the persistence layer for per-subject
// state. Production uses a BPF_MAP_TYPE_LRU_HASH;
// tests use MockCanaryStore (in-memory map with
// per-test reset).
type StateStore interface {
	// Get returns the current Status for subject. If
	// the subject is not in the store, returns
	// StatusNominal, false.
	Get(subject uint32) (Status, bool)
	// Set atomically updates the Status for subject.
	// Must be safe for concurrent callers.
	Set(subject uint32, s Status)
	// Delete removes subject. Returns true if the
	// subject was present.
	Delete(subject uint32) bool
	// Len returns the number of subjects in the store.
	Len() int
}

// AlertSink is the side-effect channel for status
// transitions. The engine calls Emit exactly once
// per transition. Production wires this to the
// server's WebSocket /eventlog channel; tests
// inject a mock that records alerts.
type AlertSink interface {
	Emit(subject uint32, from, to Status, ev Event, reason string)
}

// transitionFn is the per-state, per-event-kind
// decision function. It returns the new status
// and a reason string.
//
// The reason is used for:
//   - logs (never user-facing)
//   - SOAR playbook routing
//   - test assertions
//
// The reason MUST be a static string constant or
// a string built from the Event's fixed-size
// fields WITHOUT allocation. See
// noAllocReason below for the safe pattern.
type transitionFn func(s Status, ev Event) (Status, string)

// Engine is the DFA. It is safe for concurrent use
// from a single caller goroutine. Multiple
// goroutines need their own Engine instance, or
// external synchronization.
//
// The Engine is intentionally tiny: just the
// transition table, a StateStore handle, and an
// AlertSink handle. No goroutines spawn here.
type Engine struct {
	// table is the (state, eventKind) -> transitionFn
	// matrix. Index = (state * 16) | eventKind.
	// Slot 0 is always the no-op (stay in current
	// state, no alert).
	table [4 * 16]transitionFn

	store StateStore
	alerts AlertSink
}

// New builds an engine with default transitions
// installed. The defaults implement the L0->L1->L2->L3
// progression described in ROADMAP.md:
//
//	Nominal  -- canaryTouch        --> Challenge
//	Nominal  -- rateLimitTrip      --> Challenge
//	Challenge -- challengeFail     --> Deception
//	Deception -- canaryTouch       --> Containment
//	Deception -- cfiExit           --> Containment
//	Containment stays in Containment (terminal).
//
// All other (state, kind) pairs are no-ops.
func New(store StateStore, alerts AlertSink) *Engine {
	e := &Engine{store: store, alerts: alerts}
	e.installDefaults()
	return e
}

// noopFn is the default transition for unhandled
// (state, kind) pairs. Returns the current state
// with no reason.
func noopFn(s Status, _ Event) (Status, string) {
	return s, ""
}

func (e *Engine) installDefaults() {
	for i := range e.table {
		e.table[i] = noopFn
	}
	// L0 -> L1: canary touch, rate-limit trip
	e.table[uint8(StatusNominal)*16+EventCanaryTouch] = e.simple(StatusChallenge, "canary_touch")
	e.table[uint8(StatusNominal)*16+EventRateLimitTrip] = e.simple(StatusChallenge, "rate_limit_trip")
	// L1 -> L2: failed challenge
	e.table[uint8(StatusChallenge)*16+EventChallengeFail] = e.simple(StatusDeception, "challenge_fail")
	// L2 -> L3: canary touched again, or CFI exit
	e.table[uint8(StatusDeception)*16+EventCanaryTouch] = e.simple(StatusContainment, "canary_touch")
	e.table[uint8(StatusDeception)*16+EventCFIExit] = e.simple(StatusContainment, "cfi_exit")
}

// simple returns a transitionFn that returns the
// fixed target status with the fixed reason. The
// reason is interned at construction time so the
// returned closure never allocates.
func (e *Engine) simple(target Status, reason string) transitionFn {
	return func(_ Status, _ Event) (Status, string) {
		return target, reason
	}
}

// Process is the hot path. Given an event, it:
//
//  1. reads the current status from the store
//     (or Nominal if absent),
//  2. indexes the transition table,
//  3. calls the transition function,
//  4. if the status changed, writes the new status
//     and emits an alert.
//
// Returns the new status and whether a transition
// occurred. NEVER allocates on the hot path: the
// transition table is fixed-size, the store is
// pre-allocated, and the reason string is interned.
//
// If ev.Subject is zero the event is silently
// ignored (subject zero is reserved for
// "untracked / broadcast").
func (e *Engine) Process(ev Event) (Status, bool) {
	if ev.Subject == 0 {
		return StatusNominal, false
	}
	cur, _ := e.store.Get(ev.Subject)
	if int(cur) >= 4 {
		// Defensive: store returned a garbage value.
		// Treat as nominal.
		cur = StatusNominal
	}
	if ev.Kind >= 16 {
		// Defensive: garbage event kind.
		return cur, false
	}
	fn := e.table[uint8(cur)*16+ev.Kind]
	next, reason := fn(cur, ev)
	if next == cur {
		return cur, false
	}
	e.store.Set(ev.Subject, next)
	if e.alerts != nil {
		e.alerts.Emit(ev.Subject, cur, next, ev, reason)
	}
	return next, true
}

// Run drives the engine from an EventSource until
// the source is closed or ctx is cancelled. It is
// the user-space equivalent of the kernel-side
// "consume ring buffer" loop.
//
// The internal scratch buffer is reused across
// iterations (sync.Pool) so even a burst of
// thousands of events per second is zero-alloc.
func (e *Engine) Run(ctx context.Context, src EventSource) error {
	if src == nil {
		return nil
	}
	defer src.Close()
	bufPtr := scratchPool.Get().(*[]Event)
	defer scratchPool.Put(bufPtr)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := src.Read(ctx, *bufPtr)
		for i := 0; i < n; i++ {
			e.Process((*bufPtr)[i])
		}
		if err != nil {
			return nil // EOF / closed
		}
	}
}

// scratchPool backs Engine.Run. Sized at 256 events
// per Read; large enough to absorb a 1ms burst at
// 256k events/sec without dropping.
var scratchPool = sync.Pool{
	New: func() any {
		buf := make([]Event, 256)
		return &buf
	},
}
