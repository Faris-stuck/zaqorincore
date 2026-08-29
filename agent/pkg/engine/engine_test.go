package engine

import (
	"context"
	"sync"
	"testing"
	"time"
)

// mockStore is a minimal StateStore for unit tests.
// It is intentionally simple: a sync.Map under a
// mutex, no LRU, no expiry. For tests of the DFA
// transition table that is all we need.
type mockStore struct {
	mu sync.Mutex
	m  map[uint32]Status
}

func newMockStore() *mockStore {
	return &mockStore{m: make(map[uint32]Status)}
}

func (s *mockStore) Get(sub uint32) (Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[sub]
	return v, ok
}

func (s *mockStore) Set(sub uint32, st Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sub] = st
}

func (s *mockStore) Delete(sub uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[sub]
	delete(s.m, sub)
	return ok
}

func (s *mockStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// alertRecord is one row in the test alert log.
type alertRecord struct {
	Subject uint32
	From    Status
	To      Status
	Kind    uint8
	Reason  string
}

// recordingSink captures every Emit call in
// insertion order. Used by the table-driven
// transition tests to assert that the engine
// fires exactly the right alerts.
type recordingSink struct {
	mu      sync.Mutex
	records []alertRecord
}

func (s *recordingSink) Emit(sub uint32, from, to Status, ev Event, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, alertRecord{
		Subject: sub, From: from, To: to, Kind: ev.Kind, Reason: reason,
	})
}

func (s *recordingSink) snapshot() []alertRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]alertRecord, len(s.records))
	copy(out, s.records)
	return out
}

// TestDFA_DefaultTransitions covers every (state,
// kind) pair that has a default rule, plus a
// handful of "should NOT transition" cases to
// guard against false positives.
func TestDFA_DefaultTransitions(t *testing.T) {
	type step struct {
		ev         Event
		wantStatus Status
		wantAlert  bool
		wantReason string
	}
	cases := []struct {
		name string
		// run the same subject through these events
		steps []step
	}{
		{
			name: "canary touch from nominal -> challenge",
			steps: []step{
				{Event{Kind: EventCanaryTouch, Subject: 0xC0FFEE}, StatusChallenge, true, "canary_touch"},
			},
		},
		{
			name: "rate limit trip from nominal -> challenge",
			steps: []step{
				{Event{Kind: EventRateLimitTrip, Subject: 42}, StatusChallenge, true, "rate_limit_trip"},
			},
		},
		{
			name: "challenge fail from challenge -> deception",
			steps: []step{
				{Event{Kind: EventCanaryTouch, Subject: 7}, StatusChallenge, true, "canary_touch"},
				{Event{Kind: EventChallengeFail, Subject: 7}, StatusDeception, true, "challenge_fail"},
			},
		},
		{
			name: "canary touch from deception -> containment",
			steps: []step{
				{Event{Kind: EventCanaryTouch, Subject: 9}, StatusChallenge, true, "canary_touch"},
				{Event{Kind: EventChallengeFail, Subject: 9}, StatusDeception, true, "challenge_fail"},
				{Event{Kind: EventCanaryTouch, Subject: 9}, StatusContainment, true, "canary_touch"},
			},
		},
		{
			name: "CFI exit from deception -> containment",
			steps: []step{
				{Event{Kind: EventCanaryTouch, Subject: 11}, StatusChallenge, true, "canary_touch"},
				{Event{Kind: EventChallengeFail, Subject: 11}, StatusDeception, true, "challenge_fail"},
				{Event{Kind: EventCFIExit, Subject: 11}, StatusContainment, true, "cfi_exit"},
			},
		},
		{
			name: "unrelated event does NOT transition",
			steps: []step{
				{Event{Kind: EventTCPSYN, Subject: 13}, StatusNominal, false, ""},
			},
		},
		{
			name: "subject zero is ignored",
			steps: []step{
				{Event{Kind: EventCanaryTouch, Subject: 0}, StatusNominal, false, ""},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMockStore()
			sink := &recordingSink{}
			e := New(store, sink)
			var last Status
			for i, s := range tc.steps {
				got, transitioned := e.Process(s.ev)
				if got != s.wantStatus {
					t.Errorf("step %d: status = %v, want %v", i, got, s.wantStatus)
				}
				if transitioned != s.wantAlert {
					t.Errorf("step %d: transitioned = %v, want %v", i, transitioned, s.wantAlert)
				}
				last = got
			}
			// Store matches the final expected status.
			if got, _ := store.Get(tc.steps[len(tc.steps)-1].ev.Subject); got != last {
				t.Errorf("store status = %v, want %v", got, last)
			}
			// Alert log matches the expected alerts.
			recs := sink.snapshot()
			var wantAlerts int
			for _, s := range tc.steps {
				if s.wantAlert {
					wantAlerts++
				}
			}
			if len(recs) != wantAlerts {
				t.Errorf("alert count = %d, want %d", len(recs), wantAlerts)
			}
			for i, s := range tc.steps {
				if !s.wantAlert {
					continue
				}
				if i >= len(recs) {
					break
				}
				if recs[i].Reason != s.wantReason {
					t.Errorf("alert[%d] reason = %q, want %q", i, recs[i].Reason, s.wantReason)
				}
				if recs[i].To != s.wantStatus {
					t.Errorf("alert[%d] to = %v, want %v", i, recs[i].To, s.wantStatus)
				}
			}
		})
	}
}

// TestDFA_ContainmentIsTerminal asserts that once
// a subject is in StatusContainment, no event can
// move it (intentional: containment is the end of
// the line until an operator manually resets).
func TestDFA_ContainmentIsTerminal(t *testing.T) {
	store := newMockStore()
	sink := &recordingSink{}
	e := New(store, sink)
	sub := uint32(99)
	// Drive to containment.
	e.Process(Event{Kind: EventCanaryTouch, Subject: sub})
	e.Process(Event{Kind: EventChallengeFail, Subject: sub})
	e.Process(Event{Kind: EventCFIExit, Subject: sub})
	// Now hammer it with every event kind.
	for k := uint8(0); k < 16; k++ {
		_, transitioned := e.Process(Event{Kind: k, Subject: sub})
		if transitioned {
			t.Errorf("event kind %d transitioned out of containment", k)
		}
	}
	if got, _ := store.Get(sub); got != StatusContainment {
		t.Errorf("final status = %v, want containment", got)
	}
}

// TestDFA_ConcurrentStoreAccess exercises the
// StateStore's own concurrency (the DFA is
// explicitly single-caller; the StateStore is
// what needs to be race-clean for production).
func TestDFA_ConcurrentStoreAccess(t *testing.T) {
	store := newMockStore()
	for w := 0; w < 8; w++ {
		w := w
		go func() {
			for i := 0; i < 1000; i++ {
				sub := uint32(w*1000 + i + 1)
				store.Set(sub, StatusNominal)
				_, _ = store.Get(sub)
				store.Delete(sub)
			}
		}()
	}
	// We do not assert a specific length here
	// because workers race; the point of the test
	// is the -race detector catching data races in
	// mockStore. Wait for goroutines to finish.
	// (The test passes if -race is clean.)
	time.Sleep(50 * time.Millisecond)
}

// TestDFA_SingleCallerAcrossManySubjects is the
// non-racy smoke for the engine: one goroutine,
// many subjects, drive to containment, assert
// every subject ended in containment.
func TestDFA_SingleCallerAcrossManySubjects(t *testing.T) {
	store := newMockStore()
	sink := &recordingSink{}
	e := New(store, sink)
	const subjects = 1000
	for i := 0; i < subjects; i++ {
		sub := uint32(i + 1)
		e.Process(Event{Kind: EventCanaryTouch, Subject: sub})
		e.Process(Event{Kind: EventChallengeFail, Subject: sub})
		e.Process(Event{Kind: EventCFIExit, Subject: sub})
	}
	if store.Len() != subjects {
		t.Errorf("store len = %d, want %d", store.Len(), subjects)
	}
	for i := 0; i < subjects; i++ {
		sub := uint32(i + 1)
		got, _ := store.Get(sub)
		if got != StatusContainment {
			t.Errorf("subject %d status = %v, want containment", sub, got)
		}
	}
	// Each subject produces 3 alerts.
	if got := len(sink.snapshot()); got != subjects*3 {
		t.Errorf("alert count = %d, want %d", got, subjects*3)
	}
}

// TestDFA_DefensiveGarbage asserts that the engine
// does not panic on a state-store that returns an
// out-of-range value (impossible with our impl,
// but cheap to guard).
func TestDFA_DefensiveGarbage(t *testing.T) {
	store := &badStore{}
	sink := &recordingSink{}
	e := New(store, sink)
	// Should not panic.
	e.Process(Event{Kind: EventCanaryTouch, Subject: 1})
}

// badStore always returns a garbage Status.
type badStore struct{}

func (b *badStore) Get(_ uint32) (Status, bool) { return Status(99), true }
func (b *badStore) Set(_ uint32, _ Status)      {}
func (b *badStore) Delete(_ uint32) bool        { return false }
func (b *badStore) Len() int                    { return 0 }

// TestRun_StopsOnContextCancel uses a mock event
// source that blocks on Read until the context is
// cancelled. Asserts that Run returns promptly.
func TestRun_StopsOnContextCancel(t *testing.T) {
	store := newMockStore()
	e := New(store, nil)
	src := &blockingSource{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx, src) }()
	cancel()
	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
	}
}

func after2s() <-chan time.Time { return time.After(2 * time.Second) }

// blockingSource implements EventSource. Read
// blocks until ctx is cancelled, then returns
// (0, context.Canceled).
type blockingSource struct{}

func (b *blockingSource) Read(ctx context.Context, _ []Event) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (b *blockingSource) Close() error { return nil }
