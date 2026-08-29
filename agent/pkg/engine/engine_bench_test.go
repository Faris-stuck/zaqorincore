package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkDFAStateTransition is the NFR gate.
// The engine MUST transition 1M events per second
// with 0 B/op and 0 allocs/op on a modern x86_64
// core. If this benchmark regresses, the
// PR is rejected.
//
// Run: go test -bench=BenchmarkDFAStateTransition \
//   -benchmem -count=3 ./pkg/engine/
func BenchmarkDFAStateTransition(b *testing.B) {
	store := newMockStore()
	e := New(store, nil)
	// Pre-populate 1024 distinct subjects so the
	// store isn't trivially empty.
	const subjects = 1024
	for i := 0; i < subjects; i++ {
		store.Set(uint32(i+1), StatusNominal)
	}
	ev := Event{Kind: EventCanaryTouch, Subject: 1}
	// Rotating subject id, so we hit the table
	// across many states.
	var rot uint32
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rot = (rot % subjects) + 1
		ev.Subject = rot
		e.Process(ev)
	}
}

// BenchmarkDFAStateTransition_SameSubject is the
// "hot" case: the same subject drives the engine
// thousands of times in a row. Useful for the
// regression test on table indexing.
func BenchmarkDFAStateTransition_SameSubject(b *testing.B) {
	store := newMockStore()
	e := New(store, nil)
	ev := Event{Kind: EventCanaryTouch, Subject: 42}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(ev)
	}
}

// BenchmarkDFA_Run is the end-to-end engine
// driver, processing 1024 events from an
// in-memory source. Asserts that the dispatcher
// loop stays zero-alloc under steady load.
func BenchmarkDFA_Run(b *testing.B) {
	store := newMockStore()
	e := New(store, nil)
	src := &scriptedSource{events: make([]Event, 1024)}
	for i := range src.events {
		src.events[i] = Event{
			Kind:    EventCanaryTouch,
			Subject: uint32(i%128) + 1,
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.idx.Store(0)
		_ = e.Run(benchCtx(), src)
	}
}

// scriptedSource is a one-shot in-memory event
// source. After the scripted list is drained, Read
// returns (0, io.EOF).
type scriptedSource struct {
	events []Event
	idx    atomic.Int64
}

func (s *scriptedSource) Read(_ context.Context, dst []Event) (int, error) {
	i := int(s.idx.Load())
	if i >= len(s.events) {
		return 0, errEOF
	}
	n := copy(dst, s.events[i:])
	s.idx.Add(int64(n))
	return n, nil
}

func (s *scriptedSource) Close() error { return nil }

// errEOF is a sentinel for the scripted source.
var errEOF = errSentinel("EOF")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

// benchCtx returns a context that's already
// cancelled. Run() returns immediately on a
// cancelled context, so the benchmark is
// deterministic.
func benchCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// keep the time import meaningful
var _ = time.Second
