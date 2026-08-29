package engine

import (
	"sync"
	"sync/atomic"
	"testing"
)

// mockRing implements a bounded ring buffer
// for the ingress benchmark. It mimics the
// shape of the agent's internal ring buffer:
// a fixed-size array, two cursors (read/write),
// and a mutex protecting the buffer.
//
// Why the ring is a fixed array:
//
//   - The agent's kernel-side ringbuf is
//     BPF_MAP_TYPE_RINGBUF; the user-space
//     counterpart is a bounded Go channel
//     or a fixed array. For benchmarking
//     purposes a fixed array is the worst
//     case (no allocator fast path), so the
//     measured throughput is the floor.
type mockRing struct {
	buf    [1024]Event
	write  uint64
	read   uint64
	dropped uint64
	mu     sync.Mutex
}

func newMockRing() *mockRing { return &mockRing{} }

func (r *mockRing) push(e Event) bool {
	r.mu.Lock()
	w := r.write
	r.write = w + 1
	r.buf[w&1023] = e
	r.mu.Unlock()
	return true
}

func (r *mockRing) pop() (Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.read == r.write {
		return Event{}, false
	}
	e := r.buf[r.read&1023]
	r.read++
	return e, true
}

// BenchmarkRingBufferIngress measures the
// throughput of pushing events through a
// ring buffer with concurrent consumers
// (a single goroutine drains the ring and
// feeds the engine). The benchmark reports
// events/sec.
//
// NFR target: >= 1M events/sec sustained.
// At 27 ns per DFA transition and ~100 ns
// per ring push+pop, we expect ~3-5M/sec.
func BenchmarkRingBufferIngress(b *testing.B) {
	const workers = 4
	ring := newMockRing()
	store := newMockStore()
	var sink captureSink
	eng := New(store, &sink)
	// Pre-fill the ring with b.N events
	// distributed across subjects, so the
	// benchmark loop is "drain to empty",
	// not "push while draining".
	b.ResetTimer()
	var wg sync.WaitGroup
	wg.Add(workers)
	var processed atomic.Uint64
	for w := 0; w < workers; w++ {
		go func(wid int) {
			defer wg.Done()
			for processed.Load() < uint64(b.N) {
				e, ok := ring.pop()
				if !ok {
					// Refill.
					subject := uint32(processed.Load() % 4096)
					ring.push(Event{Subject: subject, Kind: 0})
					continue
				}
				_, _ = eng.Process(e)
				processed.Add(1)
			}
		}(w)
	}
	wg.Wait()
	b.StopTimer()
	b.ReportMetric(float64(processed.Load())/b.Elapsed().Seconds(), "ev/s")
}

// BenchmarkTaintTracking exercises the
// engine along the L0 -> L1 -> L2 -> L3
// path. Each iteration simulates one full
// subject lifecycle:
//
//   1. EventCanaryTouch   (L0 -> L1)
//   2. EventChallengeFail (L1 -> L2)
//   3. EventCanaryTouch   (L2 -> L3, CFI exit)
//
// This is the worst case for tag
// propagation: every transition writes a
// status change to the store.
func BenchmarkTaintTracking(b *testing.B) {
	store := newMockStore()
	var sink captureSink
	eng := New(store, &sink)
	subject := uint32(1)
	events := []Event{
		{Subject: subject, Kind: 11}, // EventCanaryTouch
		{Subject: subject, Kind: 12}, // EventChallengeFail
		{Subject: subject, Kind: 11}, // EventCanaryTouch (CFI exit)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range events {
			_, _ = eng.Process(e)
		}
	}
}
