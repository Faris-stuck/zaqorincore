// Package mock provides in-process stand-ins for
// the production-only components of the agent.
//
// The goal is hermetic unit testing: any test
// that imports this package runs with no
// CAP_SYS_ADMIN, no live kernel probe, no real
// WebSocket server, no real canary network.
//
// Each Mock implements the same interface the
// production driver satisfies, so a test can
// substitute a mock for the real thing with a
// one-line wire change.
package mock

import (
	"sync"
	"time"
)

// BPFEvent is a kernel-side event delivered to
// the user-space engine. The production driver
// reads from a BPF_MAP_TYPE_RINGBUF; the mock
// driver emits scripted events from a slice.
type BPFEvent struct {
	Kind    uint8
	Subject uint32
	Payload0 uint32
	Payload1 uint32
	// TimestampNS is filled in by the mock at
	// push time so the engine's adaptive timing
	// logic has a realistic monotonic value.
	TimestampNS uint64
}

// BPFDriver is the interface the engine depends
// on for kernel-side event ingest.
//
// Production: *ebpf.RingBufferReader.
// Test:       *BPFDriverMock.
type BPFDriver interface {
	// Read returns up to len(dst) events, blocking
	// until at least one is available or the
	// context is done. Returns (0, io.EOF) on close.
	Read(dst []BPFEvent) (int, error)
	// Close releases the underlying buffer.
	Close() error
}

// BPFDriverMock is an in-memory BPFDriver
// suitable for unit tests. The test pushes
// scripted events with PushEvent; the engine
// pulls them with Read.
type BPFDriverMock struct {
	mu     sync.Mutex
	closed bool
	cond   *sync.Cond
	buf    []BPFEvent
}

// NewBPFDriverMock returns an empty driver.
// Callers PushEvent to enqueue.
func NewBPFDriverMock() *BPFDriverMock {
	m := &BPFDriverMock{}
	m.cond = sync.NewCond(&m.mu)
	return m
}

// PushEvent enqueues one event. Safe for
// concurrent callers.
func (m *BPFDriverMock) PushEvent(ev BPFEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if ev.TimestampNS == 0 {
		ev.TimestampNS = uint64(time.Now().UnixNano())
	}
	m.buf = append(m.buf, ev)
	m.cond.Signal()
}

// PushBatch enqueues many events at once. The
// TimestampNS default-fill rule from PushEvent
// applies.
func (m *BPFDriverMock) PushBatch(events []BPFEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	now := uint64(time.Now().UnixNano())
	for i := range events {
		if events[i].TimestampNS == 0 {
			events[i].TimestampNS = now
		}
		m.buf = append(m.buf, events[i])
	}
	m.cond.Broadcast()
}

// Read blocks until at least one event is
// available, then copies up to len(dst) events
// into dst and returns the number copied.
//
// If the driver is closed and the buffer is
// empty, returns (0, io.EOF).
func (m *BPFDriverMock) Read(dst []BPFEvent) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.buf) == 0 && !m.closed {
		m.cond.Wait()
	}
	if m.closed && len(m.buf) == 0 {
		return 0, errEOF
	}
	n := copy(dst, m.buf)
	m.buf = m.buf[n:]
	return n, nil
}

// Close marks the driver closed. Read returns
// (0, io.EOF) once the buffer drains.
func (m *BPFDriverMock) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.cond.Broadcast()
	return nil
}

// Reset clears the buffer and re-opens the
// driver. Useful for re-using a single mock
// across sub-tests.
func (m *BPFDriverMock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = false
	m.buf = m.buf[:0]
}

// errEOF is a sentinel for the mock driver. We
// don't import io here to keep the surface
// small.
var errEOF = errSentinel("EOF")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }
