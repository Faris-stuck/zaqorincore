package efsm

import (
	"sync"
	"testing"

	"github.com/Faris-stuck/zaqorincore/agent/pkg/decode"
	"github.com/Faris-stuck/zaqorincore/agent/pkg/engine"
)

// recordingOut captures every event the EFSM
// emits. Used to assert on the produced stream.
type recordingOut struct {
	mu     sync.Mutex
	events []engine.Event
}

func (r *recordingOut) emit(ev engine.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingOut) snapshot() []engine.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]engine.Event, len(r.events))
	copy(out, r.events)
	return out
}

func TestEFSM_HTTP_GETRequest(t *testing.T) {
	out := &recordingOut{}
	e := New(out.emit)
	// One TCP packet with an HTTP/1.1 GET
	// request + minimal headers + empty body.
	pl := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
	ev := decode.L4Event{
		L4Proto: decode.L4TCP, DstPort: 80,
		Payload: pl, TimestampNS: 1000,
	}
	n, err := e.Feed(0xABCDEF01, ev)
	if err != nil {
		t.Fatalf("Feed err = %v", err)
	}
	if n < 1 {
		t.Errorf("emitted %d, want >= 1", n)
	}
	recs := out.snapshot()
	if len(recs) == 0 {
		t.Fatal("no events recorded")
	}
	if recs[0].Kind != engine.EventCanaryTouch {
		t.Errorf("kind = %v, want CanaryTouch (L7 HTTP mapped)", recs[0].Kind)
	}
	if recs[0].Subject != 0xABCDEF01 {
		t.Errorf("subject = %x, want ABCDEF01", recs[0].Subject)
	}
}

func TestEFSM_HTTP_Malformed(t *testing.T) {
	out := &recordingOut{}
	e := New(out.emit)
	// Not a real HTTP request line.
	pl := []byte("hello\r\n\r\n")
	ev := decode.L4Event{
		L4Proto: decode.L4TCP, DstPort: 80, Payload: pl,
	}
	if _, err := e.Feed(0x1234, ev); err != nil {
		t.Errorf("Feed err = %v, want nil (malformed is OK, no error)", err)
	}
	// EFSM should still emit something so the
	// rate limiter sees the traffic.
	recs := out.snapshot()
	if len(recs) == 0 {
		t.Error("expected at least one event for malformed input")
	}
}

func TestEFSM_UnknownPortEmitsSYN(t *testing.T) {
	out := &recordingOut{}
	e := New(out.emit)
	ev := decode.L4Event{
		L4Proto: decode.L4TCP, DstPort: 22, // SSH
		Payload: []byte("SSH-2.0-OpenSSH\r\n"),
	}
	_, err := e.Feed(0xC0FFEE, ev)
	if err != nil {
		t.Fatalf("Feed err = %v", err)
	}
	recs := out.snapshot()
	if len(recs) == 0 {
		t.Fatal("expected SYN-like event for SSH traffic")
	}
	if recs[0].Kind != engine.EventTCPSYN {
		t.Errorf("kind = %v, want TCPSYN", recs[0].Kind)
	}
}

func TestEFSM_WSFrame(t *testing.T) {
	out := &recordingOut{}
	e := New(out.emit)
	// WebSocket frame: FIN=1, opcode=1 (text),
	// mask=0, payload length = 5, "hello".
	pl := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	ev := decode.L4Event{
		L4Proto: decode.L4TCP, DstPort: 443, Payload: pl,
	}
	_, err := e.Feed(0x9999, ev)
	if err != nil {
		t.Fatalf("Feed err = %v", err)
	}
	recs := out.snapshot()
	if len(recs) == 0 {
		t.Fatal("expected WebSocket event")
	}
	if recs[0].Kind != engine.EventWebSocketFrame {
		t.Errorf("kind = %v, want WebSocketFrame", recs[0].Kind)
	}
	if recs[0].Payload0 != 1 { // opcode 1 = text
		t.Errorf("opcode = %d, want 1", recs[0].Payload0)
	}
}

func TestEFSM_TableFullReturnsError(t *testing.T) {
	out := &recordingOut{}
	e := New(out.emit)
	// Fill the table with distinct keys.
	pl := []byte("GET / HTTP/1.1\r\n\r\n")
	for i := 0; i < tableSize; i++ {
		ev := decode.L4Event{
			L4Proto: decode.L4TCP, DstPort: 80, Payload: pl,
		}
		_, _ = e.Feed(ConnKey(i+1), ev)
	}
	// The next one should fail.
	ev := decode.L4Event{
		L4Proto: decode.L4TCP, DstPort: 80, Payload: pl,
	}
	if _, err := e.Feed(ConnKey(0xDEADBEEF), ev); err == nil {
		t.Error("expected table-full error")
	}
}

// TestEFSM_ZeroAlloc asserts the happy path
// allocates nothing. (Failure paths may.)
func TestEFSM_ZeroAlloc(t *testing.T) {
	out := &recordingOut{}
	e := New(out.emit)
	pl := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
	ev := decode.L4Event{
		L4Proto: decode.L4TCP, DstPort: 80, Payload: pl,
	}
	// Warm up the table once so the alloc
	// isn't from a cold path.
	_, _ = e.Feed(0x1, ev)
	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = e.Feed(0x2, ev)
	})
	if allocs != 0 {
		t.Errorf("Feed happy path = %v allocs/op, want 0", allocs)
	}
}
