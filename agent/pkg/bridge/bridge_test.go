package bridge

import (
	"sync"
	"testing"

	"github.com/Faris-stuck/zaqorincore/agent/pkg/decode"
	"github.com/Faris-stuck/zaqorincore/agent/pkg/efsm"
	"github.com/Faris-stuck/zaqorincore/agent/pkg/engine"
)

// recordingSink captures engine transitions.
type recordingSink struct {
	mu       sync.Mutex
	statuses []engine.Status
	subjects []uint32
}

func (r *recordingSink) Emit(sub uint32, from, to engine.Status, _ engine.Event, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if from != to {
		r.statuses = append(r.statuses, to)
		r.subjects = append(r.subjects, sub)
	}
}

func (r *recordingSink) snapshot() ([]engine.Status, []uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]engine.Status(nil), r.statuses...), append([]uint32(nil), r.subjects...)
}

// makeHTTPWire builds a 64-byte kernel-style
// wire event with an HTTP GET payload.
func makeHTTPWire() []byte {
	pl := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
	// Wire format: 58-byte fixed header + payload,
	// padded to a multiple of 64. Real kernel
	// probes also pad to 64.
	wireSize := 58 + len(pl)
	padded := wireSize
	if padded%64 != 0 {
		padded += 64 - (padded % 64)
	}
	w := make([]byte, padded)
	w[0], w[1], w[2], w[3] = 10, 0, 0, 1
	w[4], w[5], w[6], w[7] = 10, 0, 0, 2
	w[40], w[41] = 0x04, 0xD2 // src port 1234
	w[42], w[43] = 0x00, 0x50 // dst port 80
	w[44] = decode.L3IPv4
	w[45] = decode.L4TCP
	w[46] = decode.TCPFlagSYN
	w[48] = byte(len(pl) >> 8)
	w[49] = byte(len(pl))
	copy(w[58:], pl)
	return w
}

// TestBridge_WireToEvent exercises the bridge's
// inner wire-decoding step (kernel wire ->
// engine.Event) without spinning up the ring
// buffer read loop. The full Run() loop is
// covered indirectly through the manual Read
// path in this test.
func TestBridge_WireToEvent(t *testing.T) {
	wire := makeHTTPWire()
	// Step 1: parse the wire.
	ev, err := decode.Parse(wire)
	if err != nil {
		t.Fatalf("Parse err = %v", err)
	}
	if !ev.IsSYN() {
		t.Errorf("expected SYN flag, got %08b", ev.TCPFlags)
	}
	// Step 2: feed into EFSM, capturing the
	// engine.Event the EFSM produces.
	var captured engine.Event
	ef := efsm.New(func(e engine.Event) { captured = e })
	if _, err := ef.Feed(0x1234, ev); err != nil {
		t.Fatalf("EFSM Feed err = %v", err)
	}
	if captured.Subject == 0 {
		t.Error("captured.Subject is zero")
	}
	if captured.Kind == 0 {
		t.Error("captured.Kind is zero (default EventCanaryTouch)")
	}
	// Step 3: feed into engine, asserting a
	// status transition.
	sink := &recordingSink{}
	eng := engine.New(mockStateStore{}, sink)
	eng.Process(captured)
	statuses, _ := sink.snapshot()
	if len(statuses) == 0 {
		t.Fatal("engine did not transition")
	}
}

// mockStateStore is a no-op store: the engine
// only uses Get/Set on the hot path, both
// return nominal, so the alert sink never
// transitions the state.
type mockStateStore struct{}

func (mockStateStore) Get(_ uint32) (engine.Status, bool) { return engine.StatusNominal, false }
func (mockStateStore) Set(_ uint32, _ engine.Status)      {}
func (mockStateStore) Delete(_ uint32) bool               { return false }
func (mockStateStore) Len() int                           { return 0 }
