package decode

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// makeWire builds a synthetic 64-byte wire event
// (58 used + 6 padding). Tests fill only the
// fields they need.
func makeWire(l3, l4 uint8, tcpFlags uint8, payload []byte) []byte {
	w := make([]byte, 64)
	// src v4 = 10.0.0.1
	w[0] = 10
	w[1] = 0
	w[2] = 0
	w[3] = 1
	// dst v4 = 10.0.0.2
	w[4] = 10
	w[5] = 0
	w[6] = 0
	w[7] = 2
	// src port = 1234
	binary.BigEndian.PutUint16(w[40:42], 1234)
	// dst port = 80
	binary.BigEndian.PutUint16(w[42:44], 80)
	// L3 / L4
	w[44] = l3
	w[45] = l4
	w[46] = tcpFlags
	// payload length
	binary.BigEndian.PutUint16(w[48:50], uint16(len(payload)))
	// timestamp
	binary.BigEndian.PutUint64(w[50:58], 0xCAFE)
	copy(w[58:], payload)
	return w
}

func TestParse_TCPSYN(t *testing.T) {
	w := makeWire(L3IPv4, L4TCP, TCPFlagSYN, []byte("hello"))
	ev, err := Parse(w)
	if err != nil {
		t.Fatalf("Parse err = %v", err)
	}
	if !ev.IsSYN() || ev.IsACK() {
		t.Errorf("flags = %08b, want SYN only", ev.TCPFlags)
	}
	if ev.SrcPort != 1234 || ev.DstPort != 80 {
		t.Errorf("ports = %d/%d, want 1234/80", ev.SrcPort, ev.DstPort)
	}
	if !bytes.Equal(ev.Payload, []byte("hello")) {
		t.Errorf("payload = %q, want %q", ev.Payload, "hello")
	}
}

func TestParse_TCPSYNACK(t *testing.T) {
	w := makeWire(L3IPv4, L4TCP, TCPFlagSYN|TCPFlagACK, nil)
	ev, err := Parse(w)
	if err != nil {
		t.Fatalf("Parse err = %v", err)
	}
	if !ev.IsSYNACK() {
		t.Errorf("SYNACK = false on SYN+ACK")
	}
}

func TestParse_UDP(t *testing.T) {
	w := makeWire(L3IPv4, L4UDP, 0, []byte{0x01, 0x02})
	ev, err := Parse(w)
	if err != nil {
		t.Fatalf("Parse err = %v", err)
	}
	if ev.L4Proto != L4UDP {
		t.Errorf("L4 = %d, want UDP", ev.L4Proto)
	}
}

func TestParse_ICMP(t *testing.T) {
	w := makeWire(L3IPv4, L4ICMP, 0, nil)
	if _, err := Parse(w); err != nil {
		t.Errorf("ICMP should be accepted, got %v", err)
	}
}

func TestParse_ShortWire(t *testing.T) {
	w := make([]byte, 10)
	if _, err := Parse(w); err != ErrShortWire {
		t.Errorf("err = %v, want ErrShortWire", err)
	}
}

func TestParse_UnsupportedL3(t *testing.T) {
	w := makeWire(99, L4TCP, TCPFlagSYN, nil)
	if _, err := Parse(w); err != ErrUnsupportedL3 {
		t.Errorf("err = %v, want ErrUnsupportedL3", err)
	}
}

func TestParse_UnsupportedL4(t *testing.T) {
	w := makeWire(L3IPv4, 99, 0, nil)
	if _, err := Parse(w); err != ErrUnsupportedL4 {
		t.Errorf("err = %v, want ErrUnsupportedL4", err)
	}
}

func TestParse_IPv6(t *testing.T) {
	w := makeWire(L3IPv6, L4TCP, TCPFlagSYN, nil)
	ev, err := Parse(w)
	if err != nil {
		t.Fatalf("Parse err = %v", err)
	}
	if ev.L3Proto != L3IPv6 {
		t.Errorf("L3 = %d, want IPv6", ev.L3Proto)
	}
}

// TestParse_ZeroAlloc is the NFR gate for the
// decoder. The hot path must not allocate; if a
// future refactor introduces a `string(...)` or
// `append(...)`, the regression test catches it.
func TestParse_ZeroAlloc(t *testing.T) {
	w := makeWire(L3IPv4, L4TCP, TCPFlagSYN, []byte("data"))
	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = Parse(w)
	})
	if allocs != 0 {
		t.Errorf("Parse allocates %v allocs/op, want 0", allocs)
	}
}
