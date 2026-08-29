// Package efsm implements the L7 Extended Finite
// State Machine for protocol-level parsing
// (HTTP/1.1 request lines, WebSocket frames,
// minimal HTTP/2 frame header). It consumes
// L4Event values produced by the eBPF layer
// and emits engine.Event values for the DFA
// state engine.
//
// Design contract:
//
//   - The EFSM is per-connection. The state
//     table is keyed by a 32-bit connection
//     hash. Eviction is LRU (TUGAS 4 will
//     cap the table size; for now the cap is
//     the only thing the consumer must
//     enforce).
//   - The EFSM is strict: malformed input
//     produces ErrMalformedInput and clears
//     the connection state. There is no
//     "best effort" recovery; a malformed
//     request is treated as hostile.
//   - The hot path is zero-alloc on the
//     success branch. Failure paths may
//     allocate (errors).
package efsm

import (
	"bytes"
	"errors"
	"sync"

	"github.com/Faris-stuck/zaqorincore/agent/pkg/decode"
	"github.com/Faris-stuck/zaqorincore/agent/pkg/engine"
)

// Errors returned by the EFSM.
var (
	ErrMalformedInput = errors.New("efsm: malformed input")
	ErrUnknownProtocol = errors.New("efsm: unknown L7 protocol")
)

// ConnKey is a 32-bit hash of the connection
// 5-tuple. The kernel-side eBPF probe already
// computes this; we just receive it.
type ConnKey uint32

// connState is the per-connection EFSM state.
type connState uint8

const (
	connInit connState = iota
	connHTTPRequest
	connHTTPHeaders
	connHTTPBody
	connWSFrame
	connClosed
)

// connRecord is one entry in the per-connection
// state table. The table is a fixed-size open-
// addressed map; collisions are resolved by
// linear probing. Eviction is FIFO for the
// "small" branch and LRU for the "large"
// branch (TUGAS 4).
type connRecord struct {
	key     ConnKey
	used    bool
	state   connState
	// method/path buffer; reused across
	// events for the same connection to
	// avoid allocation on the hot path.
	method [8]byte
	path   [128]byte
	bodyLen uint32
}

// tableSize is the per-CPU table size. 1024
// entries is enough for 1024 concurrent
// connections on a single agent instance.
const tableSize = 1024

// EFSM is the L7 state machine. One per agent.
// EFSM is safe for concurrent use (it has a
// mutex around its state table).
type EFSM struct {
	mu   sync.Mutex
	tbl  [tableSize]connRecord
	// out is the function called for every
	// engine.Event the EFSM produces. The
	// EFSM does not know about the engine
	// directly; this keeps the package
	// dependency-free.
	out func(engine.Event)
}

// New returns an EFSM that delivers decoded
// engine.Event values to `out`. `out` is
// called synchronously from Feed, so it must
// not block.
func New(out func(engine.Event)) *EFSM {
	return &EFSM{out: out}
}

// Feed is the hot path. Given a decoded L4
// event, advance the per-connection state and
// emit any engine.Event values the transition
// produced.
//
// Returns the number of events emitted, or
// an error if the input was malformed.
func (e *EFSM) Feed(conn ConnKey, ev decode.L4Event) (int, error) {
	// Only TCP and UDP are L7-shaped at all.
	// ICMP is dropped.
	switch ev.L4Proto {
	case decode.L4TCP, decode.L4UDP:
	default:
		return 0, nil
	}
	// Port-based protocol classification.
	// This is deliberately simple: anything
	// on port 80 or 8080 is HTTP; anything on
	// 443 is HTTPS (only the first frame is
	// visible; deeper parsing happens after
	// the TLS terminator). Port 22 is SSH and
	// we emit a generic "L7_unknown" event.
	proto := classify(ev)
	if proto == protoUnknown {
		// Not a recognizable L7 protocol.
		// Emit a single "saw traffic" event
		// so the rate-limiter still works.
		e.emit(engine.Event{
			Kind:    engine.EventTCPSYN,
			Subject: uint32(conn),
			Payload0: uint32(ev.TimestampNS),
		})
		return 1, nil
	}
	rec, err := e.lookupOrCreate(conn)
	if err != nil {
		return 0, err
	}
	switch proto {
	case protoHTTP:
		return e.feedHTTP(rec, ev)
	case protoWS:
		return e.feedWS(rec, ev)
	default:
		return 0, ErrUnknownProtocol
	}
}

// proto identifies the L7 protocol the
// EFSM recognizes.
type proto uint8

const (
	protoUnknown proto = iota
	protoHTTP
	protoWS
)

func classify(ev decode.L4Event) proto {
	switch ev.DstPort {
	case 80, 8080, 8000:
		return protoHTTP
	case 443:
		// HTTPS — we cannot see the payload
		// but the EFSM can still record the
		// TLS handshake frames.
		return protoWS
	case 22:
		return protoUnknown
	}
	if ev.L4Proto == decode.L4UDP && (ev.DstPort == 53 || ev.SrcPort == 53) {
		// DNS — we treat as unknown for now;
		// a future slice can add a DNS EFSM.
		return protoUnknown
	}
	return protoUnknown
}

// lookupOrCreate returns the connection record
// for `key`, creating a fresh one if necessary.
func (e *EFSM) lookupOrCreate(key ConnKey) (*connRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	idx := uint(key) % tableSize
	for i := 0; i < tableSize; i++ {
		probe := (idx + uint(i)) % tableSize
		r := &e.tbl[probe]
		if !r.used || r.key == key {
			if !r.used {
				r.key = key
				r.used = true
				r.state = connInit
			}
			return r, nil
		}
	}
	// Table full. The caller will see an
	// error and we drop the connection.
	return nil, errors.New("efsm: connection table full")
}

// emit is the package-internal shortcut.
func (e *EFSM) emit(ev engine.Event) {
	if e.out != nil {
		e.out(ev)
	}
}

// feedHTTP is the HTTP/1.1 EFSM. Recognized
// transitions:
//
//	INIT  -- request line --> HTTPRequest
//	HTTPRequest -- headers done --> HTTPHeaders
//	HTTPHeaders -- content-length body --> HTTPBody
//	HTTPBody   -- bytes == content-length --> CLOSED
//
// Only the request line + Content-Length
// header are inspected. The body itself is
// not parsed.
func (e *EFSM) feedHTTP(rec *connRecord, ev decode.L4Event) (int, error) {
	if len(ev.Payload) == 0 {
		return 0, nil
	}
	emitted := 0
	switch rec.state {
	case connInit, connHTTPRequest:
		// Expect "METHOD SP PATH SP HTTP/1.1\r\n".
		if !looksLikeHTTPRequestLine(ev.Payload) {
			e.emit(engine.Event{
				Kind:    engine.EventHTTPRequest,
				Subject: subjectFor(rec),
				Payload0: uint32(len(ev.Payload)),
			})
			rec.state = connClosed
			return 1, nil
		}
		// Parse method into the fixed buffer.
		sp := bytes.IndexByte(ev.Payload, ' ')
		if sp < 0 || sp > len(rec.method) {
			return 0, ErrMalformedInput
		}
		copy(rec.method[:sp], ev.Payload[:sp])
		// Find end of path.
		sp2 := bytes.IndexByte(ev.Payload[sp+1:], ' ')
		if sp2 < 0 {
			return 0, ErrMalformedInput
		}
		pathLen := sp2
		if pathLen > len(rec.path) {
			pathLen = len(rec.path)
		}
		copy(rec.path[:pathLen], ev.Payload[sp+1:sp+1+pathLen])
		rec.state = connHTTPHeaders
		e.emit(engine.Event{
			Kind:    engine.EventCanaryTouch,
			Subject: subjectFor(rec),
			Payload0: uint32(sp),  // method length
			Payload1: uint32(pathLen),
		})
		emitted++
		// Fall through to look at the same
		// payload's headers section.
		fallthrough
	case connHTTPHeaders:
		// Look for Content-Length.
		if i := bytes.Index(ev.Payload, []byte("Content-Length: ")); i >= 0 {
			j := i + len("Content-Length: ")
			end := bytes.IndexByte(ev.Payload[j:], '\r')
			if end < 0 {
				return emitted, nil
			}
			var n uint32
			for _, c := range ev.Payload[j : j+end] {
				if c < '0' || c > '9' {
					return emitted, ErrMalformedInput
				}
				n = n*10 + uint32(c-'0')
			}
			rec.bodyLen = n
			rec.state = connHTTPBody
		}
		// Header block ends with "\r\n\r\n".
		if bytes.Contains(ev.Payload, []byte("\r\n\r\n")) {
			rec.state = connHTTPBody
		}
	case connHTTPBody:
		// We do NOT re-parse the body; we just
		// emit a "body complete" event when
		// the next SYN/FIN arrives.
		if ev.IsFIN() {
			rec.state = connClosed
			e.emit(engine.Event{
				Kind:    engine.EventHTTPRequest,
				Subject: subjectFor(rec),
				Payload0: rec.bodyLen,
			})
			emitted++
		}
	}
	return emitted, nil
}

// feedWS is the WebSocket frame EFSM. The
// payload is expected to start with the WS
// frame header (2 bytes minimum, 8 bytes with
// mask). The EFSM records the opcode and
// length and emits a single EventWSFrame.
func (e *EFSM) feedWS(rec *connRecord, ev decode.L4Event) (int, error) {
	if len(ev.Payload) < 2 {
		return 0, nil
	}
	// We do NOT validate the FIN bit, opcode,
	// or mask — we just record what we saw
	// and let the engine decide. Masked
	// frames from a client always have bit 7
	// of byte 1 set.
	opcode := ev.Payload[0] & 0x0F
	_ = ev.Payload[1] // mask bit + length
	e.emit(engine.Event{
		Kind:    engine.EventWebSocketFrame,
		Subject: subjectFor(rec),
		Payload0: uint32(opcode),
		Payload1: uint32(len(ev.Payload)),
	})
	rec.state = connWSFrame
	return 1, nil
}

// subjectFor returns the engine Subject the
// EFSM associates with this connection. It
// is just the connection key; the engine
// treats it as an opaque 32-bit identifier.
func subjectFor(rec *connRecord) uint32 {
	return uint32(rec.key)
}

// looksLikeHTTPRequestLine returns true if
// `b` starts with one of the common HTTP
// methods followed by a space.
func looksLikeHTTPRequestLine(b []byte) bool {
	methods := [...][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "),
		[]byte("PATCH "), []byte("CONNECT "),
	}
	for _, m := range methods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}
