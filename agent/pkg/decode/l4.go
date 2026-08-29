// Package decode parses the L3/L4 wire bytes produced
// by the kernel-side eBPF/XDP probes into a typed
// L4Event the user-space EFSM can consume.
//
// Design contract:
//
//   - The parser is STRICT: it does NOT silently
//     accept malformed input. Every wire variant
//     has a dedicated test in decode_test.go.
//   - The hot path is zero-alloc: the parser
//     returns a value type, no slices escape.
//   - The parser handles only what the kernel
//     side produces: IPv4, IPv6, TCP, UDP, ICMP,
//     ICMPv6. Everything else is rejected with
//     ErrUnsupportedProtocol.
//
// Wire format (matches the kernel-side struct
// __attribute__((packed)) in pkg/ebpf/probes/):
//
//	offset 0:   src_v4  [4]byte
//	offset 4:   dst_v4  [4]byte
//	offset 8:   src_v6  [16]byte
//	offset 24:  dst_v6  [16]byte
//	offset 40:  src_port uint16 (BE)
//	offset 42:  dst_port uint16 (BE)
//	offset 44:  l3_proto uint8 (4=IPv4, 6=IPv6, others unsupported)
//	offset 45:  l4_proto uint8 (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)
//	offset 46:  tcp_flags uint8 (only valid for L4=TCP)
//	offset 47:  _pad     uint8
//	offset 48:  payload_len uint16 (BE)
//	offset 50:  timestamp_ns uint64 (BE, monotonic kernel)
//
// Total = 58 bytes. The kernel pads to 64.
package decode

import (
	"encoding/binary"
	"errors"
)

// L3Proto values.
const (
	L3IPv4 uint8 = 4
	L3IPv6 uint8 = 6
)

// L4Proto values.
const (
	L4ICMP   uint8 = 1
	L4TCP    uint8 = 6
	L4UDP    uint8 = 17
	L4ICMPv6 uint8 = 58
)

// WireSize is the fixed wire format length. The
// kernel pads to 64 but we only need the first
// 58 bytes; the remaining 6 are zero.
const WireSize = 58

// Errors returned by Parse.
var (
	ErrShortWire        = errors.New("decode: wire shorter than 58 bytes")
	ErrUnsupportedL3    = errors.New("decode: unsupported L3 protocol")
	ErrUnsupportedL4    = errors.New("decode: unsupported L4 protocol")
	ErrPayloadOverrun   = errors.New("decode: payload_len exceeds wire")
)

// L4Event is the decoded L3/L4 event. It carries
// the source/destination 5-tuple, the L3/L4
// protocols, TCP flags, and the kernel-supplied
// monotonic timestamp.
//
// L4Event is a value type (no pointers, no
// slices). The hot path never escapes to the
// heap.
type L4Event struct {
	SrcIP       [16]byte // IPv4 in the first 4 bytes; IPv6 in all 16
	DstIP       [16]byte
	SrcPort     uint16
	DstPort     uint16
	L3Proto     uint8
	L4Proto     uint8
	TCPFlags    uint8
	PayloadLen  uint16
	TimestampNS uint64
	// Payload is a slice into the input wire
	// bytes, NOT a copy. The caller MUST treat
	// the input buffer as immutable for the
	// lifetime of the returned L4Event, or
	// copy the payload before returning to
	// the input source.
	Payload []byte
}

// TCP flag bits. Matches RFC 793.
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
	TCPFlagURG uint8 = 0x20
	TCPFlagECE uint8 = 0x40
	TCPFlagCWR uint8 = 0x80
)

// Parse decodes one wire event. It returns
// (event, nil) on success, (zero, Err*) on
// failure. The returned event.Payload shares
// memory with `wire` (no copy).
func Parse(wire []byte) (L4Event, error) {
	if len(wire) < WireSize {
		return L4Event{}, ErrShortWire
	}
	var ev L4Event
	copy(ev.SrcIP[:], wire[0:4])
	copy(ev.DstIP[:], wire[4:8])
	// Wire stores IPv6 in bytes 8..24 of the
	// SADDR and 24..40 of the DADDR, but only
	// when L3Proto == IPv6. For IPv4 we just
	// zero those fields.
	if wire[44] == L3IPv6 {
		copy(ev.SrcIP[4:], wire[8:16])
		copy(ev.DstIP[4:], wire[24:32])
	}
	ev.SrcPort = binary.BigEndian.Uint16(wire[40:42])
	ev.DstPort = binary.BigEndian.Uint16(wire[42:44])
	ev.L3Proto = wire[44]
	ev.L4Proto = wire[45]
	ev.TCPFlags = wire[46]
	// wire[47] is padding.
	ev.PayloadLen = binary.BigEndian.Uint16(wire[48:50])
	ev.TimestampNS = binary.BigEndian.Uint64(wire[50:58])

	switch ev.L3Proto {
	case L3IPv4, L3IPv6:
	default:
		return L4Event{}, ErrUnsupportedL3
	}
	switch ev.L4Proto {
	case L4TCP, L4UDP, L4ICMP, L4ICMPv6:
	default:
		return L4Event{}, ErrUnsupportedL4
	}
	// Payload slice (no copy).
	plen := int(ev.PayloadLen)
	if plen > len(wire)-WireSize {
		plen = len(wire) - WireSize
	}
	ev.Payload = wire[WireSize : WireSize+plen]
	return ev, nil
}

// IsSYN, IsRST, etc. are tiny helpers the
// EFSM uses to make the call sites readable.
// They are 1-cycle ALU ops; the engine
// inliner removes the call.

func (e L4Event) IsSYN() bool { return e.L4Proto == L4TCP && e.TCPFlags&TCPFlagSYN != 0 }
func (e L4Event) IsRST() bool { return e.L4Proto == L4TCP && e.TCPFlags&TCPFlagRST != 0 }
func (e L4Event) IsFIN() bool { return e.L4Proto == L4TCP && e.TCPFlags&TCPFlagFIN != 0 }
func (e L4Event) IsACK() bool { return e.L4Proto == L4TCP && e.TCPFlags&TCPFlagACK != 0 }
func (e L4Event) IsSYNACK() bool { return e.IsSYN() && e.IsACK() }
