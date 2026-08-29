package mock

import (
	"errors"
	"sync"
	"time"
)

// NetworkPacket is a single packet observed by
// the user-space stream. The production stream
// reads from a raw socket via AF_PACKET; the mock
// generates a scripted sequence.
type NetworkPacket struct {
	// 5-tuple summary (mock is L3/L4-only).
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 // 6=TCP, 17=UDP, 1=ICMP
	// TCP flags when Protocol == 6. 0 otherwise.
	TCPFlags uint8
	// Payload length in bytes.
	PayloadLen uint16
	// TimestampNS filled in by the mock at push.
	TimestampNS uint64
}

// NetworkStream is the interface the engine
// depends on for L7-shaped ingest (HTTP, WS
// frame parsing, etc., after a packet has been
// reassembled).
type NetworkStream interface {
	// NextPacket returns the next packet or
	// (nil, io.EOF) on close.
	NextPacket() (*NetworkPacket, error)
	Close() error
}

// NetworkStreamMock is an in-memory scripted
// packet source.
type NetworkStreamMock struct {
	mu     sync.Mutex
	closed bool
	cond   *sync.Cond
	queue  []*NetworkPacket
}

func NewNetworkStreamMock() *NetworkStreamMock {
	s := &NetworkStreamMock{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Push enqueues one packet.
func (s *NetworkStreamMock) Push(p *NetworkPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if p.TimestampNS == 0 {
		p.TimestampNS = uint64(time.Now().UnixNano())
	}
	s.queue = append(s.queue, p)
	s.cond.Signal()
}

// PushTCP is a convenience for TCP packets.
func (s *NetworkStreamMock) PushTCP(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, flags uint8, payloadLen uint16) {
	s.Push(&NetworkPacket{
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		Protocol: 6, TCPFlags: flags,
		PayloadLen: payloadLen,
	})
}

// NextPacket blocks until a packet is available
// or the stream is closed.
func (s *NetworkStreamMock) NextPacket() (*NetworkPacket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.queue) == 0 && !s.closed {
		s.cond.Wait()
	}
	if s.closed && len(s.queue) == 0 {
		return nil, errEOF
	}
	p := s.queue[0]
	s.queue = s.queue[1:]
	return p, nil
}

func (s *NetworkStreamMock) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.cond.Broadcast()
	return nil
}

// errClosed is a separate sentinel used by
// tests that want to distinguish "stream closed
// cleanly" from "next call before any packet
// arrived" — for now, both are io.EOF-equivalent.
var errClosed = errors.New("mock: stream closed")
