package mock

import (
	"sync"
	"testing"
	"time"
)

func TestBPFDriverMock_PushRead(t *testing.T) {
	d := NewBPFDriverMock()
	d.PushEvent(BPFEvent{Kind: 1, Subject: 42})
	d.PushEvent(BPFEvent{Kind: 2, Subject: 43})
	dst := make([]BPFEvent, 4)
	n, err := d.Read(dst)
	if err != nil {
		t.Fatalf("Read err = %v", err)
	}
	if n != 2 {
		t.Errorf("Read n = %d, want 2", n)
	}
	if dst[0].Subject != 42 || dst[1].Subject != 43 {
		t.Errorf("got subjects %d %d, want 42 43", dst[0].Subject, dst[1].Subject)
	}
	if dst[0].TimestampNS == 0 {
		t.Error("TimestampNS not auto-filled")
	}
}

func TestBPFDriverMock_CloseReturnsEOF(t *testing.T) {
	d := NewBPFDriverMock()
	d.Close()
	dst := make([]BPFEvent, 1)
	n, err := d.Read(dst)
	if n != 0 || err == nil {
		t.Errorf("Read after close: n=%d err=%v, want (0, EOF)", n, err)
	}
}

func TestNetworkStreamMock_PushNext(t *testing.T) {
	s := NewNetworkStreamMock()
	var src [4]byte
	src[0] = 10
	s.PushTCP(src, 1234, [4]byte{192, 168, 1, 1}, 80, 0x02, 64)
	p, err := s.NextPacket()
	if err != nil {
		t.Fatalf("NextPacket err = %v", err)
	}
	if p.SrcPort != 1234 || p.TCPFlags != 0x02 {
		t.Errorf("got %+v, want port=1234 flags=0x02", p)
	}
}

func TestCanaryStoreMock_TouchAndLookup(t *testing.T) {
	c := NewCanaryStoreMock()
	c.Register("tok-1")
	if first := c.Touch("tok-1", 7); !first {
		t.Error("first touch should return true")
	}
	if first := c.Touch("tok-1", 7); first {
		t.Error("second touch should return false")
	}
	e, ok := c.Lookup("tok-1")
	if !ok {
		t.Fatal("Lookup ok=false")
	}
	if e.Subject != 7 || e.TouchCount != 2 {
		t.Errorf("got %+v, want subject=7 count=2", e)
	}
}

// TestConcurrentPushes asserts that all three
// mocks are safe for concurrent callers (so
// tests can drive them from multiple goroutines
// when simulating multi-source traffic).
func TestConcurrentPushes(t *testing.T) {
	d := NewBPFDriverMock()
	s := NewNetworkStreamMock()
	c := NewCanaryStoreMock()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d.PushEvent(BPFEvent{Kind: uint8(i)})
			s.PushTCP([4]byte{10, 0, 0, byte(i)}, 80, [4]byte{1, 1, 1, 1}, 80, 0x02, 0)
			c.Register("tok")
			c.Touch("tok", uint32(i))
			time.Sleep(time.Millisecond)
		}(i)
	}
	wg.Wait()
}
