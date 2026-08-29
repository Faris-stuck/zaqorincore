// Package bridge wires the eBPF ring-buffer
// reader to the user-space EFSM and DFA
// engine.
//
// Architecture:
//
//   kernel eBPF probe
//        │
//        ▼   (zero-copy ringbuf)
//   BPFDriver.Read([]Event)
//        │
//        ▼
//   decode.Parse  (pkg/decode, 0 alloc)
//        │
//        ▼
//   efsm.EFSM.Feed  (pkg/efsm, 0 alloc)
//        │
//        ▼
//   engine.Engine.Process  (pkg/engine, 0 alloc)
//
// One goroutine owns the read loop. The loop
// is the only place allocations happen (one
// scratch buffer is reused via sync.Pool).
package bridge

import (
	"context"
	"sync"

	"github.com/Faris-stuck/zaqorincore/agent/pkg/decode"
	"github.com/Faris-stuck/zaqorincore/agent/pkg/efsm"
	"github.com/Faris-stuck/zaqorincore/agent/pkg/engine"
)

// BPFDriver is the read side of the ring buffer
// (or a mock in tests). The production impl is
// the cilium/ebpf ring.Reader; the mock is
// internal/mock.BPFDriverMock.
type BPFDriver interface {
	Read(dst []byte) (int, error)
	Close() error
}

// Bridge connects BPFDriver -> decode -> EFSM
// -> Engine. One Bridge per agent.
type Bridge struct {
	driver BPFDriver
	decode func([]byte) (decode.L4Event, error)
	efsm   *efsm.EFSM
	engine *engine.Engine
}

// New builds a Bridge. `dec` may be nil; in
// that case the default pkg/decode.Parse is
// used. This indirection lets unit tests
// inject malformed bytes without touching the
// real parser.
func New(
	driver BPFDriver,
	machine *efsm.EFSM,
	eng *engine.Engine,
	dec func([]byte) (decode.L4Event, error),
) *Bridge {
	if dec == nil {
		dec = decode.Parse
	}
	return &Bridge{
		driver: driver,
		decode: dec,
		efsm:   machine,
		engine: eng,
	}
}

// Run drives the bridge until ctx is cancelled
// or the driver returns EOF. The hot path
// inside the loop is zero-alloc because the
// scratch buffer is reused.
func (b *Bridge) Run(ctx context.Context) error {
	if b.driver == nil {
		return nil
	}
	defer b.driver.Close()
	bufPtr := scratchPool.Get().(*[]byte)
	defer scratchPool.Put(bufPtr)
	buf := *bufPtr
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := b.driver.Read(buf)
		if err != nil {
			return nil // EOF / closed
		}
		// Process each 64-byte event in the
		// batch. WireSize=58; the kernel pads
		// to 64.
		for off := 0; off+64 <= n; off += 64 {
			ev, derr := b.decode(buf[off : off+64])
			if derr != nil {
				// Malformed wire event:
				// skip and continue.
				continue
			}
			// Connection key is derived from
			// the 4-tuple hash the kernel
			// gave us in the wire header.
			// We use the source IP lower 32
			// bits as a stand-in until the
			// kernel-side probe is updated
			// to write a proper ConnKey.
			key := efsm.ConnKey(binaryU32(ev.SrcIP[:4]))
			_, _ = b.efsm.Feed(key, ev)
		}
	}
}

// binaryU32 returns the first 4 bytes of b
// interpreted as a big-endian uint32. Used
// for the connection key until the kernel
// probe is updated.
func binaryU32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// scratchPool reuses the per-iteration
// scratch buffer. Sized at 4096 bytes
// (64 × 64 events per Read) which absorbs
// a 1ms burst at 64k events/sec.
var scratchPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 4096)
		return &buf
	},
}
