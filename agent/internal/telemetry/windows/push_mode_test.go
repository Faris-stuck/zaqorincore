// Cross-platform tests for the v1.6.0 push-mode drain
// loop. The Win32 EvtSubscribe callback itself lives
// in push_mode_windows.go (//go:build windows) and
// requires MinGW to cross-build. What we can verify
// on Linux is:
//
//  1. The drain loop reads from the channel and
//     forwards each event to the handler.
//  2. The drop-on-full path is taken when the
//     channel is full (no blocking).
//  3. Close is idempotent.
//  4. ctx cancellation stops the loop.
package windows

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
)

// newTestBackend returns a PushBackend with a small
// buffer so the drop-on-full path is easy to trigger
// in tests.
func newTestBackend(buf int) *PushBackend {
	return &PushBackend{
		hostID:  "test-host",
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		in:      make(chan PushEvent, buf),
		done:    make(chan struct{}),
	}
}

func validEvent4624XML() []byte {
	// Minimal well-formed Event XML containing EventID=4624
	// so buildWireEvent accepts it (4624 is in
	// subscribedEventIDs). The payload is otherwise empty;
	// the test only counts handler invocations, not field
	// extraction.
	return []byte(`<Event><System><EventID>4624</EventID><Provider Name="MS"/></System><EventData><Data>a</Data><Data>b</Data><Data>c</Data><Data>d</Data><Data>e</Data><Data>f</Data><Data>g</Data><Data>h</Data><Data>10</Data><Data>j</Data><Data>k</Data><Data>l</Data><Data>m</Data><Data>n</Data><Data>o</Data><Data>p</Data><Data>q</Data><Data>1.2.3.4</Data><Data>9999</Data></EventData></Event>`)
}

func TestPushBackend_ForwardsEventsToHandler(t *testing.T) {
	b := newTestBackend(4)
	defer b.Close()

	var received int64
	handler := func(payload []byte) error {
		atomic.AddInt64(&received, 1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go b.Run(ctx, handler)

	// Use a real eventID that buildWireEvent accepts.
	for i := 0; i < 3; i++ {
		b.Push(PushEvent{XML: validEvent4624XML()})
	}
	time.Sleep(200 * time.Millisecond)

	if got := atomic.LoadInt64(&received); got != 3 {
		t.Errorf("expected 3 events, got %d", got)
	}
}

func TestPushBackend_DropsOnFullChannel(t *testing.T) {
	b := newTestBackend(1)
	// Don't call Close — the channel stays at cap 1.
	// Don't start Run — we want to fill the channel
	// without it being drained.
	for i := 0; i < 5; i++ {
		b.Push(PushEvent{XML: []byte("x")})
	}
	// If Push were blocking, the test would deadlock
	// before reaching this line. The fact that we get
	// here means Push correctly returned instead of
	// blocking.
	if got := len(b.in); got > 1 {
		t.Errorf("channel grew beyond cap: %d", got)
	}
}

func TestPushBackend_CloseIdempotent(t *testing.T) {
	b := newTestBackend(1)
	b.Close()
	b.Close() // second close must not panic
	// done must be closed exactly once.
	select {
	case <-b.done:
		// ok
	default:
		t.Errorf("done channel was not closed")
	}
}

func TestPushBackend_ConfigPullIsDefault(t *testing.T) {
	// The wiring in main.go (TODO v1.6.2) will read
	// cfg.WindowsEventlog.Mode and choose between
	// New() (pull, default) and NewPush() (push,
	// v1.6.1+). For now, this test documents the
	// contract: default mode = pull. If the default
	// changes, this test fails loud.
	cfg := config.Defaults()
	if cfg.WindowsEventlog.Mode != "pull" {
		t.Errorf("default windows_eventlog.mode = %q, want pull", cfg.WindowsEventlog.Mode)
	}
}

func TestPushBackend_CtxCancelStopsRun(t *testing.T) {
	b := newTestBackend(1)
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())

	doneCh := make(chan error, 1)
	go func() { doneCh <- b.Run(ctx, func(p []byte) error { return nil }) }()

	cancel()
	select {
	case <-doneCh:
		// Run returned
	case <-time.After(1 * time.Second):
		t.Errorf("Run did not return within 1s of ctx cancel")
	}
}
