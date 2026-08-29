// Cross-platform helpers for the Windows ETW push-mode backend
// (v1.6.0).
//
// Push mode is an alternative to the v1.2.0 pull backend:
// EvtSubscribe is given a C callback that the kernel
// invokes as events arrive. Latency drops from the
// poll interval (1s) to the event's actual arrival
// time (sub-millisecond on Windows 10 1903+).
//
// The C callback is a CGO trampoline — defining it
// for Windows requires `//go:build windows` because
// we need to import "C" and use //export. To keep
// the type signatures and helpers unit-testable on
// Linux, the cross-platform types live here.
package windows

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
)

// PushEvent is the minimal handoff between the Win32
// callback and the Go runtime. The callback marshals
// the event, then sends to a buffered channel; the
// Go goroutine pulls from the channel and runs the
// user's handler.
type PushEvent struct {
	// XML is the rendered event XML, exactly as EvtRender
	// would have produced. Bytes (not string) because
	// that's what the Win32 side has natively.
	XML []byte
	// Bookmark is an EVT_HANDLE the kernel can use to
	// resume after a crash. We capture it via the
	// EVT_SUBSCRIBE_CALLBACK signature's first parameter
	// (the EVENT_OBJECT).
	//
	// Stored as uintptr (opaque) on Linux test builds;
	// the real Win32 handle type lives in
	// push_mode_windows.go under //go:build windows.
	Bookmark uintptr
}

// PushBackend implements telemetry.Backend in push mode.
// It runs a goroutine that reads from `in` and forwards
// each event to the user's handler, while the C callback
// fills the channel.
//
// The actual Win32 subscription is set up in
// push_mode_windows.go (//go:build windows).
type PushBackend struct {
	hostID string
	logger *slog.Logger

	// in receives events from the C callback.
	in chan PushEvent

	// mu protects handle during shutdown.
	mu      sync.Mutex
	handle  uintptr
	done    chan struct{}
	stopped bool
}

// NewPush returns a new push-mode backend. The channel
// buffer is sized for one second of worst-case event
// volume; a Windows host generates a few hundred
// security events per second under heavy load, so 1024
// is a safe round number.
func NewPush(hostID string, logger *slog.Logger) *PushBackend {
	return &PushBackend{
		hostID:  hostID,
		logger:  logger,
		in:      make(chan PushEvent, 1024),
		done:    make(chan struct{}),
	}
}

// Name implements telemetry.Backend.
func (b *PushBackend) Name() string { return "windows/eventlog-push" }

// Run drains the channel and forwards each event to
// the user's handler until ctx is canceled. The
// Win32 subscription is started by the caller before
// Run (via SubscribePush) and stopped by the caller
// after Run returns (via ClosePush).
func (b *PushBackend) Run(ctx context.Context, handler func([]byte) error) error {
	b.logger.Info("eventlog-push: drain loop started",
		slog.Int("buffer", cap(b.in)))

	for {
		select {
		case <-ctx.Done():
			b.logger.Info("eventlog-push: shutdown")
			return ctx.Err()
		case ev := <-b.in:
			wire, err := buildWireEvent(ev.XML)
			if err != nil {
				b.logger.Debug("eventlog-push: build wire",
					slog.String("error", err.Error()))
				continue
			}
			payload, err := json.Marshal(wire)
			if err != nil {
				b.logger.Debug("eventlog-push: marshal",
					slog.String("error", err.Error()))
				continue
			}
			if err := handler(payload); err != nil {
				b.logger.Debug("eventlog-push: handler",
					slog.String("error", err.Error()))
			}
		}
	}
}

// Push is called from the C callback (via a wrapper in
// push_mode_windows.go). It non-blockingly enqueues the
// event. If the channel is full, the event is dropped and
// logged — failing the kernel callback is worse than
// dropping an event (the kernel would retry, blocking
// the whole subscription).
func (b *PushBackend) Push(ev PushEvent) {
	select {
	case b.in <- ev:
		// queued
	default:
		b.logger.Warn("eventlog-push: channel full, dropping event",
			slog.Int("buffer", cap(b.in)))
	}
}

// Close stops the backend. Idempotent.
func (b *PushBackend) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return
	}
	b.stopped = true
	close(b.done)
}
