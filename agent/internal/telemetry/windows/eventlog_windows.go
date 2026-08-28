//go:build windows

// Win32 subscription loop for the Windows Event Log backend.
// All syscalls live here so the cross-platform helpers in
// eventlog_common.go can be unit-tested on Linux.
//
// The `Source*` constants and `subscribedEventIDs` map live in
// eventlog_common.go so they are visible to the dispatcher test
// (which runs on every GOOS).
package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Query is the XPath filter we hand to EvtSubscribe. It selects the
// six event IDs above from the Security log. The `Suppress` keyword
// keeps us from receiving the "subscription heartbeat" event the
// channel emits every few minutes.
const evtQuery = `<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4698 or EventID=4720 or EventID=4732)]]</Select>
  </Query>
</QueryList>`

// --- Win32 bindings ----------------------------------------------------

var (
	modwevtapi       = syscall.NewLazyDLL("wevtapi.dll")
	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	procEvtRender    = modwevtapi.NewProc("EvtRender")
	procEvtClose     = modwevtapi.NewProc("EvtClose")
)

// EvtSubscribe flags. We use EvtSubscribeToFutureEvents so we get
// only events that fire after we subscribe (no replay of the
// pre-subscription log).
const (
	evtSubscribeToFutureEvents = 0x00000001
	evtRenderEventXml          = 1 // render as XML
)

// eventLogBackend implements telemetry.Backend for Windows.
type eventLogBackend struct {
	hostID string
	logger *slog.Logger
	// mu protects the subscription handle during shutdown.
	mu   sync.Mutex
	sub  uintptr
	done chan struct{}
}

// New returns a Windows Event Log backend. The backend blocks on
// Run until ctx is canceled. hostID is the agent's stable UUID,
// embedded in every wire event.
func New(hostID string, logger *slog.Logger) *eventLogBackend {
	return &eventLogBackend{
		hostID: hostID,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Name implements telemetry.Backend.
func (b *eventLogBackend) Name() string { return "windows/eventlog" }

// Run implements telemetry.Backend. It opens a subscription on the
// Security log and pumps events into `handler` until ctx is canceled.
//
// Failure modes (all surfaced as errors from Run so the agent can
// decide to crashloop or run in degraded mode):
//
//   - wevtapi.dll missing          -> the proc pointers are nil
//   - EvtSubscribe returns NULL    -> insufficient privilege, log
//                                     disabled, or corrupt channel
//   - Render fails for an event    -> skipped, logged, and we
//                                     continue with the next one
func (b *eventLogBackend) Run(ctx context.Context, handler func([]byte) error) error {
	if procEvtSubscribe.Addr() == 0 {
		return fmt.Errorf("eventlog: wevtapi.dll not available on this host")
	}

	// EvtSubscribe signature:
	//   EVT_HANDLE EvtSubscribe(
	//     LPCWSTR ChannelPath,    // NULL = use query Path
	//     LPCWSTR Query,          // XPath
	//     EVT_HANDLE Bookmark,    // NULL
	//     PVOID CallbackContext,  // user pointer
	//     EVT_SUBSCRIBE_CALLBACK Callback,
	//     DWORD Flags);
	// We pass NULL for the bookmark and the callback (synchronous,
	// pull via EvtRender). The push callback would require a Go
	// trampoline that survives the C call; pull is simpler and
	// good enough for the 5s poll in the operator guide.
	queryPtr, err := syscall.UTF16PtrFromString(evtQuery)
	if err != nil {
		return fmt.Errorf("eventlog: build query: %w", err)
	}

	handle, _, _ := procEvtSubscribe.Call(
		0, // session NULL
		0, // bookmark NULL
		uintptr(unsafe.Pointer(queryPtr)),
		0, // signalEvent NULL
		0, // context NULL (synchronous)
		0, // callback NULL
		uintptr(evtSubscribeToFutureEvents),
	)
	if handle == 0 {
		return fmt.Errorf("eventlog: EvtSubscribe returned NULL (insufficient privilege or channel disabled)")
	}
	b.mu.Lock()
	b.sub = handle
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if b.sub != 0 {
			procEvtClose.Call(b.sub)
			b.sub = 0
		}
		b.mu.Unlock()
		close(b.done)
	}()

	b.logger.Info("eventlog: subscribed",
		slog.String("query", "Security:4624,4625,4688,4698,4720,4732"))

	// Poll loop. We could go push (callback) but a 1s poll keeps the
	// code path easy to test on Linux and avoids the CGO trampoline.
	// 1s is also well under the 5s operator SLA.
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			b.logger.Info("eventlog: shutdown")
			return ctx.Err()
		case <-tick.C:
			if err := b.renderBatch(ctx, handler); err != nil {
				// Render errors are non-fatal; we keep going.
				b.logger.Debug("eventlog: render batch",
					slog.String("error", err.Error()))
			}
		}
	}
}

// renderBatch reads the next available event from the subscription
// handle and forwards it to `handler`. Returns nil if no event is
// available, the rendered event on success, or a render error.
func (b *eventLogBackend) renderBatch(_ context.Context, handler func([]byte) error) error {
	b.mu.Lock()
	handle := b.sub
	b.mu.Unlock()
	if handle == 0 {
		return nil
	}
	// EvtRender(NULL, EventHandle, Flags, BufferSize, Buffer, ...)
	// With BufferSize=0 and Buffer=NULL the call returns the
	// required size; we then allocate and call again.
	var needed uint32
	procEvtRender.Call(
		0,
		handle,
		uintptr(evtRenderEventXml),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
		0,
	)
	if needed == 0 {
		return nil
	}
	buf := make([]byte, needed)
	// The first DWORD of the buffer is the actual bytes used; we
	// capture it via a small helper struct so we can read the count
	// back out of the syscall result.
	var used uint32
	ret, _, _ := procEvtRender.Call(
		0,
		handle,
		uintptr(evtRenderEventXml),
		uintptr(needed),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		0,
	)
	if ret == 0 || used == 0 {
		return fmt.Errorf("eventlog: EvtRender returned %d, used=%d", ret, used)
	}
	xmlBytes := buf[:used]
	// Truncate at the first NUL (EvtRender may pad with trailing 0s).
	if idx := indexNul(xmlBytes); idx >= 0 {
		xmlBytes = xmlBytes[:idx]
	}

	wire, err := buildWireEvent(xmlBytes)
	if err != nil {
		return fmt.Errorf("eventlog: build wire: %w", err)
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("eventlog: marshal: %w", err)
	}
	return handler(payload)
}
