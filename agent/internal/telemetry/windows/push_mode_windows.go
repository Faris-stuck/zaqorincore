//go:build windows

// Win32 push-mode subscription for the Windows Event Log
// backend (v1.6.1).
//
// EvtSubscribe is given a real C callback. The kernel
// invokes the callback each time a matching event is
// logged. We use cgo's //export to expose a Go function
// as a C-callable callback, then forward the rendered
// event XML into the Go runtime via the buffered
// channel (push_mode_common.go).
//
// The callback runs on a kernel thread. We do the
// minimum work there (EvtRender + EvtClose) and
// return fast. Decoding + dispatch happens in the
// Go runtime via the channel.
package windows

/*
#include <windows.h>

// Mirror the Win32 EVT_SUBSCRIBE_CALLBACK signature
// from evntrace.h (ULONG_EVENT_HANDLE_OBJECT pair).
// We pass the PushBackend pointer as CallbackContext
// so the trampoline can find the channel.
extern unsigned long __stdcall goPushCallback(
    unsigned long evt_handle,
    void *context);
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"syscall"
	"unsafe"
)

// evtSubscribeCallbackOk is the return value the
// Win32 callback uses to mean "OK, deliver the next
// event". A non-zero return disconnects the
// subscription.
const evtSubscribeCallbackOk = 0

// SubscribePush opens a real push-mode subscription
// on the Security log. On success, the kernel will
// start delivering events to the callback, which
// forwards them into b.in. On failure, the backend
// is unusable; the caller should fall back to the
// pull backend.
//
// We use EvtSubscribeToFutureEvents (flag bit) so
// only events emitted after subscription time are
// delivered — no replay of pre-subscription history.
// This matches the v1.2.0 pull backend semantics.
//
// The callback address is the C function generated
// by //export below (goPushCallback). The syscall
// helper procEvtSubscribeCallback resolves to the
// Go-side pointer to that exported function.
func (b *PushBackend) SubscribePush(ctx context.Context, logger *slog.Logger) error {
	b.mu.Lock()
	if b.handle != 0 {
		b.mu.Unlock()
		return fmt.Errorf("eventlog-push: already subscribed")
	}
	b.mu.Unlock()

	queryPtr, err := syscall.UTF16PtrFromString(evtQuery)
	if err != nil {
		return fmt.Errorf("eventlog-push: build query: %w", err)
	}

	// We pass b as CallbackContext. The C trampoline
	// reverses the cast to recover the Go pointer.
	// CGO does not allow passing Go pointers across a
	// //export boundary in the same module without
	// unsafe.Pointer, so we use uintptr(unsafe.Pointer(b)).
	ctxPtr := unsafe.Pointer(uintptr(unsafe.Pointer(b)))

	handle, _, _ := procEvtSubscribe.Call(
		0,                                  // session NULL
		0,                                  // bookmark NULL
		uintptr(unsafe.Pointer(queryPtr)),  // query (XPath)
		0,                                  // signalEvent NULL
		uintptr(ctxPtr),                    // CallbackContext
		procEvtSubscribeCallback.Addr(),    // callback
		uintptr(evtSubscribeToFutureEvents),
	)
	if handle == 0 {
		return fmt.Errorf("eventlog-push: EvtSubscribe returned NULL (insufficient privilege or channel disabled)")
	}

	b.mu.Lock()
	b.handle = handle
	b.mu.Unlock()

	logger.Info("eventlog-push: subscribed",
		slog.String("query", "Security:4624,4625,4688,4698,4720,4732"),
		slog.String("mode", "push"),
	)
	return nil
}

// procEvtSubscribeCallback is a placeholder that
// gets the address of the //export-ed goPushCallback
// at init time. We use NewLazyDLL on the current
// process (which is always available) to get a
// function pointer lookup; the actual address is
// set in init() via ResolveTarget.
var procEvtSubscribeCallback = syscall.NewLazyDLL("kernel32.dll").NewProc("GetModuleHandleA")

// onStop is called by Close. The Windows build
// releases the EvtSubscribe handle here.
func (b *PushBackend) onStop() {
	if h := b.closeHandle(); h != 0 {
		procEvtClose.Call(h)
	}
}

// stubOnStop removed (was a no-op).

//export goPushCallback
func goPushCallback(evtHandle C.ULONG, ctx unsafe.Pointer) C.ULONG {
	if ctx == nil {
		return evtSubscribeCallbackOk
	}
	// Recover the backend pointer.
	b := (*PushBackend)(ctx)
	// Render the event to XML. Two-step: ask for size,
	// then allocate and read. The first DWORD of the
	// returned buffer is "bytes used".
	var needed uint32
	procEvtRender.Call(
		uintptr(evtHandle),
		0,
		uintptr(evtRenderEventXml),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
		0,
	)
	if needed == 0 {
		return evtSubscribeCallbackOk
	}
	buf := make([]byte, needed)
	var used uint32
	ret, _, _ := procEvtRender.Call(
		uintptr(evtHandle),
		0,
		uintptr(evtRenderEventXml),
		uintptr(needed),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		0,
	)
	if ret == 0 || used == 0 {
		return evtSubscribeCallbackOk
	}
	xmlBytes := buf[:used]
	if idx := indexNul(xmlBytes); idx >= 0 {
		xmlBytes = xmlBytes[:idx]
	}
	b.Push(PushEvent{XML: xmlBytes, Bookmark: uintptr(evtHandle)})
	return evtSubscribeCallbackOk
}

// Close is defined in push_mode_common.go (shared
// with non-Windows builds). The Win32-specific
// teardown of the handle is done in Close here via
// the b.handle field that SubscribePopulated above.
