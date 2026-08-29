//go:build !windows

// Stub for non-Windows builds. The real Win32 push-mode
// subscription lives in push_mode_windows.go (//go:build
// windows). On Linux/macOS this file compiles to a no-op
// that returns a clear "not supported" error from Run.
package windows

import (
	"context"
	"fmt"
	"log/slog"
)

// SubscribePush is the platform entry point. On
// non-Windows hosts it always returns an error so the
// agent can fall back to the pull backend.
func (b *PushBackend) SubscribePush(_ context.Context, _ *slog.Logger) error {
	return fmt.Errorf("eventlog-push: not supported on this platform (build tag: windows required)")
}

// onStop is a no-op on non-Windows builds (the
// Windows build in push_mode_windows.go releases
// the EvtSubscribe handle).
func (b *PushBackend) onStop() {}
