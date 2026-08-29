//go:build !windows

package app

import (
	"log/slog"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
)

// NewWindowsEventlogBackend returns (nil, nil) on
// non-Windows builds. The Windows build
// (windows_eventlog_windows.go) returns a real
// push-mode backend.
//
// The reason for the platform split: app.Run() only
// calls this when cfg.WindowsEventlog.Mode == "push",
// and on non-Windows hosts that mode is meaningless.
// The agent still runs fine — it just won't start a
// Windows eventlog subscription.
func NewWindowsEventlogBackend(
	_ *config.Config, _ *slog.Logger,
) (WindowsEventlogBackend, error) {
	return nil, nil
}
