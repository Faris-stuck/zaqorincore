// Package telemetry holds the platform-specific event-capture
// backends for the ZaqorinCore agent.
//
// v1.0.0 ships only the Linux file-tail backend. v1.2 (ADR-007)
// adds Windows Event Log and macOS Endpoint Security
// Framework backends. Slices 1 of v1.2 (this file + the
// windows/ and darwin/ subpackages) provides the registry
// skeleton that returns "platform not implemented" so the
// build matrix compiles cleanly for all five GOOS targets.
// v1.2 Slice 2 (this file) wires the real Windows Event Log
// backend (see internal/telemetry/windows) for the windows
// branch. The darwin branch remains the Slice 1 sentinel
// because macOS is explicitly out of scope for v1.2
// (user said "Yasudah windows dan Linux saja tidak usah mac").
package telemetry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Faris-stuck/zaqorincore/agent/internal/telemetry/windows"
)

// Backend is the abstraction main.go calls to start a
// platform's telemetry source. It blocks until ctx is
// canceled. Events are delivered to the handler as raw
// bytes (the wire wire format is owned by internal/event).
type Backend interface {
	Run(ctx context.Context, handler func([]byte) error) error
	Name() string
}

// NewForPlatform returns the telemetry backend for the
// current build target. v1.2 Slice 2 (this file) wires the
// real Windows Event Log backend (see
// internal/telemetry/windows). The darwin branch keeps the
// Slice 1 sentinel because macOS is out of scope for v1.2.
// The linux branch is wired by main.go via internal/tailer.
func NewForPlatform(platform string, hostID string, logger *slog.Logger) (Backend, error) {
	switch platform {
	case "linux":
		// Wired up by main.go via internal/tailer.
		// We don't return a Backend here because the
		// file-tail backend is registered separately.
		return nil, fmt.Errorf("telemetry.NewForPlatform: use internal/tailer for linux")
	case "windows":
		return windows.New(hostID, logger), nil
	case "darwin":
		return NewDarwinUnavailable(logger), nil
	default:
		return nil, fmt.Errorf("telemetry.NewForPlatform: unsupported platform %q", platform)
	}
}

// Unavailable is the placeholder returned by the v1.2
// Slice 1 darwin/ backend. It logs once at startup and
// returns when ctx is canceled. The windows branch is now
// fully implemented (eventlog_windows.go) and no longer
// uses this sentinel.
type Unavailable struct {
	platform string
	logger   *slog.Logger
}

// NewDarwinUnavailable returns a macOS backend that
// reports the platform is not yet implemented. macOS is
// explicitly out of scope for v1.2.
func NewDarwinUnavailable(logger *slog.Logger) *Unavailable {
	return &Unavailable{platform: "darwin", logger: logger}
}

// Name implements Backend.
func (u *Unavailable) Name() string {
	return u.platform + "/scaffold"
}

// Run implements Backend. Logs once and blocks on ctx.
func (u *Unavailable) Run(ctx context.Context, handler func([]byte) error) error {
	u.logger.Warn("telemetry: platform backend not built in this release",
		"platform", u.platform,
		"see", "ADR-007 Slice 1")
	<-ctx.Done()
	return ctx.Err()
}
