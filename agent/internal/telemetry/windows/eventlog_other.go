//go:build !windows

// Stub for the Windows Event Log backend. On non-Windows GOOS
// (linux, darwin) the dispatcher returns a sentinel that returns
// an error at Run time. The real implementation lives in
// eventlog_windows.go (//go:build windows).
//
// This file's job is to keep `telemetry.go`'s call site compiling
// for the linux and darwin build targets so the cross-compile
// matrix passes.
package windows

import (
	"context"
	"fmt"
	"log/slog"
)

// newWindowsBackend is the non-Windows shim. The Windows
// implementation is in eventlog_windows.go behind
// `//go:build windows`.
func newWindowsBackend(hostID string, logger *slog.Logger) interface {
	Name() string
	Run(ctx context.Context, handler func([]byte) error) error
} {
	return &stubBackend{hostID: hostID, logger: logger}
}

// New returns the non-Windows stub. The Windows implementation
// (eventlog_windows.go) shadows this on windows GOOS. Both
// files expose the same exported `New` so the dispatcher in
// telemetry.go compiles for every target.
func New(hostID string, logger *slog.Logger) *stubBackend {
	return &stubBackend{hostID: hostID, logger: logger}
}

type stubBackend struct {
	hostID string
	logger *slog.Logger
}

func (s *stubBackend) Name() string { return "windows/eventlog-stub" }

func (s *stubBackend) Run(ctx context.Context, _ func([]byte) error) error {
	s.logger.Warn("eventlog: stub backend active (non-Windows GOOS)",
		slog.String("platform", "non-windows"))
	<-ctx.Done()
	return fmt.Errorf("eventlog: not available on non-Windows GOOS: %w", ctx.Err())
}
