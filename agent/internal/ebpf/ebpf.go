// Package ebpf holds the eBPF kernel-telemetry backend for the
// ZaqorinCore agent (v1.1.0, see ADR-006).
//
// This file is the public-facing Backend interface used by
// app.Run. The implementation is either the real BPF loader
// (loader.go) when the kernel is new enough, the compiled
// objects are present, and CAP_BPF is available — or the
// Slice 1 NotImplemented stub that logs once and returns.
//
// Both implementations satisfy the Backend interface below.
package ebpf

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// Backend is the abstraction that main.go calls. It produces
// events via the callback and stops cleanly on context cancel.
type Backend interface {
	// Run blocks until ctx is canceled. Each event the probes
	// capture is delivered to the handler in the form of a
	// pre-built wire event. Returning from Run must be
	// safe and idempotent.
	Run(ctx context.Context, handler func(event []byte) error) error
	// Name returns the backend identifier used in the agent's
	// startup log and the source-prefix on the wire
	// (e.g. "ebpf/execve").
	Name() string
}

// Availability describes whether the current build can load
// eBPF programs. The checks are:
//
//   - kernel >= 5.4 (BPF_PROG_TYPE_TRACING was added in 5.4
//     and is what the probes use)
//   - the bpf() syscall is available (parses /proc/sys/kernel/unprivileged_bpf
//     and CAP_BPF on the agent's creds)
//   - the compiled .o files are present at the expected path
//
// When Availability returns false the agent uses the
// file-tail backend unchanged. The reason is logged so
// operators can fix the most common case (missing compiled
// objects) with a single `make ebpf` invocation.
func Availability() (available bool, kernelMajor, kernelMinor int, err error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, reason := NewReal(logger, LoadConfig{})
	if reason == "" {
		return true, 0, 0, nil
	}
	return false, 0, 0, fmt.Errorf("ebpf: %s", reason)
}

// NewBackend returns the most capable Backend the current
// process can construct. It is the entry point used by
// main.go: try the real loader first, fall back to the
// NotImplemented stub if anything is missing.
func NewBackend(logger *slog.Logger, cfg LoadConfig) Backend {
	if real, reason := NewReal(logger, cfg); reason == "" {
		logger.Info("ebpf: BPF backend active",
			slog.String("host_id", cfg.AgentID))
		return real
	} else {
		logger.Warn("ebpf: BPF backend unavailable, using file-tail",
			slog.String("reason", reason))
		return NewNotImplemented(logger)
	}
}

// NotImplemented is the Backend returned to the agent for
// hosts where the BPF backend is unavailable. It logs a
// one-time warning and returns immediately. The agent
// continues with the existing file-tail backend.
type NotImplemented struct {
	logger *slog.Logger
}

// NewNotImplemented is the constructor used by NewBackend
// when the real loader declines to initialise.
func NewNotImplemented(logger *slog.Logger) *NotImplemented {
	return &NotImplemented{logger: logger}
}

// Name implements Backend.
func (n *NotImplemented) Name() string {
	return "ebpf/scaffold"
}

// Run implements Backend. It logs the scaffold status and blocks
// until ctx is canceled, doing no work in the meantime.
func (n *NotImplemented) Run(ctx context.Context, handler func(event []byte) error) error {
	n.logger.Warn("ebpf: kernel telemetry backend not active; " +
		"using file-tail backend only. See ADR-006 / docs/PHASE11.md " +
		"for the v1.1.0 deployment guide.")
	<-ctx.Done()
	return ctx.Err()
}
