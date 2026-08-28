// Package ebpf holds the eBPF kernel-telemetry backend for the
// ZaqorinCore agent (v1.1 — see ADR-006).
//
// This file is the scaffolding shipped in Slice 1 (v1.0.0 → v1.1.0).
// It compiles, runs, and reports "BPF backend not built" so the
// rest of the agent continues to work unchanged. Slices 2-5
// (v1.1.0+) replace this body with real probe loaders.
package ebpf

import (
	"context"
	"fmt"
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
//   - cilium/ebpf is linked into the binary
//
// In Slice 1 we report "not available" unconditionally because
// the probe objects are not built yet. Slices 2+ swap this for
// real syscalls.
func Availability() (available bool, kernelMajor, kernelMinor int, err error) {
	// Scaffold: probes are not built yet. Always unavailable.
	// Real implementation (Slice 2) uses unix.Kernel() to read
	// /proc/version and unix.PrctlRetInt to probe CAP_BPF.
	return false, 0, 0, fmt.Errorf("ebpf: probe binaries not built in this release; " +
		"file-tail backend in use (see ADR-006 Slice 1)")
}

// NotImplemented is the Backend returned to the agent for v1.0.0.
// It logs a one-time warning and returns immediately. The agent
// continues with the existing file-tail backend.
type NotImplemented struct {
	logger *slog.Logger
}

// NewNotImplemented is the constructor used by app.go.
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
	n.logger.Warn("ebpf: kernel telemetry backend not built in this release; " +
		"using file-tail backend only. See ADR-006 for the v1.1 plan.")
	<-ctx.Done()
	return ctx.Err()
}
