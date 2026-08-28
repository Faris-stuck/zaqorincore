// Test helpers for kinds_test.go.
package kinds

import (
	"context"
	"io"
	"log/slog"
)

// testContext returns a fresh background context for tests.
func testContext() context.Context {
	return context.Background()
}

// testLogger returns a logger that discards all output, so test runs
// stay clean. We return a real *slog.Logger to keep callers honest.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
