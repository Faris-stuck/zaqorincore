package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newTestLogger returns a slog.Logger that discards output,
// keeping `go test -v` output clean. Tests don't assert on
// log lines; the warning emit in Unavailable.Run is exercised
// via a separate test that captures the buffer.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newCapturingLogger returns a slog.Logger writing into buf
// so tests can assert that the darwin scaffold logs once.
func newCapturingLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// TestNewForPlatform exercises every branch of the
// platform dispatcher. The linux and unsupported branches
// must return an error; the darwin branch must return a
// non-nil sentinel; the windows branch is a stub on non-
// windows GOOS but must also return a non-nil Backend.
func TestNewForPlatform(t *testing.T) {
	logger := newTestLogger()
	cases := []struct {
		name    string
		plat    string
		wantErr bool
		nilOut  bool // true → expect nil Backend + error
	}{
		{"linux uses tailer", "linux", true, true},
		{"windows returns backend", "windows", false, false},
		{"darwin returns scaffold", "darwin", false, false},
		{"unknown unsupported", "freebsd", true, true},
		{"empty unsupported", "", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be, err := NewForPlatform(tc.plat, "host-1", logger)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for platform %q, got nil", tc.plat)
				}
				if be != nil {
					t.Fatalf("expected nil Backend on error, got %T", be)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for platform %q: %v", tc.plat, err)
			}
			if be == nil {
				t.Fatalf("expected non-nil Backend for platform %q", tc.plat)
			}
		})
	}
}

// TestUnavailable_Name verifies the scaffold reports its
// platform tag so operators can tell from logs which
// telemetry source is in use.
func TestUnavailable_Name(t *testing.T) {
	u := NewDarwinUnavailable(newTestLogger())
	if got, want := u.Name(), "darwin/scaffold"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

// TestUnavailable_BlocksOnCtxCancel verifies the scaffold
// (1) emits its single warning at start and (2) blocks
// until ctx is canceled, then returns ctx.Err().
func TestUnavailable_BlocksOnCtxCancel(t *testing.T) {
	buf := &bytes.Buffer{}
	u := NewDarwinUnavailable(newCapturingLogger(buf))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- u.Run(ctx, func([]byte) error { return nil }) }()

	// Give Run a moment to emit its warning.
	time.Sleep(20 * time.Millisecond)

	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Run err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Run returned too late: %v", elapsed)
	}
	if !strings.Contains(buf.String(), "platform backend not built") {
		t.Fatalf("expected startup warning, got log:\n%s", buf.String())
	}
}

// TestUnavailable_PropagatesHandlerError is a defensive
// check: the scaffold never calls handler, so a handler
// that always errors must not see Run fail with anything
// other than ctx.Err() once we cancel.
func TestUnavailable_DoesNotInvokeHandler(t *testing.T) {
	called := 0
	u := NewDarwinUnavailable(newTestLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- u.Run(ctx, func([]byte) error {
			called++
			return errors.New("handler should not be called")
		})
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if called != 0 {
		t.Fatalf("handler invoked %d times; scaffold should never call it", called)
	}
}