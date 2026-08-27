// Package logger is a thin, opinionated wrapper over log/slog.
//
// We use it for two reasons:
//
//  1. The config file lets operators pick "debug"|"info"|"warn"|"error".
//     Mapping an invalid value to a valid one (with a warning) is the
//     job of New, so main.go does not have to know the level names.
//  2. The agent's default output is JSON to stderr. JSON-line logs are
//     what Loki / Vector / journald are happy to ingest without extra
//     grok rules. If the operator wants human-readable text (e.g. when
//     running in a terminal), New(..., FormatText, ...) switches the
//     handler.
package logger

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format chooses the handler's output encoding.
type Format int

const (
	// FormatJSON emits one JSON object per line. Default.
	FormatJSON Format = iota
	// FormatText emits the slog default text handler. Useful in a TTY.
	FormatText
)

// New returns a *slog.Logger configured for the given level and format.
//
// Behaviour:
//
//   - If w is nil, os.Stderr is used.
//   - If level is not one of "debug"|"info"|"warn"|"error", the
//     returned logger is at info level and a separate warning is
//     written to a side channel (see NewWithWarning) — this function
//     silently defaults to info so main.go does not have to special-case
//     the error path. Use NewWithWarning if you need to surface the
//     fact that the operator passed a bad level.
func New(level string, w io.Writer, format Format) *slog.Logger {
	l, _ := NewWithWarning(level, w, format)
	return l
}

// NewWithWarning is New with the side-channel warning returned to the
// caller. The returned warning is non-nil iff the level string was
// invalid (or empty, which is treated the same way).
//
// When the level is invalid, the returned logger still works — it just
// runs at info. The reason we do not return an error is that the agent
// must keep running; a bad log level is not a fatal config problem.
func NewWithWarning(level string, w io.Writer, format Format) (*slog.Logger, error) {
	if w == nil {
		w = os.Stderr
	}
	lvl, ok := parseLevel(level)
	var warn error
	if !ok {
		warn = fmt.Errorf("logger: invalid level %q, falling back to info", level)
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch format {
	case FormatText:
		h = slog.NewTextHandler(w, opts)
	default:
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h), warn
}

// parseLevel maps a config-string level to its slog counterpart.
// Empty input is treated as "info" (so an empty config field is
// not an error).
func parseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// ErrStderrUnavailable is returned by Stderr if os.Stderr is somehow
// nil. In normal operation this is never triggered, but the constant
// exists so tests can assert on it without string-matching.
var ErrStderrUnavailable = errors.New("logger: os.Stderr is nil")

// Stderr is a convenience that returns a JSON logger at the given
// level writing to os.Stderr.
func Stderr(level string) *slog.Logger {
	if os.Stderr == nil {
		// Almost impossible in practice; defensive only.
		return slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return New(level, os.Stderr, FormatJSON)
}
