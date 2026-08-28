package canary

import (
	"io"
	"log/slog"
	"os"
)

// testLogger is a tiny slog helper used by canary_test.go so
// we don't depend on whatever main.go wires.
func testLogger(t testingT) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// testingT is the subset of testing.T we use. Defining it
// here lets us avoid importing "testing" in helpers used by
// other test files.
type testingT interface {
	Helper()
	FailNow()
	Skip(args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

var _ = os.Stdout
