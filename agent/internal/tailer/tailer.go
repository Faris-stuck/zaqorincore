// Package tailer wraps a log file with rotation-safe "tail -F" semantics
// and exposes each new line on a channel of byte slices.
//
// Design constraints (from docs/PHASE1_PLAN.md):
//
//   - On open, seek to end of file — Phase 1 is forward-only. We never
//     replay history.
//   - On rename/rotation, keep following the path: the next time the
//     file is created (by logrotate or by the next service start), we
//     open it and continue from the new end. This is what
//     `tail -F path` does, and what nxadm/tail gives us via
//     `ReOpen`.
//
//   - The output channel is created in Start() and CLOSED when the
//     tailer shuts down (context cancel, unrecoverable error, or
//     normal EOF). Consumers use `for line := range ch { ... }`.
//
//   - Errors are logged, not returned after Start(). Start() returns
//     an error only for configuration problems the caller can fix
//     (e.g. an unreadable initial path on a developer machine). Once
//     the goroutine is running, the channel is the only signal.
package tailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nxadm/tail"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
)

// Line is a single read line plus the source it came from. We attach
// the source name here (rather than at the consumer) so the event
// builder does not have to know which tailer a channel belongs to
// when fanning in multiple sources.
type Line struct {
	Source string
	Raw    []byte
}

// Tailer reads one log file. Use a separate Tailer per [[log_source]].
type Tailer struct {
	src    config.LogSource
	logger *slog.Logger

	// pollInterval is how often nxadm/tail checks for file changes
	// we do not have a separate poll thread; this is delegated to
	// the underlying library. The field is here for test override.
	pollInterval time.Duration
}

// New constructs a Tailer. The logger must not be nil; the tailer logs
// rotation events and shutdown reasons through it.
func New(src config.LogSource, logger *slog.Logger) *Tailer {
	return &Tailer{
		src:          src,
		logger:       logger.With(slog.String("source", src.Name), slog.String("path", src.Path)),
		pollInterval: 250 * time.Millisecond,
	}
}

// Start opens the file and begins streaming new lines. The returned
// channel is closed when ctx is cancelled or when the underlying
// tailer exits (which itself only happens on a fatal error — see
// gracefulStop). Start does not block: the file open happens in the
// background goroutine, and the first read may race with the
// caller's first receive.
//
// If the file is missing at Start() time, we log a warning and KEEP
// retrying. logrotate and journald are common cases where the path
// does not exist at agent start.
func (t *Tailer) Start(ctx context.Context) (<-chan Line, error) {
	if t.src.Path == "" {
		return nil, errors.New("tailer: empty path")
	}
	out := make(chan Line, 64)

	cfg := tail.Config{
		Follow:    true,
		ReOpen:    true, // reopen on rename/rotation
		MustExist: false,
		Poll:      true, // works on NFS / unusual FS where inotify is unreliable
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2}, // 2 = SEEK_END
		Logger:    tail.DiscardingLogger,                // we use our own slog
	}

	tailer, err := tail.TailFile(t.src.Path, cfg)
	if err != nil {
		// Path unreadable at start. We still want to keep retrying
		// (file may appear later), so start a retry loop instead of
		// failing closed.
		t.logger.Warn("tail: initial open failed, will retry", slog.String("error", err.Error()))
		go t.retryUntilReady(ctx, out)
		return out, nil
	}

	go t.run(ctx, tailer, out)
	return out, nil
}

// retryUntilReady keeps trying to open the file until it appears, then
// transitions to the normal run loop. Used when Start() found the file
// missing.
func (t *Tailer) retryUntilReady(ctx context.Context, out chan<- Line) {
	defer close(out)
	backoff := 250 * time.Millisecond
	const maxBackoff = 5 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		cfg := tail.Config{
			Follow:    true,
			ReOpen:    true,
			MustExist: false,
			Poll:      true,
			Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
			Logger:    tail.DiscardingLogger,
		}
		tailer, err := tail.TailFile(t.src.Path, cfg)
		if err == nil {
			t.logger.Info("tail: file appeared, resuming")
			t.runFromOpened(ctx, tailer, out)
			return
		}
		t.logger.Debug("tail: still waiting for file", slog.String("error", err.Error()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// run is the normal lifecycle: forward lines until the tailer exits
// or ctx is cancelled. The tailer is closed here.
func (t *Tailer) run(ctx context.Context, tf *tail.Tail, out chan<- Line) {
	defer close(out)

	// If the parent context is cancelled, ask the library to stop
	// blocking reads so we can drain and exit. We do this in a
	// separate goroutine because tf.Stop() is what makes
	// `for line := range tf.Lines` return.
	go func() {
		<-ctx.Done()
		_ = tf.Stop()
	}()

	for line := range tf.Lines {
		if line.Err != nil {
			// Rotation and truncation show up here as transient
			// errors. Log at debug so a noisy log file does not
			// flood the operator's stderr.
			t.logger.Debug("tail: read error", slog.String("error", line.Err.Error()))
			continue
		}
		// Copy the bytes; the tailer recycles the underlying buffer.
		raw := make([]byte, len(line.Text))
		copy(raw, line.Text)
		select {
		case out <- Line{Source: t.src.Name, Raw: raw}:
		case <-ctx.Done():
			return
		}
	}
}

// runFromOpened is run() minus the initial open: it assumes the tailer
// is already alive and only manages the forward + shutdown.
func (t *Tailer) runFromOpened(ctx context.Context, tf *tail.Tail, out chan<- Line) {
	defer close(out)

	go func() {
		<-ctx.Done()
		_ = tf.Stop()
	}()

	for line := range tf.Lines {
		if line.Err != nil {
			t.logger.Debug("tail: read error", slog.String("error", line.Err.Error()))
			continue
		}
		raw := make([]byte, len(line.Text))
		copy(raw, line.Text)
		select {
		case out <- Line{Source: t.src.Name, Raw: raw}:
		case <-ctx.Done():
			return
		}
	}
}

// String renders a debug-friendly view of the tailer.
func (t *Tailer) String() string {
	return fmt.Sprintf("tailer{source=%s path=%s}", t.src.Name, t.src.Path)
}
