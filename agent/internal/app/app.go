// Package app is the wiring layer between config, tailer, transport,
// and main.go. It is intentionally framework-free: no global state,
// no signal handling — main.go owns those, and passes a Context to Run.
//
// Splitting wiring out of main.go (which lives in package main and
// cannot be unit-tested) lets us test the end-to-end flow with an
// in-process WebSocket echo server and a tailer pointing at a temp file.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
	"github.com/Faris-stuck/zaqorincore/agent/internal/tailer"
	"github.com/Faris-stuck/zaqorincore/agent/internal/transport"
)

// Command is re-exported from transport so callers of app don't
// have to import the transport package just to reference the
// Command type. Phase 4: response handlers in main.go use this.
type Command = transport.Command

// Transport is the subset of *transport.Client that app needs. We
// define it as an interface so tests can substitute a fake without
// standing up a WebSocket server.
type Transport interface {
	Send(ctx context.Context, ev event.Event) error
	Run(ctx context.Context)
	Close()
}

// TailerSource is the subset of *tailer.Tailer that the app needs.
type TailerSource interface {
	Start(ctx context.Context) (<-chan tailer.Line, error)
}

// WindowsEventlogBackend is the interface for the
// optional Windows eventlog subscription. Only
// constructed when cfg.WindowsEventlog.Mode == "push".
// The non-Windows build returns (nil, nil) — the agent
// runs fine without it.
type WindowsEventlogBackend interface {
	Run(ctx context.Context, out chan<- event.Event)
	Close() error
}

// NewWindowsEventlogBackend is implemented in
// build-tag-specific files: windows_eventlog_windows.go
// (real) and windows_eventlog_other.go (no-op).
// The non-Windows build returns (nil, nil) — the
// default is a no-op factory. The Windows build
// returns a real push-mode backend.

// Dependencies bundles everything Run needs. Tests can override any
// field to inject fakes.
type Dependencies struct {
	Config         *config.Config
	Logger         *slog.Logger
	Client         Transport        // optional: if set, used as-is
	NewTailer      func(src config.LogSource, logger *slog.Logger) TailerSource
	CommandHandler func(ctx context.Context, cmd transport.Command) (status string, err error)
	// NewWindowsEventlogBackend is optional. If non-nil,
	// called when cfg.WindowsEventlog.Mode == "push".
	// Tests inject a fake; production wires via the
	// build-tag factory.
	NewWindowsEventlogBackend func(cfg *config.Config, log *slog.Logger) (WindowsEventlogBackend, error)
}

// Run starts every tailer, opens the transport, and forwards lines
// from any tailer to the transport as events. It blocks until ctx is
// cancelled, then drains and returns nil.
func Run(ctx context.Context, deps Dependencies) error {
	if deps.Config == nil {
		return errors.New("app: Config is nil")
	}
	if deps.Logger == nil {
		return errors.New("app: Logger is nil")
	}

	logger := deps.Logger.With(slog.String("agent_id", deps.Config.AgentID))

	// Build or accept the transport client.
	tr := deps.Client
	if tr == nil {
		client, err := transport.New(transport.Config{
			ServerURL:        deps.Config.ServerURL,
			AgentID:          deps.Config.AgentID,
			AuthToken:        deps.Config.AuthToken,
			Logger:           logger,
			HandshakeTimeout: 10 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("app: build transport: %w", err)
		}
		// Phase 4: wire the response handler. The handler
		// is created in main.go and passed via deps if
		// the operator has configured [response] in TOML.
		// For now we attach a default no-op that always
		// fails with "no host secret"; main.go replaces
		// this with the real one if available.
		client.SetCommandHandler(deps.CommandHandler)
		tr = client
	}

	// Transport supervisor runs in the background and reconnects on
	// failure; we only need to call Run once per process.
	go tr.Run(ctx)

	// Windows eventlog push-mode: optional, only if
	// configured. Runs in a goroutine that fans events
	// into the same dispatcher channel as the tailers.
	pushEventOut := make(chan event.Event, 1024)
	if deps.Config.WindowsEventlog.Mode == "push" {
		newFn := deps.NewWindowsEventlogBackend
		if newFn == nil {
			newFn = NewWindowsEventlogBackend
		}
		be, err := newFn(deps.Config, logger)
		if err != nil {
			logger.Warn("app: windows eventlog push-mode start failed (continuing with tailers only)",
				slog.String("error", err.Error()),
			)
		} else if be != nil {
			defer be.Close()
			go be.Run(ctx, pushEventOut)
		}
	}

	// Fan in: every tailer writes into a single channel that the
	// dispatcher drains. Channel buffer of 1024 is large enough for
	// a few minutes of auth.log on a busy host without dropping.
	lines := make(chan tailer.Line, 1024)
	for _, src := range deps.Config.LogSources {
		src := src
		var tl TailerSource
		if deps.NewTailer != nil {
			tl = deps.NewTailer(src, logger)
		} else {
			tl = tailer.New(src, logger)
		}
		ch, err := tl.Start(ctx)
		if err != nil {
			logger.Error("app: tailer start failed",
				slog.String("source", src.Name),
				slog.String("error", err.Error()),
			)
			continue
		}
		go func(in <-chan tailer.Line) {
			for l := range in {
				select {
				case lines <- l:
				case <-ctx.Done():
					return
				}
			}
		}(ch)
	}

	// Dispatcher: turn each line OR each Windows event
	// into an event and ship it.
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		for {
			select {
			case <-ctx.Done():
				return
			case l, ok := <-lines:
				if !ok {
					lines = nil // disable this case
					if pushEventOut == nil {
						return
					}
					continue
				}
				ev := event.New(deps.Config.AgentID, l.Source, string(l.Raw))
				enrichWithWebParser(&ev, logger)
				if err := tr.Send(ctx, ev); err != nil {
					logger.Debug("app: send failed",
						slog.String("event_id", ev.ID),
						slog.String("error", err.Error()),
					)
				}
			case ev, ok := <-pushEventOut:
				if !ok {
					pushEventOut = nil // disable this case
					if lines == nil {
						return
					}
					continue
				}
				if err := tr.Send(ctx, ev); err != nil {
					logger.Debug("app: send push event failed",
						slog.String("event_id", ev.ID),
						slog.String("error", err.Error()),
					)
				}
			}
		}
	}()

	// Block until the parent context is cancelled, then close the
	// transport (no more reconnects) and wait for the dispatcher.
	<-ctx.Done()
	logger.Info("app: shutdown signal received, draining")
	tr.Close()
	<-dispatchDone
	logger.Info("app: clean shutdown complete")
	return nil
}
