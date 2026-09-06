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

type Command = transport.Command

type Transport interface {
	Send(ctx context.Context, ev event.Event) error
	Run(ctx context.Context)
	Close()
}

type TailerSource interface { Start(ctx context.Context) (<-chan tailer.Line, error) }

type WindowsEventlogBackend interface {
	Run(ctx context.Context, out chan<- event.Event)
	Close() error
}

type Dependencies struct {
	Config         *config.Config
	Logger         *slog.Logger
	Client         Transport
	NewTailer      func(src config.LogSource, logger *slog.Logger) TailerSource
	CommandHandler func(ctx context.Context, cmd transport.Command) (status string, err error)
	NewWindowsEventlogBackend func(cfg *config.Config, log *slog.Logger) (WindowsEventlogBackend, error)
}

func Run(ctx context.Context, deps Dependencies) error {
	if deps.Config == nil { return errors.New("app: Config is nil") }
	if deps.Logger == nil { return errors.New("app: Logger is nil") }
	logger := deps.Logger.With(slog.String("agent_id", deps.Config.AgentID))

	tr := deps.Client
	if tr == nil {
		client, err := transport.New(transport.Config{
			ServerURL: deps.Config.ServerURL,
			AgentID: deps.Config.AgentID,
			AuthToken: deps.Config.AuthToken,
			SharedSecret: deps.Config.SharedSecret,
			Logger: logger,
			HandshakeTimeout: 10 * time.Second,
		})
		if err != nil { return fmt.Errorf("app: build transport: %w", err) }
		client.SetCommandHandler(deps.CommandHandler)
		tr = client
	}
	go tr.Run(ctx)

	pushEventOut := make(chan event.Event, 1024)
	if deps.Config.WindowsEventlog.Mode == "push" {
		newFn := deps.NewWindowsEventlogBackend
		if newFn == nil { newFn = NewWindowsEventlogBackend }
		be, err := newFn(deps.Config, logger)
		if err != nil {
			logger.Warn("app: windows eventlog push-mode start failed", slog.String("error", err.Error()))
		} else if be != nil {
			defer be.Close()
			go be.Run(ctx, pushEventOut)
		}
	}

	lines := make(chan tailer.Line, 1024)
	for _, src := range deps.Config.LogSources {
		src := src
		var tl TailerSource
		if deps.NewTailer != nil { tl = deps.NewTailer(src, logger) } else { tl = tailer.New(src, logger) }
		ch, err := tl.Start(ctx)
		if err != nil {
			logger.Error("app: tailer start failed", slog.String("source", src.Name), slog.String("error", err.Error()))
			continue
		}
		go func(in <-chan tailer.Line) {
			for l := range in {
				select { case lines <- l: case <-ctx.Done(): return }
			}
		}(ch)
	}

	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		for {
			select {
			case <-ctx.Done(): return
			case l, ok := <-lines:
				if !ok { lines = nil; if pushEventOut == nil { return }; continue }
				ev := event.New(deps.Config.AgentID, l.Source, string(l.Raw))
				enrichWithWebParser(&ev, logger)
				if err := tr.Send(ctx, ev); err != nil { logger.Debug("app: send failed", slog.String("event_id", ev.ID), slog.String("error", err.Error())) }
			case ev, ok := <-pushEventOut:
				if !ok { pushEventOut = nil; if lines == nil { return }; continue }
				if err := tr.Send(ctx, ev); err != nil { logger.Debug("app: send push event failed", slog.String("event_id", ev.ID), slog.String("error", err.Error())) }
			}
		}
	}()

	<-ctx.Done()
	logger.Info("app: shutdown signal received, draining")
	tr.Close()
	<-dispatchDone
	logger.Info("app: clean shutdown complete")
	return nil
}
