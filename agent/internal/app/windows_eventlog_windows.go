//go:build windows

package app

import (
	"context"
	"log/slog"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
	"github.com/Faris-stuck/zaqorincore/agent/internal/telemetry/windows"
)

// NewWindowsEventlogBackend returns a real push-mode
// backend on Windows. The returned backend, when Run()
// is called, starts an EvtSubscribe subscription and
// forwards each event to the supplied channel (in the
// event.Event shape the dispatcher already knows how
// to handle).
//
// configDep is the agent config; the backend only
// needs cfg.WindowsEventlog.Mode to know to start in
// push mode (the caller has already gated on
// cfg.WindowsEventlog.Mode == "push").
func NewWindowsEventlogBackend(
	cfg *config.Config,
	log *slog.Logger,
) (WindowsEventlogBackend, error) {
	be := windows.NewPush(cfg.AgentID, log)
	if err := be.SubscribePush(context.Background(), log); err != nil {
		return nil, err
	}
	return &winPushBackend{inner: be, cfg: cfg, log: log}, nil
}

// winPushBackend wraps *windows.PushBackend to satisfy
// the WindowsEventlogBackend interface. Run() starts the
// drain loop; events flow into `out`.
type winPushBackend struct {
	inner *windows.PushBackend
	cfg   *config.Config
	log   *slog.Logger
}

func (w *winPushBackend) Run(ctx context.Context, out chan<- event.Event) {
	w.log.Info("app: starting windows eventlog push-mode subscription",
		slog.String("agent_id", w.cfg.AgentID),
	)
	w.inner.Run(ctx, func(xmlBytes []byte) error {
		select {
		case out <- event.New(w.cfg.AgentID, "windows:push", string(xmlBytes)):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

func (w *winPushBackend) Close() error {
	w.inner.Close()
	return nil
}
