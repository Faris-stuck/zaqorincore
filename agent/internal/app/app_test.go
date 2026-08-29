package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
	"github.com/Faris-stuck/zaqorincore/agent/internal/tailer"
)

// fakeTransport is a Transport that records every event passed to Send
// and lets the test drive its lifecycle via Close().
type fakeTransport struct {
	mu     sync.Mutex
	events []event.Event
	closed chan struct{}
	once   sync.Once
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{closed: make(chan struct{})}
}

func (f *fakeTransport) Run(ctx context.Context) {
	<-ctx.Done()
	f.Close()
}

func (f *fakeTransport) Send(_ context.Context, ev event.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeTransport) Close() {
	f.once.Do(func() { close(f.closed) })
}

func (f *fakeTransport) snapshot() []event.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]event.Event, len(f.events))
	copy(out, f.events)
	return out
}

// fakeTailer is a TailerSource that emits a fixed sequence of lines
// from a buffered channel.
type fakeTailer struct {
	lines chan tailer.Line
}

func newFakeTailer(lines ...string) *fakeTailer {
	ch := make(chan tailer.Line, len(lines))
	for _, l := range lines {
		ch <- tailer.Line{Source: "test", Raw: []byte(l)}
	}
	close(ch)
	return &fakeTailer{lines: ch}
}

func (f *fakeTailer) Start(_ context.Context) (<-chan tailer.Line, error) {
	return f.lines, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestRun_RejectsNilDeps(t *testing.T) {
	if err := Run(context.Background(), Dependencies{Logger: quietLogger()}); err == nil {
		t.Error("expected error for nil Config, got nil")
	}
	if err := Run(context.Background(), Dependencies{Config: &config.Config{}}); err == nil {
		t.Error("expected error for nil Logger, got nil")
	}
}

func TestRun_ForwardsTailerLinesAsEvents(t *testing.T) {
	// Tailer emits 3 lines; transport records 3 events with the
	// expected content. Then we cancel the context and assert a
	// clean shutdown.
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.log"), []byte(""), 0o644)

	cfg := &config.Config{
		ServerURL:  "ws://test.invalid",
		AgentID:    "11111111-2222-3333-4444-555555555555",
		LogLevel:   "info",
		StateDir:   dir,
		DryRun:     true,
		LogSources: []config.LogSource{{Name: "test", Path: filepath.Join(dir, "app.log")}},
	}
	tr := newFakeTransport()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Dependencies{
		Config: cfg,
		Logger: quietLogger(),
		Client: tr,
		NewTailer: func(_ config.LogSource, _ *slog.Logger) TailerSource {
			return newFakeTailer("alpha", "beta", "gamma")
		},
	}) }()

	// Give the dispatcher a moment to drain.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(tr.snapshot()) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := tr.snapshot()
	if len(got) != 3 {
		t.Fatalf("transport got %d events, want 3", len(got))
	}
	for i, want := range []string{"alpha", "beta", "gamma"} {
		if string(got[i].Raw) != want {
			t.Errorf("event[%d] raw = %q, want %q", i, string(got[i].Raw), want)
		}
		if got[i].Source != "test" {
			t.Errorf("event[%d] source = %q, want test", i, got[i].Source)
		}
		if got[i].HostID != cfg.AgentID {
			t.Errorf("event[%d] host_id = %q, want %q", i, got[i].HostID, cfg.AgentID)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}
}

// fakeWinBackend is a WindowsEventlogBackend that
// emits a fixed sequence of events into out.
type fakeWinBackend struct {
	mu     sync.Mutex
	closed bool
}

func (f *fakeWinBackend) Run(ctx context.Context, out chan<- event.Event) {
	for _, raw := range []string{"<Event>win1</Event>", "<Event>win2</Event>"} {
		select {
		case out <- event.New("agent-ctx", "windows:push", raw):
		case <-ctx.Done():
			return
		}
	}
}

func (f *fakeWinBackend) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestRun_ForwardsWindowsEventlogEvents(t *testing.T) {
	cfg := &config.Config{
		ServerURL: "ws://test.invalid",
		AgentID:   "agent-ctx",
		LogLevel:  "info",
		StateDir:  t.TempDir(),
		DryRun:    true,
		LogSources: []config.LogSource{},
		WindowsEventlog: config.WindowsEventlog{
			Mode: "push",
		},
	}
	tr := newFakeTransport()
	winBE := &fakeWinBackend{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Dependencies{
			Config:    cfg,
			Logger:    quietLogger(),
			Client:    tr,
			NewWindowsEventlogBackend: func(_ *config.Config, _ *slog.Logger) (WindowsEventlogBackend, error) {
				return winBE, nil
			},
		})
	}()

	// Wait for both win events to arrive via the dispatcher.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(tr.snapshot()) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := tr.snapshot()
	if len(got) != 2 {
		t.Fatalf("transport got %d events, want 2", len(got))
	}
	for i, want := range []string{"<Event>win1</Event>", "<Event>win2</Event>"} {
		if string(got[i].Raw) != want {
			t.Errorf("event[%d] raw = %q, want %q", i, string(got[i].Raw), want)
		}
		if got[i].Source != "windows:push" {
			t.Errorf("event[%d] source = %q, want windows:push", i, got[i].Source)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	winBE.mu.Lock()
	if !winBE.closed {
		t.Error("fakeWinBackend.Close was not called on shutdown")
	}
	winBE.mu.Unlock()
}

func TestRun_PropagatesContextCancel(t *testing.T) {
	cfg := &config.Config{
		ServerURL:  "ws://test.invalid",
		AgentID:    "agent-ctx",
		LogLevel:   "info",
		StateDir:   t.TempDir(),
		DryRun:     true,
		LogSources: []config.LogSource{},
	}
	tr := newFakeTransport()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Dependencies{Config: cfg, Logger: quietLogger(), Client: tr}) }()

	// No log sources; just exercise the shutdown path.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
