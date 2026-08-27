package transport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// startEchoServer brings up an httptest server that upgrades incoming
// WebSocket requests and returns a *Server. The server records every
// frame the client sends into rec.frames.
//
// If closeOnCount > 0, the server forcibly closes the connection after
// receiving that many frames (used for the reconnect test). The
// underlying httptest server stays up, so a subsequent reconnect can
// complete a fresh upgrade and keep recording.
type recordingServer struct {
	srv          *httptest.Server
	url          string
	frames       [][]byte
	mu           sync.Mutex
	closeOnCount int
	closeOnce    sync.Once
	dropPing     atomic.Bool
}

func newRecordingServer(t *testing.T, closeOnCount int) *recordingServer {
	t.Helper()
	rs := &recordingServer{closeOnCount: closeOnCount}
	up := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		// Per-connection frame counter — close-on-count applies to
		// this connection only, so the next reconnect is unaffected.
		var connCount int
		// Don't `defer c.Close()` here — if we close-on-count, we
		// want the *next* upgrade (post-reconnect) to be served too.
		// We close manually below.
		for {
			mt, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = mt
			connCount++
			rs.mu.Lock()
			rs.frames = append(rs.frames, append([]byte(nil), data...))
			rs.mu.Unlock()
			if rs.closeOnCount > 0 && connCount >= rs.closeOnCount {
				rs.closeOnce.Do(func() { _ = c.Close() })
				return
			}
		}
	}))
	rs.url = "ws" + strings.TrimPrefix(rs.srv.URL, "http")
	return rs
}

func (rs *recordingServer) stop() { rs.srv.Close() }

func (rs *recordingServer) snapshot() [][]byte {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([][]byte, len(rs.frames))
	for i, f := range rs.frames {
		out[i] = append([]byte(nil), f...)
	}
	return out
}

// waitForFrames polls until the server has at least n frames or the
// timeout fires. Returns the snapshot.
func (rs *recordingServer) waitForFrames(t *testing.T, n int, d time.Duration) [][]byte {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		got := rs.snapshot()
		if len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return rs.snapshot()
}

func TestTransport_HelloReceived(t *testing.T) {
	rs := newRecordingServer(t, 0)
	defer rs.stop()

	c, err := New(Config{
		ServerURL: rs.url,
		AgentID:   "agent-hello-1",
		Logger:    quietLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	frames := rs.waitForFrames(t, 1, 2*time.Second)
	if len(frames) < 1 {
		t.Fatalf("server got no frames")
	}
	var f helloFrame
	if err := json.Unmarshal(frames[0], &f); err != nil {
		t.Fatalf("unmarshal hello: %v (raw=%s)", err, frames[0])
	}
	if f.Type != "hello" {
		t.Errorf("frame type = %q, want hello", f.Type)
	}
	if f.AgentID != "agent-hello-1" {
		t.Errorf("agent_id = %q", f.AgentID)
	}
	if f.Version != ProtocolVersion {
		t.Errorf("version = %q, want %q", f.Version, ProtocolVersion)
	}
}

func TestTransport_SendMany(t *testing.T) {
	rs := newRecordingServer(t, 0)
	defer rs.stop()

	c, err := New(Config{
		ServerURL: rs.url,
		AgentID:   "agent-send",
		Logger:    quietLogger(),
		// Tight heartbeat so we don't sit around for 20s.
		HeartbeatInterval: 200 * time.Millisecond,
		PongWait:          200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// Wait for the HELLO so we know the conn is up.
	rs.waitForFrames(t, 1, 2*time.Second)

	const N = 100
	for i := 0; i < N; i++ {
		ev := event.New("agent-send", "auth", "line")
		ev.Metadata["i"] = "x"
		if err := c.Send(ctx, ev); err != nil {
			t.Fatalf("Send #%d: %v", i, err)
		}
	}

	frames := rs.waitForFrames(t, N+1, 5*time.Second)
	if len(frames) < N+1 {
		t.Fatalf("server got %d frames, want at least %d", len(frames), N+1)
	}
	// First frame is HELLO; subsequent are events.
	for i := 1; i <= N; i++ {
		var f eventFrame
		if err := json.Unmarshal(frames[i], &f); err != nil {
			t.Fatalf("frame %d not event: %v (%s)", i, err, frames[i])
		}
		if f.Type != "event" {
			t.Errorf("frame %d type = %q", i, f.Type)
		}
		if f.Event.Source != "auth" {
			t.Errorf("frame %d source = %q", i, f.Event.Source)
		}
	}
}

func TestTransport_ReconnectAfterServerCloses(t *testing.T) {
	// Server closes after the first event; client must reconnect,
	// resend HELLO, and successfully deliver a second event.
	rs := newRecordingServer(t, 2) // close after 2 frames
	defer rs.stop()

	c, err := New(Config{
		ServerURL:         rs.url,
		AgentID:           "agent-recon",
		Logger:            quietLogger(),
		BackoffInitial:    50 * time.Millisecond,
		BackoffMax:        100 * time.Millisecond,
		HeartbeatInterval: 200 * time.Millisecond,
		PongWait:          200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// Wait for the first HELLO so we know the connection is up.
	rs.waitForFrames(t, 1, 2*time.Second)

	// First connection: HELLO + 1 event triggers close.
	ev1 := event.New("agent-recon", "auth", "first")
	if err := c.Send(ctx, ev1); err != nil {
		t.Fatalf("Send #1: %v", err)
	}
	// Wait for the server to record exactly 2 frames (HELLO + first
	// event), so we know the close was triggered.
	frames := rs.waitForFrames(t, 2, 3*time.Second)
	if len(frames) < 2 {
		t.Fatalf("server got %d frames, want 2", len(frames))
	}

	// Now wait for the client to detect the close + reconnect.
	// Polling for a NEW hello is the most reliable signal.
	deadline := time.Now().Add(5 * time.Second)
	var postReconnect int
	for time.Now().Before(deadline) {
		frames = rs.snapshot()
		if len(frames) >= 3 {
			postReconnect = len(frames)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if postReconnect < 3 {
		t.Fatalf("client did not reconnect; frames=%d", postReconnect)
	}

	// Send a second event. It should land on the NEW connection.
	ev2 := event.New("agent-recon", "auth", "second")
	if err := c.Send(ctx, ev2); err != nil {
		t.Fatalf("Send #2: %v", err)
	}

	frames = rs.waitForFrames(t, 4, 5*time.Second)
	if len(frames) < 4 {
		t.Fatalf("server got %d frames, want at least 4 (HELLO+EVENT+HELLO+EVENT)", len(frames))
	}
	// Frames 2 and 3 should be the new HELLO + the second event.
	var f2 helloFrame
	if err := json.Unmarshal(frames[2], &f2); err != nil {
		t.Fatalf("frame[2] not hello: %v (%s)", err, frames[2])
	}
	if f2.Type != "hello" {
		t.Errorf("frame[2] type = %q, want hello (reconnect did not resend HELLO)", f2.Type)
	}
	var f3 eventFrame
	if err := json.Unmarshal(frames[3], &f3); err != nil {
		t.Fatalf("frame[3] not event: %v (%s)", err, frames[3])
	}
	if f3.Event.Raw != "second" {
		t.Errorf("frame[3] event raw = %q, want second (frame=%s)", f3.Event.Raw, frames[3])
	}
}

func TestTransport_CloseStops(t *testing.T) {
	rs := newRecordingServer(t, 0)
	defer rs.stop()

	c, err := New(Config{
		ServerURL:         rs.url,
		AgentID:           "agent-close",
		Logger:            quietLogger(),
		BackoffInitial:    10 * time.Millisecond,
		BackoffMax:        50 * time.Millisecond,
		HeartbeatInterval: 100 * time.Millisecond,
		PongWait:          100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	rs.waitForFrames(t, 1, 2*time.Second)

	c.Close()
	select {
	case <-done:
		// pass
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

func TestTransport_NewRejectsEmptyConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"empty url":    {ServerURL: "", AgentID: "x", Logger: quietLogger()},
		"empty agent":  {ServerURL: "ws://x", AgentID: "", Logger: quietLogger()},
		"nil logger":   {ServerURL: "ws://x", AgentID: "x", Logger: nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestTransport_SendAfterCloseErrors(t *testing.T) {
	rs := newRecordingServer(t, 0)
	defer rs.stop()

	c, err := New(Config{
		ServerURL:         rs.url,
		AgentID:           "agent-send-closed",
		Logger:            quietLogger(),
		HeartbeatInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	rs.waitForFrames(t, 1, 2*time.Second)

	c.Close()
	time.Sleep(100 * time.Millisecond)
	ev := event.New("agent-send-closed", "auth", "x")
	if err := c.Send(ctx, ev); err == nil {
		t.Fatal("expected error on Send after Close, got nil")
	}
}

func TestBackoff_GrowsAndCaps(t *testing.T) {
	b := backoff{initial: 100 * time.Millisecond, max: 400 * time.Millisecond}
	got := []time.Duration{b.next(), b.next(), b.next(), b.next(), b.next()}
	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d: got %v, want %v", i, got[i], want[i])
		}
	}
	b.reset()
	if d := b.next(); d != 100*time.Millisecond {
		t.Errorf("after reset: got %v, want initial", d)
	}
}
