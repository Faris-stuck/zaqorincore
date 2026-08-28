// Package transport owns the WebSocket client that connects the agent
// to the central server.
//
// Phase 1 scope (no auto-response, no commands received): the client
// opens a connection, sends a HELLO frame, and streams events. Commands
// from the server (the "command" frame type) are parsed and logged but
// NOT applied — that lands in Phase 4 with HMAC signing.
//
// Wire protocol summary (kept in sync with the server):
//
//	client -> server: {"type":"hello",   "agent_id": "...", "version": "1.0"}
//	client -> server: {"type":"event",   "event": { ... event.Event ... }}
//	client -> server: {"type":"bye",     "reason": "shutdown"}
//	server -> client: {"type":"command", "id":"...", "kind":"block_ip", "target":"1.2.3.4", "ttl_sec":3600}
//	                     (Phase 4 will verify HMAC before applying)
//
// All frames are JSON objects. The server is responsible for the rest.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
)

// Protocol version negotiated in the HELLO frame. Bumped when the
// on-wire shape changes incompatibly.
const ProtocolVersion = "1.0"

// FrameType is the discriminator for the polymorphic frame envelope.
type FrameType string

const (
	FrameHello   FrameType = "hello"
	FrameEvent   FrameType = "event"
	FrameBye     FrameType = "bye"
	FrameCommand FrameType = "command"
)

// Command is the public-facing shape of a server-issued command. The
// internal `commandFrame` is wire-only; this is what the
// CommandHandler receives.
type Command struct {
	ID       string
	Kind     string
	Target   string
	TTLSec   int
	IssuedAt string
	HMAC     string
}

// helloFrame is the first message the client sends. The server uses
// agent_id to look up the agent's shared secret and ACL.
type helloFrame struct {
	Type    string `json:"type"`
	AgentID string `json:"agent_id"`
	Version string `json:"version"`
}

// eventFrame wraps a single event. We keep the inner Event struct
// field-named "event" so the server can decode it as
// `{"type": "event", "event": {...}}`.
type eventFrame struct {
	Type  string      `json:"type"`
	Event event.Event `json:"event"`
}

// byeFrame is sent during graceful shutdown so the server can free
// the agent's session promptly.
type byeFrame struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// commandFrame is what the server may send us. Phase 4 verifies
// the HMAC against the host's shared secret and dispatches the
// action via a CommandHandler.
type commandFrame struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	TTLSec   int    `json:"ttl_sec"`
	IssuedAt string `json:"issued_at"`
	HMAC     string `json:"hmac"`
}

// commandAckFrame is what the agent sends back to report the
// outcome. The server updates the Action row to applied/failed.
type commandAckFrame struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// envelope is used only for inbound frames to peek at the "type"
// field before dispatching to the right concrete struct.
type envelope struct {
	Type string `json:"type"`
}

// Config holds the fields the Client needs at construction time.
// We keep it small so tests can pass ad-hoc values.
type Config struct {
	// ServerURL is the WSS endpoint. Must start with ws:// or wss://.
	ServerURL string
	// AgentID is the resolved, stable UUID for this host.
	AgentID string
	// AuthToken is sent as `Authorization: Bearer *** on the
	// upgrade request. Optional in Phase 1; the server may require
	// it in Phase 6.
	AuthToken string
	// Logger receives lifecycle and reconnect events. Must be non-nil.
	Logger *slog.Logger
	// Backoff policy. Zero values get defaults: 1s, 2s, 4s, ..., cap 30s.
	BackoffInitial time.Duration
	BackoffMax     time.Duration
	// Heartbeat: ping interval and pong-wait. Defaults: 20s / 10s.
	HeartbeatInterval time.Duration
	PongWait          time.Duration
	// HandshakeTimeout caps the initial dial. Default 10s.
	HandshakeTimeout time.Duration
	// CommandHandler, if non-nil, is invoked for every verified
	// command frame. The handler is responsible for verifying
	// the HMAC and applying the action; this layer only does
	// JSON parsing and ACK plumbing.
	CommandHandler func(ctx context.Context, cmd Command) (status string, err error)
}

// SetCommandHandler replaces the command callback. Safe to call
// before the client starts running; unsafe to call after Connect
// without coordinating with the supervisor.
func (c *Client) SetCommandHandler(h func(ctx context.Context, cmd Command) (string, error)) {
	c.cfg.CommandHandler = h
}

// Client manages one logical WebSocket connection. Internally it
// holds a pointer to the current *Conn and a supervisor goroutine
// that reconnects on failure. The Send method is safe for concurrent
// callers; the read pump is single-threaded.
type Client struct {
	cfg     Config
	backoff backoff
	dialer  *websocket.Dialer

	mu      sync.Mutex // protects the connection pointer + reader
	conn    *websocket.Conn
	closed  atomic.Bool // true after Close() — no further reconnects
	writeMu sync.Mutex // serialises frame writes
}

// New constructs a Client. It does NOT open the connection — call Run.
func New(cfg Config) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("transport: ServerURL is empty")
	}
	if cfg.AgentID == "" {
		return nil, errors.New("transport: AgentID is empty")
	}
	if cfg.Logger == nil {
		return nil, errors.New("transport: Logger is nil")
	}
	if cfg.BackoffInitial <= 0 {
		cfg.BackoffInitial = 1 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 30 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 20 * time.Second
	}
	if cfg.PongWait <= 0 {
		cfg.PongWait = 10 * time.Second
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	return &Client{
		cfg:     cfg,
		backoff: backoff{initial: cfg.BackoffInitial, max: cfg.BackoffMax},
		dialer:  &websocket.Dialer{HandshakeTimeout: cfg.HandshakeTimeout},
	}, nil
}

// Run is the supervisor loop. It opens the connection, runs the read
// pump, and on disconnect sleeps for a backoff and retries. It returns
// only when ctx is cancelled or Close() has been called.
//
// Typical use:
//
//	go client.Run(ctx)
//	...
//	client.Send(ctx, ev)
//	...
//	client.Close()
func (c *Client) Run(ctx context.Context) {
	for {
		if c.closed.Load() {
			return
		}
		if err := c.connectAndServe(ctx); err != nil {
			if c.closed.Load() {
				return
			}
			if errors.Is(err, context.Canceled) {
				return
			}
			delay := c.backoff.next()
			c.cfg.Logger.Warn("transport: connection lost, reconnecting",
				slog.String("error", err.Error()),
				slog.Duration("delay", delay),
			)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			continue
		}
		// connectAndServe returned nil — Close was called cleanly.
		return
	}
}

// connectAndServe opens a single connection, runs until it dies, and
// returns the terminal error (or nil on graceful Close).
func (c *Client) connectAndServe(ctx context.Context) error {
	hdr := http.Header{}
	if c.cfg.AuthToken != "" {
		hdr.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	conn, resp, err := c.dialer.DialContext(ctx, c.cfg.ServerURL, hdr)
	if err != nil {
		// Bubble up the server's reason if it sent one.
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return fmt.Errorf("dial %s: %w (status=%d, body=%q)", c.cfg.ServerURL, err, resp.StatusCode, string(body))
		}
		return fmt.Errorf("dial %s: %w", c.cfg.ServerURL, err)
	}

	c.setConn(conn)
	c.backoff.reset()
	c.cfg.Logger.Info("transport: connected", slog.String("url", c.cfg.ServerURL))

	// Send HELLO before anything else.
	if err := c.sendHello(); err != nil {
		_ = conn.Close()
		c.setConn(nil)
		return fmt.Errorf("send hello: %w", err)
	}

	// Run the read pump in a separate goroutine; the write side
	// (heartbeat) is the supervisor's responsibility.
	readErr := make(chan error, 1)
	go func() { readErr <- c.readPump() }()

	// Heartbeat loop. We stop it as soon as the connection dies.
	hbStop := make(chan struct{})
	go func() {
		c.heartbeatLoop(hbStop)
	}()

	// Wait for whichever ends first.
	var terminalErr error
	select {
	case <-ctx.Done():
		// Send a BYE so the server frees our session slot.
		_ = c.sendBye("context_canceled")
		terminalErr = ctx.Err()
	case err := <-readErr:
		terminalErr = err
	}
	close(hbStop)
	_ = conn.Close()
	c.setConn(nil)
	return terminalErr
}

// sendHello writes the HELLO frame. Called once per successful dial.
func (c *Client) sendHello() error {
	frame := helloFrame{Type: string(FrameHello), AgentID: c.cfg.AgentID, Version: ProtocolVersion}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	conn := c.getConn()
	if conn == nil {
		return errors.New("no connection")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
	return conn.WriteJSON(frame)
}

// sendBye writes a BYE frame. Best-effort; ignored on error.
func (c *Client) sendBye(reason string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	conn := c.getConn()
	if conn == nil {
		return nil
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return conn.WriteJSON(byeFrame{Type: string(FrameBye), Reason: reason})
}

// sendAck writes a command_ack frame. Used by the read pump after
// the CommandHandler has run.
func (c *Client) sendAck(id, status, errMsg string) error {
	if status != "applied" && status != "failed" {
		return fmt.Errorf("sendAck: invalid status %q", status)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	conn := c.getConn()
	if conn == nil {
		return errors.New("no connection")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return conn.WriteJSON(commandAckFrame{
		Type:   "command_ack",
		ID:     id,
		Status: status,
		Error:  errMsg,
	})
}

// readPump consumes one frame at a time. Phase 4 dispatches
// "command" frames to cfg.CommandHandler and ACKs the server.
func (c *Client) readPump() error {
	conn := c.getConn()
	if conn == nil {
		return errors.New("readPump: no connection")
	}
	conn.SetReadLimit(1 << 20) // 1 MiB
	_ = conn.SetReadDeadline(time.Now().Add(c.cfg.PongWait + c.cfg.HeartbeatInterval))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(c.cfg.PongWait + c.cfg.HeartbeatInterval))
		return nil
	})

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			c.cfg.Logger.Warn("transport: dropping malformed frame", slog.String("error", err.Error()))
			continue
		}
		switch FrameType(env.Type) {
		case FrameCommand:
			var cmd commandFrame
			if err := json.Unmarshal(data, &cmd); err != nil {
				c.cfg.Logger.Warn("transport: malformed command", slog.String("error", err.Error()))
				continue
			}
			if c.cfg.CommandHandler == nil {
				c.cfg.Logger.Warn("transport: received command but no CommandHandler configured",
					slog.String("id", cmd.ID), slog.String("kind", cmd.Kind))
				continue
			}
			// Run the handler synchronously. The server is
			// patient (it has the Action row to retry from),
			// and we want the ACK to reflect the actual
			// effect on the local system.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			status, herr := c.cfg.CommandHandler(ctx, Command{
				ID:       cmd.ID,
				Kind:     cmd.Kind,
				Target:   cmd.Target,
				TTLSec:   cmd.TTLSec,
				IssuedAt: cmd.IssuedAt,
				HMAC:     cmd.HMAC,
			})
			cancel()
			errMsg := ""
			if herr != nil {
				errMsg = herr.Error()
				if status == "" {
					status = "failed"
				}
			}
			if ackErr := c.sendAck(cmd.ID, status, errMsg); ackErr != nil {
				c.cfg.Logger.Warn("transport: command_ack send failed",
					slog.String("id", cmd.ID),
					slog.String("status", status),
					slog.String("error", ackErr.Error()),
				)
			}
			c.cfg.Logger.Info("transport: command processed",
				slog.String("id", cmd.ID),
				slog.String("kind", cmd.Kind),
				slog.String("target", cmd.Target),
				slog.String("status", status),
				slog.String("error", errMsg),
			)
		case FrameHello, FrameEvent, FrameBye:
			// Server should not send these; ignore.
			c.cfg.Logger.Debug("transport: ignoring server-sent frame", slog.String("type", env.Type))
		default:
			c.cfg.Logger.Debug("transport: unknown frame type", slog.String("type", env.Type))
		}
	}
}

// heartbeatLoop sends a ping every HeartbeatInterval. The server is
// expected to respond with a pong within PongWait, which the
// readPump's SetPongHandler uses to extend the read deadline.
func (c *Client) heartbeatLoop(stop <-chan struct{}) {
	t := time.NewTicker(c.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.writeMu.Lock()
			conn := c.getConn()
			if conn == nil {
				c.writeMu.Unlock()
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			err := conn.WriteMessage(websocket.PingMessage, nil)
			c.writeMu.Unlock()
			if err != nil {
				c.cfg.Logger.Debug("transport: ping failed, will reconnect", slog.String("error", err.Error()))
				// Force-close the connection so readPump returns and
				// the supervisor reconnects.
				_ = conn.Close()
				return
			}
		}
	}
}

// Send writes one event frame. Concurrent-safe.
//
// If the connection is not currently up, Send drops the event and
// returns nil (with a debug log) — Phase 1's contract is "best-effort,
// do not backpressure the tailers". The TODO is to make this
// configurable in Phase 5.
func (c *Client) Send(ctx context.Context, ev event.Event) error {
	if c.closed.Load() {
		return errors.New("transport: client is closed")
	}
	conn := c.getConn()
	if conn == nil {
		c.cfg.Logger.Debug("transport: dropping event, no connection", slog.String("event_id", ev.ID))
		return nil
	}
	frame := eventFrame{Type: string(FrameEvent), Event: ev}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if ctx != nil {
		// Caller can pass a per-event deadline via ctx; default is 5s.
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
		}
		dl, _ := ctx.Deadline()
		_ = conn.SetWriteDeadline(dl)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}
	return conn.WriteJSON(frame)
}

// Close marks the client as closed (no reconnects) and closes the
// current connection if any. Safe to call multiple times.
func (c *Client) Close() {
	if c.closed.Swap(true) {
		return
	}
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (c *Client) setConn(conn *websocket.Conn) {
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
}

func (c *Client) getConn() *websocket.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

// backoff implements exponential backoff with a cap.
type backoff struct {
	initial time.Duration
	max     time.Duration
	cur     time.Duration
}

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.initial
	} else {
		b.cur *= 2
		if b.cur > b.max {
			b.cur = b.max
		}
	}
	return b.cur
}

func (b *backoff) reset() {
	b.cur = 0
}
