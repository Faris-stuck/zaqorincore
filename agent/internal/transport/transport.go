package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
)

const ProtocolVersion = "2.0"

const (
	FrameChallenge FrameType = "challenge"
	FrameHello     FrameType = "hello"
	FrameEvent     FrameType = "event"
	FrameBye       FrameType = "bye"
	FrameCommand   FrameType = "command"
)

type FrameType string

type Command struct {
	ID       string
	Kind     string
	Target   string
	TTLSec   int
	IssuedAt string
	HMAC     string
}

type helloFrame struct {
	Type    string `json:"type"`
	AgentID string `json:"agent_id"`
	V       int    `json:"v"`
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
	Sig     string `json:"sig"`
}

type challengeFrame struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
	V     int    `json:"v"`
}

type eventFrame struct {
	Type  string      `json:"type"`
	Event event.Event `json:"event"`
}

type byeFrame struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type commandFrame struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	TTLSec   int    `json:"ttl_sec"`
	IssuedAt string `json:"issued_at"`
	HMAC     string `json:"hmac"`
}

type commandAckFrame struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type envelope struct {
	Type string `json:"type"`
}

type Config struct {
	ServerURL        string
	AgentID          string
	AuthToken        string
	SharedSecret     string
	Logger           *slog.Logger
	BackoffInitial   time.Duration
	BackoffMax       time.Duration
	HeartbeatInterval time.Duration
	PongWait         time.Duration
	HandshakeTimeout time.Duration
	CommandHandler   func(ctx context.Context, cmd Command) (status string, err error)
}

func (c *Client) SetCommandHandler(h func(ctx context.Context, cmd Command) (string, error)) {
	c.cfg.CommandHandler = h
}

type Client struct {
	cfg     Config
	backoff backoff
	dialer  *websocket.Dialer
	mu      sync.Mutex
	conn    *websocket.Conn
	closed  atomic.Bool
	writeMu sync.Mutex
}

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
		cfg.BackoffInitial = time.Second
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
	if strings.HasPrefix(strings.ToLower(cfg.ServerURL), "wss://") {
		cfg2 := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
		return &Client{
			cfg: cfg,
			backoff: backoff{initial: cfg.BackoffInitial, max: cfg.BackoffMax},
			dialer: &websocket.Dialer{HandshakeTimeout: cfg.HandshakeTimeout, TLSClientConfig: cfg2},
		}, nil
	}
	// ws:// remains available for loopback/dev integration tests only.
	if !isLoopbackWS(cfg.ServerURL) {
		return nil, errors.New("transport: insecure ws:// is allowed only for loopback hosts; use wss://")
	}
	cfg.Logger.Warn("transport: using insecure loopback WebSocket for development")
	return &Client{
		cfg: cfg,
		backoff: backoff{initial: cfg.BackoffInitial, max: cfg.BackoffMax},
		dialer: &websocket.Dialer{HandshakeTimeout: cfg.HandshakeTimeout},
	}, nil
}

func isLoopbackWS(raw string) bool {
	raw = strings.ToLower(raw)
	return strings.HasPrefix(raw, "ws://127.0.0.1:") || strings.HasPrefix(raw, "ws://localhost:") || strings.HasPrefix(raw, "ws://[::1]:")
}

func (c *Client) Run(ctx context.Context) {
	for {
		if c.closed.Load() {
			return
		}
		if err := c.connectAndServe(ctx); err != nil {
			if c.closed.Load() || errors.Is(err, context.Canceled) {
				return
			}
			delay := c.backoff.next()
			c.cfg.Logger.Warn("transport: connection lost, reconnecting", slog.String("error", err.Error()), slog.Duration("delay", delay))
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			continue
		}
		return
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	hdr := http.Header{}
	if c.cfg.AuthToken != "" {
		hdr.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	conn, resp, err := c.dialer.DialContext(ctx, c.cfg.ServerURL, hdr)
	if err != nil {
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

	if err := c.authenticate(ctx); err != nil {
		_ = conn.Close()
		c.setConn(nil)
		return fmt.Errorf("authenticate: %w", err)
	}

	readErr := make(chan error, 1)
	go func() { readErr <- c.readPump() }()
	hbStop := make(chan struct{})
	go c.heartbeatLoop(hbStop)

	var terminalErr error
	select {
	case <-ctx.Done():
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

func (c *Client) authenticate(ctx context.Context) error {
	if strings.TrimSpace(c.cfg.SharedSecret) == "" {
		return errors.New("shared secret is empty")
	}
	conn := c.getConn()
	if conn == nil {
		return errors.New("no connection")
	}
	_ = conn.SetReadDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
	_, data, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	var challenge challengeFrame
	if err := json.Unmarshal(data, &challenge); err != nil {
		return fmt.Errorf("challenge is not valid JSON: %w", err)
	}
	if challenge.Type != string(FrameChallenge) || challenge.V != 2 {
		return fmt.Errorf("unexpected challenge type/version: type=%q v=%d", challenge.Type, challenge.V)
	}
	if _, err := hex.DecodeString(challenge.Nonce); err != nil || len(challenge.Nonce) != 64 {
		return errors.New("invalid challenge nonce")
	}
	mac := hmac.New(sha256.New, []byte(c.cfg.SharedSecret))
	_, _ = mac.Write([]byte(challenge.Nonce))
	sig := hex.EncodeToString(mac.Sum(nil))
	return c.sendHello(challenge.Nonce, sig)
}

func (c *Client) sendHello(nonce, sig string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	conn := c.getConn()
	if conn == nil {
		return errors.New("no connection")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
	frame := helloFrame{
		Type: string(FrameHello), AgentID: c.cfg.AgentID, V: 2,
		Version: ProtocolVersion, Nonce: nonce, Sig: sig,
	}
	return conn.WriteJSON(frame)
}

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
	return conn.WriteJSON(commandAckFrame{Type: "command_ack", ID: id, Status: status, Error: errMsg})
}

func (c *Client) readPump() error {
	conn := c.getConn()
	if conn == nil {
		return errors.New("readPump: no connection")
	}
	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(c.cfg.PongWait + c.cfg.HeartbeatInterval))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(c.cfg.PongWait + c.cfg.HeartbeatInterval))
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
				continue
			}
			if c.cfg.CommandHandler == nil {
				c.cfg.Logger.Warn("transport: received command with no handler", slog.String("id", cmd.ID))
				continue
			}
			cmdCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			status, herr := c.cfg.CommandHandler(cmdCtx, Command{ID: cmd.ID, Kind: cmd.Kind, Target: cmd.Target, TTLSec: cmd.TTLSec, IssuedAt: cmd.IssuedAt, HMAC: cmd.HMAC})
			cancel()
			errMsg := ""
			if herr != nil {
				errMsg = herr.Error()
				if status == "" {
					status = "failed"
				}
			}
			if err := c.sendAck(cmd.ID, status, errMsg); err != nil {
				c.cfg.Logger.Warn("transport: command_ack failed", slog.String("id", cmd.ID), slog.String("error", err.Error()))
			}
		case FrameHello, FrameEvent, FrameBye, FrameChallenge:
			c.cfg.Logger.Debug("transport: ignoring server-sent frame", slog.String("type", env.Type))
		default:
			c.cfg.Logger.Debug("transport: unknown frame type", slog.String("type", env.Type))
		}
	}
}

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
				_ = conn.Close()
				return
			}
		}
	}
}

func (c *Client) Send(ctx context.Context, ev event.Event) error {
	if c.closed.Load() {
		return errors.New("transport: client is closed")
	}
	conn := c.getConn()
	if conn == nil {
		c.cfg.Logger.Debug("transport: dropping event, no connection", slog.String("event_id", ev.ID))
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(5 * time.Second)
	}
	_ = conn.SetWriteDeadline(dl)
	return conn.WriteJSON(eventFrame{Type: string(FrameEvent), Event: ev})
}

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

func (b *backoff) reset() { b.cur = 0 }
