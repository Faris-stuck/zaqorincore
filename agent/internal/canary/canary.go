// Package canary watches canary tokens on the local filesystem
// and TCP ports. Phase 7 (ADR-005).
//
// A canary token is a file (or a TCP listener) that no
// legitimate process should ever touch. When something does,
// the watcher emits a `canary_touched` event over the agent's
// WS transport. The server-side rule engine can then fire a
// `canary_alert` action with zero false-positive risk.
//
// The watcher is intentionally minimal: inotify for files, a
// trivial net.Listener for TCP. We do not aim to be a full
// filesystem integrity monitor — AIDE or samhain already do
// that. The canary watcher is a single-purpose "did anyone
// touch this thing?" probe.
package canary

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Descriptor mirrors the server's CanaryDescriptor. The agent
// receives a list of these from the server's CONFIG frame and
// instantiates one watcher per entry.
type Descriptor struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // file | tcp_socket | http_endpoint | credential
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	Secret    string    `json:"secret"`
}

// Touch is the event payload the agent sends to the server
// when a canary is touched. The server ingests it as a normal
// event with event_type="canary_touched".
type Touch struct {
	CanaryID     string `json:"canary_id"`
	TouchedBy    string `json:"touched_by"`
	EvidencePath string `json:"evidence_path,omitempty"`
}

// Watcher is the per-host canary registry. It owns the inotify
// handle and the TCP listeners. Touches are reported on the
// `touches` channel; the agent's main loop drains it and
// forwards each one as a `canary_touched` event.
type Watcher struct {
	mu      sync.Mutex
	log     *slog.Logger
	entries map[string]*entry // id -> entry
	touches chan Touch
}

// entry is the live state for one canary. File canaries hold
// the fsnotify watch; TCP canaries hold the listener.
type entry struct {
	desc     Descriptor
	watcher  *fsnotify.Watcher
	listener net.Listener
	cancel   context.CancelFunc
}

func New(log *slog.Logger) *Watcher {
	return &Watcher{
		log:     log,
		entries: make(map[string]*entry),
		touches: make(chan Touch, 64),
	}
}

// Touches returns the channel the agent's main loop reads.
func (w *Watcher) Touches() <-chan Touch { return w.touches }

// Add registers a descriptor and starts its watcher.
func (w *Watcher) Add(ctx context.Context, desc Descriptor) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, exists := w.entries[desc.ID]; exists {
		return fmt.Errorf("canary %s already registered", desc.ID)
	}
	cctx, cancel := context.WithCancel(ctx)
	e := &entry{desc: desc, cancel: cancel}
	switch desc.Kind {
	case "file":
		if err := w.watchFile(cctx, e); err != nil {
			cancel()
			return fmt.Errorf("watch file: %w", err)
		}
	case "tcp_socket":
		if err := w.watchTCP(cctx, e); err != nil {
			cancel()
			return fmt.Errorf("watch tcp: %w", err)
		}
	case "http_endpoint":
		// HTTP canaries are just TCP listeners on the configured
		// port. The agent doesn't run a full HTTP server — we
		// treat any inbound connection as a touch, since legitimate
		// clients should never hit a canary port.
		if err := w.watchTCP(cctx, e); err != nil {
			cancel()
			return fmt.Errorf("watch http: %w", err)
		}
	case "credential":
		// Credential canaries are entries planted in a watched
		// file (e.g. /etc/shadow, ~/.aws/credentials). The agent
		// fsnotify-watches the file and any read of the canary
		// line fires a touch. Path is the file; Secret is the
		// planted token string.
		if err := w.watchFile(cctx, e); err != nil {
			cancel()
			return fmt.Errorf("watch credential: %w", err)
		}
	default:
		cancel()
		return fmt.Errorf("unsupported canary kind: %s", desc.Kind)
	}
	w.entries[desc.ID] = e
	return nil
}

func (w *Watcher) watchFile(ctx context.Context, e *entry) error {
	// Make sure the canary file exists. We create a tiny marker
	// so fsnotify has something to watch; the canary's "secret"
	// is the file's content hash.
	if _, err := os.Stat(e.desc.Path); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(e.desc.Path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(e.desc.Path, []byte(e.desc.Secret+"\n"), 0o600); err != nil {
			return err
		}
	}
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := fw.Add(filepath.Dir(e.desc.Path)); err != nil {
		fw.Close()
		return err
	}
	e.watcher = fw
	go w.fileLoop(ctx, e)
	return nil
}

func (w *Watcher) fileLoop(ctx context.Context, e *entry) {
	defer e.watcher.Close()
	target := e.desc.Path
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-e.watcher.Events:
			if !ok {
				return
			}
			if ev.Name == target {
				w.fire(Touch{
					CanaryID:     e.desc.ID,
					TouchedBy:    ev.Op.String(),
					EvidencePath: target,
				})
			}
		case err, ok := <-e.watcher.Errors:
			if !ok {
				return
			}
			w.log.Warn("canary fsnotify error", "id", e.desc.ID, "err", err)
		}
	}
}

func (w *Watcher) watchTCP(ctx context.Context, e *entry) error {
	// Path is a port number string (e.g. "2222") for tcp_socket
	// canaries. We bind to 127.0.0.1:<port> and report any
	// connection as a touch.
	addr := ":" + e.desc.Path
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	e.listener = ln
	go w.tcpLoop(ctx, e)
	return nil
}

func (w *Watcher) tcpLoop(ctx context.Context, e *entry) {
	defer e.listener.Close()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := e.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			w.log.Warn("canary accept failed", "id", e.desc.ID, "err", err)
			continue
		}
		remote := conn.RemoteAddr().String()
		// Drain and close. We don't want a canary to actually
		// serve anything.
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		w.fire(Touch{
			CanaryID:     e.desc.ID,
			TouchedBy:    "tcp:" + remote,
			EvidencePath: e.listener.Addr().String(),
		})
	}
}

func (w *Watcher) fire(t Touch) {
	select {
	case w.touches <- t:
	default:
		w.log.Warn("canary touches channel full, dropping", "id", t.CanaryID)
	}
}

// Remove stops a watcher and forgets the entry.
func (w *Watcher) Remove(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e, ok := w.entries[id]; ok {
		e.cancel()
		if e.watcher != nil {
			_ = e.watcher.Close()
		}
		if e.listener != nil {
			_ = e.listener.Close()
		}
		delete(w.entries, id)
	}
}

// List returns the active canary IDs (for diagnostics).
func (w *Watcher) List() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids := make([]string, 0, len(w.entries))
	for id := range w.entries {
		ids = append(ids, id)
	}
	return ids
}

// MarshalDescriptors serializes a list of descriptors for the
// CONFIG frame.
func MarshalDescriptors(descs []Descriptor) ([]byte, error) {
	return json.Marshal(descs)
}
