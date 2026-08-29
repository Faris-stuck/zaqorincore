// Package pprof hosts the runtime profiling
// endpoint for the agent. The endpoint is
// isolated: it binds only to 127.0.0.1, on a
// dedicated port that does NOT share the
// main agent listener, and is gated by the
// ZAQORIN_PPROF environment variable.
//
// Why isolated:
//
//  1. The pprof endpoint is debug-only and
//     should never be reachable from the
//     network.
//  2. The pprof HTTP server is a separate
//     process socket from any listener that
//     accepts untrusted input; an attacker
//     who reaches the agent's main port
//     cannot reach the pprof port.
//  3. Disabling pprof is a single env var.
//     The endpoint is OFF in production by
//     default.
package pprof

import (
	"context"
	"errors"
	"net"
	"net/http"
	// Imported for side effects: registers
	// the pprof endpoints on http.DefaultServeMux.
	_ "net/http/pprof"
	"sync/atomic"
	"time"
)

// DefaultAddr is the loopback bind address.
// The port is conventional for Go pprof;
// change via ZAQORIN_PPROF_ADDR.
const DefaultAddr = "127.0.0.1:6060"

// Server is the pprof HTTP server. One per
// agent process.
type Server struct {
	addr   string
	srv    *http.Server
	ln     net.Listener
	closed atomic.Bool
}

// New builds a Server bound to addr.
// addr should be a loopback address in
// production; the constructor does NOT
// validate this — the caller is responsible
// (see internal/config for the env-gate).
func New(addr string) *Server {
	if addr == "" {
		addr = DefaultAddr
	}
	return &Server{addr: addr}
}

// Start binds the listener and serves
// http.DefaultServeMux (which carries the
// pprof endpoints via the side-effect
// import above). Returns an error if the
// bind fails. The function is non-blocking;
// the server runs on its own goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 5 * time.Second,
		// No ReadTimeout/WriteTimeout:
		// pprof endpoints (e.g. /debug/pprof/profile)
		// take seconds; a tight timeout would
		// kill profile collection.
	}
	go func() {
		_ = s.srv.Serve(ln)
	}()
	return nil
}

// Addr returns the actual bound address. If
// the listener was bound to ":0" (e.g. for
// tests), Addr returns the chosen port.
// Returns "" if Start has not been called.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown stops the server and waits for
// in-flight requests to complete (with a
// bounded grace period).
func (s *Server) Shutdown(ctx context.Context) error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.srv == nil {
		return nil
	}
	err := s.srv.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
