package pprof

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestServer_StartShutdown brings up a
// pprof server on a random port
// (127.0.0.1:0) and tears it down. The
// server must:
//
//  1. Bind successfully.
//  2. Respond to /debug/pprof/ with 200.
//  3. Shutdown cleanly.
func TestServer_StartShutdown(t *testing.T) {
	s := New("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := s.Addr()
	if addr == "" {
		t.Fatal("Addr is empty after Start")
	}

	// Hit /debug/pprof/ and check we get
	// a 200. The body is HTML; we just
	// check the status code.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET pprof: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Shutdown with a 2s grace.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// TestServer_RejectsExternal ensures that
// the default bind address is loopback.
// This is a structural test: it inspects
// the DefaultAddr constant. If someone
// changes it to a wildcard, this test
// fires.
func TestServer_DefaultAddrIsLoopback(t *testing.T) {
	if !strings.HasPrefix(DefaultAddr, "127.0.0.1:") &&
		!strings.HasPrefix(DefaultAddr, "localhost:") {
		t.Errorf("DefaultAddr = %q, want loopback (127.0.0.1: or localhost:)", DefaultAddr)
	}
}

// TestServer_AddrEmptyBeforeStart documents
// the precondition: Addr returns "" until
// Start has been called.
func TestServer_AddrEmptyBeforeStart(t *testing.T) {
	s := New("127.0.0.1:0")
	if got := s.Addr(); got != "" {
		t.Errorf("Addr before Start = %q, want \"\"", got)
	}
}
