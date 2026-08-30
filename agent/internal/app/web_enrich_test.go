package app

import (
	"log/slog"
	"os"
	"testing"

	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
)

func TestEnrichWithWebParser_NginxAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := event.New("test-agent", event.SourceNginxAccess,
		`203.0.113.42 - alice [30/Aug/2026:12:34:56 +0000] `+
			`"GET /admin/users?id=1 HTTP/1.1" 200 1234 `+
			`"https://example.com/" "Mozilla/5.0"`)
	enrichWithWebParser(&ev, logger)

	if ev.Metadata[event.WebKeySourceIP] != "203.0.113.42" {
		t.Errorf("src_ip: got %q", ev.Metadata[event.WebKeySourceIP])
	}
	if ev.Metadata[event.WebKeyMethod] != "GET" {
		t.Errorf("http_method: got %q", ev.Metadata[event.WebKeyMethod])
	}
	if ev.Metadata[event.WebKeyURI] != "/admin/users?id=1" {
		t.Errorf("uri: got %q", ev.Metadata[event.WebKeyURI])
	}
	if ev.Metadata[event.WebKeyStatus] != "200" {
		t.Errorf("status_code: got %q", ev.Metadata[event.WebKeyStatus])
	}
	if ev.Metadata[event.WebKeyAuthUser] != "alice" {
		t.Errorf("auth_user: got %q", ev.Metadata[event.WebKeyAuthUser])
	}
}

func TestEnrichWithWebParser_ModSecAudit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := event.New("test-agent", event.SourceModSecAudit, "--5d7c1e2a-A--")
	enrichWithWebParser(&ev, logger)
	if ev.Metadata["modsec_section"] != "A" {
		t.Errorf("modsec_section: got %q", ev.Metadata["modsec_section"])
	}
}

func TestEnrichWithWebParser_UnrelatedSource(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := event.New("test-agent", "journald", "hello world")
	enrichWithWebParser(&ev, logger)
	if ev.Metadata != nil && len(ev.Metadata) > 0 {
		t.Errorf("expected no metadata for journald source, got %v", ev.Metadata)
	}
}

func TestEnrichWithWebParser_NginxUnrecognised(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ev := event.New("test-agent", event.SourceNginxAccess, "this is not a log line")
	enrichWithWebParser(&ev, logger)
	// Should not panic, should not add metadata.
	if ev.Metadata != nil && len(ev.Metadata) > 0 {
		t.Errorf("expected no metadata for malformed nginx line, got %v", ev.Metadata)
	}
}

func TestEnrichWithWebParser_NilEvent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	// Should not panic.
	enrichWithWebParser(nil, logger)
}