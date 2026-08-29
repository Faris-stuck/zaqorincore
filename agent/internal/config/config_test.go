package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// validMinimal is the smallest config the agent will accept.
// Tests mutate a copy of this and feed it through Load.
const validMinimal = `
server_url = "wss://zaqorin.example.com/api/v1/events"

[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestLoad_ValidMinimal(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "agent.toml", validMinimal)

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ServerURL != "wss://zaqorin.example.com/api/v1/events" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	// Defaults applied:
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel default = %q, want info", cfg.LogLevel)
	}
	if cfg.StateDir != "/var/lib/zaqorin-agent" {
		t.Errorf("StateDir default = %q", cfg.StateDir)
	}
	if !cfg.DryRun {
		t.Error("DryRun default should be true")
	}
	if cfg.AgentID != "auto" {
		t.Errorf("AgentID default = %q, want auto", cfg.AgentID)
	}
	if len(cfg.LogSources) != 1 || cfg.LogSources[0].Name != "auth" {
		t.Errorf("LogSources = %+v", cfg.LogSources)
	}
}

func TestLoad_DefaultWindowsEventlogMode(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "agent.toml", `server_url = "wss://zaqorin.example.com/events"
[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WindowsEventlog.Mode != "pull" {
		t.Errorf("default mode = %q, want %q", cfg.WindowsEventlog.Mode, "pull")
	}
}

func TestLoad_PushModeAccepted(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "agent.toml", `server_url = "wss://zaqorin.example.com/events"
[windows_eventlog]
mode = "push"
[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WindowsEventlog.Mode != "push" {
		t.Errorf("mode = %q, want push", cfg.WindowsEventlog.Mode)
	}
}

func TestLoad_BadWindowsEventlogMode(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "agent.toml", `server_url = "wss://zaqorin.example.com/events"
[windows_eventlog]
mode = "yankee"
[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for bad mode")
	}
	if !strings.Contains(err.Error(), "windows_eventlog.mode") {
		t.Errorf("error %q should mention windows_eventlog.mode", err)
	}
}

func TestLoad_MissingServerURL(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "agent.toml", `
[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for missing server_url, got nil")
	} else if !strings.Contains(err.Error(), "server_url") {
		t.Errorf("error %q should mention server_url", err)
	}
}

func TestLoad_BadServerURLScheme(t *testing.T) {
	dir := t.TempDir()
	cases := []string{
		"http://zaqorin.example.com/events",
		"https://zaqorin.example.com/events",
		"zaqorin.example.com/events",
		"ftp://zaqorin.example.com/events",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			body := "server_url = \"" + u + "\"\n\n" + `[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`
			p := writeFile(t, dir, "agent.toml", body)
			if _, err := Load(p); err == nil {
				t.Errorf("expected error for scheme %q, got nil", u)
			} else if !strings.Contains(err.Error(), "scheme") {
				t.Errorf("error %q should mention scheme", err)
			}
		})
	}
}

func TestLoad_BadLogLevel(t *testing.T) {
	dir := t.TempDir()
	body := `
server_url = "wss://x.example.com"
log_level  = "trace"
` + `[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`
	p := writeFile(t, dir, "agent.toml", body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for invalid log_level, got nil")
	} else if !strings.Contains(err.Error(), "log_level") {
		t.Errorf("error %q should mention log_level", err)
	}
}

func TestLoad_DuplicateLogSourceName(t *testing.T) {
	dir := t.TempDir()
	body := `
server_url = "wss://x.example.com"

[[log_source]]
name = "auth"
path = "/var/log/auth.log"

[[log_source]]
name = "auth"
path = "/var/log/auth2.log"
`
	p := writeFile(t, dir, "agent.toml", body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for duplicate log_source name, got nil")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error %q should mention duplicate", err)
	}
}

func TestLoad_RelativeLogSourcePath(t *testing.T) {
	dir := t.TempDir()
	body := `
server_url = "wss://x.example.com"

[[log_source]]
name = "auth"
path = "auth.log"
`
	p := writeFile(t, dir, "agent.toml", body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for relative log_source path, got nil")
	} else if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("error %q should mention absolute", err)
	}
}

func TestLoad_EmptyLogSources(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "agent.toml", `server_url = "wss://x.example.com"`+"\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for empty log_sources, got nil")
	} else if !strings.Contains(err.Error(), "log_source") {
		t.Errorf("error %q should mention log_source", err)
	}
}

func TestLoad_FileMissing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "does-not-exist.toml")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for missing file, got nil")
	} else if !strings.Contains(err.Error(), "read") {
		t.Errorf("error %q should mention read", err)
	}
}

func TestLoad_AllFieldsSet(t *testing.T) {
	dir := t.TempDir()
	body := `
server_url  = "ws://127.0.0.1:9001"
agent_id    = "11111111-2222-3333-4444-555555555555"
auth_token  = "secret-token"
log_level   = "debug"
state_dir   = "/tmp/zaqorin-state"
dry_run     = false

[[log_source]]
name = "auth"
path = "/var/log/auth.log"

[[log_source]]
name = "nginx_access"
path = "/var/log/nginx/access.log"

[response]
allow_block_ip        = true
allow_kill_process    = false
allow_disable_user    = false
block_default_ttl_sec = 600
`
	p := writeFile(t, dir, "agent.toml", body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AgentID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("AgentID = %q", cfg.AgentID)
	}
	if cfg.AuthToken != "secret-token" {
		t.Errorf("AuthToken = %q", cfg.AuthToken)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.DryRun {
		t.Error("DryRun should be false")
	}
	if len(cfg.LogSources) != 2 {
		t.Errorf("LogSources len = %d, want 2", len(cfg.LogSources))
	}
	if cfg.Response.BlockDefaultTTLSec != 600 {
		t.Errorf("BlockDefaultTTLSec = %d", cfg.Response.BlockDefaultTTLSec)
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	body := `
server_url = "wss://round.example.com"

[[log_source]]
name = "auth"
path = "/var/log/auth.log"
`
	p := writeFile(t, dir, "agent.toml", body)
	cfg1, err := Load(p)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	// Writing the same struct back out and re-loading should be a
	// fixed point (defaults are stable).
	var buf strings.Builder
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(cfg1); err != nil {
		t.Fatalf("encode: %v", err)
	}
	p2 := writeFile(t, dir, "round.toml", buf.String())
	cfg2, err := Load(p2)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if cfg1.ServerURL != cfg2.ServerURL || cfg1.LogLevel != cfg2.LogLevel || len(cfg1.LogSources) != len(cfg2.LogSources) {
		t.Errorf("round-trip mismatch:\n  cfg1=%+v\n  cfg2=%+v", cfg1, cfg2)
	}
}

func TestResolveAgentID_LiteralUUID(t *testing.T) {
	cfg := Defaults()
	cfg.AgentID = "11111111-2222-3333-4444-555555555555"
	id, generated, err := ResolveAgentID(&cfg)
	if err != nil {
		t.Fatalf("ResolveAgentID: %v", err)
	}
	if id != cfg.AgentID {
		t.Errorf("id = %q, want %q", id, cfg.AgentID)
	}
	if generated {
		t.Error("generated should be false for literal UUID")
	}
}

func TestResolveAgentID_InvalidLiteral(t *testing.T) {
	cfg := Defaults()
	cfg.AgentID = "not-a-uuid"
	if _, _, err := ResolveAgentID(&cfg); err == nil {
		t.Fatal("expected error for non-UUID agent_id, got nil")
	}
}

func TestResolveAgentID_AutoFresh(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.AgentID = "auto"
	cfg.StateDir = dir

	id, generated, err := ResolveAgentID(&cfg)
	if err != nil {
		t.Fatalf("ResolveAgentID: %v", err)
	}
	if !generated {
		t.Error("generated should be true on first run")
	}
	if id == "" {
		t.Fatal("id is empty")
	}
	// File should exist now.
	data, err := os.ReadFile(filepath.Join(dir, "agent_id"))
	if err != nil {
		t.Fatalf("agent_id file missing: %v", err)
	}
	if strings.TrimSpace(string(data)) != id {
		t.Errorf("persisted id %q != returned id %q", strings.TrimSpace(string(data)), id)
	}
}

func TestResolveAgentID_AutoReusesPersisted(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.AgentID = "auto"
	cfg.StateDir = dir

	first, _, err := ResolveAgentID(&cfg)
	if err != nil {
		t.Fatalf("first ResolveAgentID: %v", err)
	}
	second, generated, err := ResolveAgentID(&cfg)
	if err != nil {
		t.Fatalf("second ResolveAgentID: %v", err)
	}
	if generated {
		t.Error("second call should not regenerate")
	}
	if first != second {
		t.Errorf("id changed across calls: %q -> %q", first, second)
	}
}
