// Package config loads and validates the agent's TOML configuration file.
//
// The file format is documented in agent.example.toml at the repo root.
// Validation here is defensive: any field the operator can mis-type is
// checked, and the errors are operator-friendly (file + line where the
// TOML decoder can provide them, otherwise a clear message).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/uuid"
)

// LogSource describes a single log file the agent should tail.
//
// The Name is what the agent puts in the event.Source field, so it must
// be stable across restarts — detectors on the server side group by it.
type LogSource struct {
	Name string `toml:"name"`
	Path string `toml:"path"`
}

// WindowsEventlog configures the Windows Event Log backend
// (Windows hosts only). v1.6.0 adds `mode = "push"` for
// lower-latency event delivery via EvtSubscribe callback;
// `mode = "pull"` (the default) uses the v1.2.0 poll loop
// at the configured interval.
type WindowsEventlog struct {
	// Mode is "pull" (default) or "push". Any other
	// value is rejected at Load() time.
	Mode string `toml:"mode"`
}

// Response controls which auto-response actions the agent is allowed
// to apply. Phase 1 ignores this (no response side is wired up), but the
// field is parsed so existing operator configs keep working in Phase 4.
type Response struct {
	AllowBlockIP        bool `toml:"allow_block_ip"`
	AllowKillProcess    bool `toml:"allow_kill_process"`
	AllowDisableUser    bool `toml:"allow_disable_user"`
	BlockDefaultTTLSec  int  `toml:"block_default_ttl_sec"`
}

// Config is the in-memory representation of the agent's TOML file.
// Defaults are applied during Load(); the zero value is NOT a valid
// config (server_url is required).
type Config struct {
	ServerURL        string           `toml:"server_url"`
	AgentID          string           `toml:"agent_id"`
	AuthToken        string           `toml:"auth_token"`
	LogLevel         string           `toml:"log_level"`
	StateDir         string           `toml:"state_dir"`
	DryRun           bool             `toml:"dry_run"`
	LogSources       []LogSource      `toml:"log_source"`
	Response         Response         `toml:"response"`
	WindowsEventlog  WindowsEventlog  `toml:"windows_eventlog"`
}

// validLogLevels are the levels the agent's logger accepts. We map
// anything else to "info" with a warning during Load().
var validLogLevels = map[string]struct{}{
	"debug": {},
	"info":  {},
	"warn":  {},
	"error": {},
}

// IsValidLogLevel reports whether level is one of the values the
// agent's logger recognises. Exported for tests.
func IsValidLogLevel(level string) bool {
	_, ok := validLogLevels[level]
	return ok
}

// Defaults returns a Config populated with the same defaults Load()
// applies when fields are omitted. Exported for tests and for the
// rare caller that wants to build a config in code.
func Defaults() Config {
	return Config{
		AgentID:  "auto",
		LogLevel: "info",
		StateDir: "/var/lib/zaqorin-agent",
		DryRun:   true,
		Response: Response{
			AllowBlockIP:       true,
			BlockDefaultTTLSec: 3600,
		},
		WindowsEventlog: WindowsEventlog{
			Mode: "pull",
		},
	}
}

// Load reads, parses, validates, and default-fills the config at path.
// The returned *Config is always non-nil on a nil error.
//
// Load does NOT touch the filesystem beyond reading the file itself —
// agent_id resolution against state_dir is the caller's job (it happens
// once per process, at startup, and needs the logger to be ready).
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config: path is empty")
	}
	// Resolve to an absolute path so error messages and downstream
	// state_dir joins are unambiguous.
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", abs, err)
	}

	// Start from defaults so unspecified fields have sane values.
	cfg := Defaults()

	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", abs, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: invalid %s: %w", abs, err)
	}
	return &cfg, nil
}

// validate enforces the cross-field invariants documented in
// agent.example.toml. Returns the first violation found; we do not
// collect all of them because the typical operator mistake is a
// single field, and stacking errors makes the message noisy.
func (c *Config) validate() error {
	if strings.TrimSpace(c.ServerURL) == "" {
		return errors.New("server_url is required")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return fmt.Errorf("server_url is not a valid URL: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("server_url scheme must be ws:// or wss://, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("server_url is missing a host")
	}

	if c.AgentID == "" {
		// Operator wrote agent_id = "" explicitly — treat as "auto".
		c.AgentID = "auto"
	}

	if !IsValidLogLevel(c.LogLevel) {
		return fmt.Errorf("log_level %q is not one of debug|info|warn|error", c.LogLevel)
	}

	if c.StateDir == "" {
		return errors.New("state_dir must not be empty")
	}

	if len(c.LogSources) == 0 {
		return errors.New("at least one [[log_source]] entry is required")
	}
	seen := make(map[string]struct{}, len(c.LogSources))
	for i, src := range c.LogSources {
		if strings.TrimSpace(src.Name) == "" {
			return fmt.Errorf("log_source[%d]: name is required", i)
		}
		if strings.TrimSpace(src.Path) == "" {
			return fmt.Errorf("log_source[%d] (%q): path is required", i, src.Name)
		}
		if !filepath.IsAbs(src.Path) {
			return fmt.Errorf("log_source[%d] (%q): path must be absolute, got %q", i, src.Name, src.Path)
		}
		if _, dup := seen[src.Name]; dup {
			return fmt.Errorf("log_source[%d]: duplicate name %q", i, src.Name)
		}
		seen[src.Name] = struct{}{}
	}

	if c.Response.BlockDefaultTTLSec < 0 {
		return fmt.Errorf("response.block_default_ttl_sec must be >= 0, got %d", c.Response.BlockDefaultTTLSec)
	}

	// v1.6.0: Windows Event Log mode validation.
	if c.WindowsEventlog.Mode != "" && c.WindowsEventlog.Mode != "pull" && c.WindowsEventlog.Mode != "push" {
		return fmt.Errorf("windows_eventlog.mode must be one of pull|push, got %q", c.WindowsEventlog.Mode)
	}
	return nil
}

// ResolveAgentID returns the agent's stable identifier:
//
//   - If cfg.AgentID is "auto" (or empty after defaulting), the function
//     reads state_dir/agent_id. If that file exists and contains a valid
//     UUID, it is returned. Otherwise a fresh UUID v4 is generated, the
//     directory is created if needed, and the new ID is persisted. The
//     persisted ID is also returned so the caller can log it.
//   - If cfg.AgentID is a literal UUID, it is returned unchanged and the
//     state file is not touched. (Operator-pinned identity.)
//
// The second return value reports whether a new ID was generated and
// persisted — useful for the startup log line.
func ResolveAgentID(cfg *Config) (string, bool, error) {
	if cfg.AgentID != "auto" {
		if _, err := uuid.Parse(cfg.AgentID); err != nil {
			return "", false, fmt.Errorf("agent_id %q is not a valid UUID (use \"auto\" to auto-generate): %w", cfg.AgentID, err)
		}
		return cfg.AgentID, false, nil
	}

	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return "", false, fmt.Errorf("create state_dir %s: %w", cfg.StateDir, err)
	}
	idPath := filepath.Join(cfg.StateDir, "agent_id")
	existing, err := os.ReadFile(idPath)
	if err == nil {
		id := strings.TrimSpace(string(existing))
		if _, perr := uuid.Parse(id); perr == nil {
			return id, false, nil
		}
		// Corrupt file — fall through to regeneration.
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("read %s: %w", idPath, err)
	}

	id := uuid.NewString()
	if err := os.WriteFile(idPath, []byte(id+"\n"), 0o644); err != nil {
		return "", false, fmt.Errorf("write %s: %w", idPath, err)
	}
	return id, true, nil
}
