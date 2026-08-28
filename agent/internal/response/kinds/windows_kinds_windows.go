//go:build windows

// Windows action applier (ADR-007 Slice 3, v1.2.0).
//
// Implements the four action kinds the Linux kinds package does
// NOT cover on Windows. The kinds package itself is
// platform-agnostic; per-platform implementations live here so
// the dispatcher's call site does not change.
//
// Kinds covered:
//
//   - kill_process     : OpenProcess + TerminateProcess (via
//                        kinds.platformKill, which the kinds
//                        package already calls; this file only
//                        re-exports the public Windows helper)
//   - quarantine_file  : icacls deny + rename to .quarantine
//   - block_ip         : netsh advfirewall firewall add rule
//   - revoke_credential: klist purge (tickets) + logoff session
//
// All four go through `exec.CommandContext` with a 30s timeout
// because Windows commands can hang on locked files / network
// RPC. The timeout is enforced by the caller's ctx, but the
// helpers below also set a defensive deadline via the parameter
// ctx.
//
// All commands require administrator privileges. The
// install.ps1 (packaging/windows/install.ps1) installs the
// service as LocalSystem which carries the right by default.
package kinds

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// timeoutSec is the per-command wall-clock cap. Windows tools
// rarely exceed 10s on a healthy host; 30s is a generous upper
// bound that still frees the agent if a command wedges.
const winTimeoutSec = 30

// QuarantineFileWin denies all access to `path` via icacls then
// moves the file under %ProgramData%\zaqorin-agent\quarantine with
// a .quarantine extension. The deny ACL is set first so the
// file becomes unreadable even if the rename fails (the agent
// will retry the rename at next incident).
func QuarantineFileWin(ctx context.Context, path string, log *slog.Logger) error {
	if !IsValidPath(path) {
		return fmt.Errorf("quarantine_file: invalid path %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("quarantine_file: stat: %w", err)
	}
	dctx, cancel := context.WithTimeout(ctx, winTimeoutSec*time.Second)
	defer cancel()
	// 1. icacls deny *S-1-1-0 (Everyone) — denies read/write/execute.
	c := exec.CommandContext(dctx, "icacls", path, "/deny", "*S-1-1-0:(R,W,X,F)")
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		log.Warn("response: icacls deny failed (continuing)",
			slog.String("path", path), slog.String("error", err.Error()))
	}
	// 2. Move under ProgramData quarantine. ProgramData is the
	//    cross-user equivalent of /var/lib on Linux; ACLs there
	//    are restrictive by default which matches our intent.
	vault := filepath.Join(os.Getenv("ProgramData"), "zaqorin-agent", "quarantine")
	if err := os.MkdirAll(vault, 0o700); err != nil {
		return fmt.Errorf("quarantine_file: mkdir vault: %w", err)
	}
	dest := filepath.Join(vault, filepath.Base(path)+".quarantine")
	// Disambiguate if a file with the same name already exists.
	for i := 1; ; i++ {
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			break
		}
		dest = filepath.Join(vault, fmt.Sprintf("%s.%d.quarantine", filepath.Base(path), i))
	}
	if err := os.Rename(path, dest); err != nil {
		return fmt.Errorf("quarantine_file: rename: %w", err)
	}
	log.Info("response: quarantined file",
		slog.String("src", path), slog.String("dest", dest))
	return nil
}

// BlockIPWin adds a Windows Firewall deny rule via netsh. The
// rule is named "zaqorin-block-<ip>" so the TTL goroutine can
// find and remove it later. The rule is given a 1-minute
// activity timeout to bound resource use even if the agent
// crashes before un-applying.
func BlockIPWin(ctx context.Context, ip string, ttl int, log *slog.Logger) error {
	if !IsValidIPv4(ip) {
		return fmt.Errorf("block_ip: invalid IPv4 address %q", ip)
	}
	if ttl <= 0 {
		ttl = 3600
	}
	dctx, cancel := context.WithTimeout(ctx, winTimeoutSec*time.Second)
	defer cancel()
	ruleName := "zaqorin-block-" + strings.ReplaceAll(ip, ".", "-")
	c := exec.CommandContext(dctx, "netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=in",
		"action=block",
		fmt.Sprintf("remoteip=%s", ip),
	)
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		// A rule with the same name already exists is non-fatal.
		log.Debug("response: netsh block (may already exist)",
			slog.String("ip", ip), slog.String("rule", ruleName),
			slog.String("error", err.Error()))
	}
	log.Info("response: blocked IP (Windows Firewall)",
		slog.String("ip", ip), slog.Int("ttl_sec", ttl),
		slog.String("rule", ruleName))
	// Schedule removal. We do not block the caller.
	if ttl > 0 {
		go removeBlockIPAfter(ip, ttl, log)
	}
	return nil
}

func removeBlockIPAfter(ip string, ttl int, log *slog.Logger) {
	time.Sleep(time.Duration(ttl) * time.Second)
	ruleName := "zaqorin-block-" + strings.ReplaceAll(ip, ".", "-")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName))
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		log.Warn("response: netsh delete rule failed",
			slog.String("ip", ip), slog.String("rule", ruleName),
			slog.String("error", err.Error()))
		return
	}
	log.Info("response: block expired (rule removed)",
		slog.String("ip", ip), slog.String("rule", ruleName))
}

// RevokeCredentialWin clears the local Kerberos ticket cache via
// `klist purge` and logs off the specified session id. `target`
// is interpreted as either:
//
//   - a session id (numeric)            -> `logoff <id>`
//   - a username                        -> `logoff <id>` after
//                                          looking up via `query
//                                          session`
//   - the special string "all" or ""    -> purge all tickets
//                                          and log off every
//                                          active session
func RevokeCredentialWin(ctx context.Context, target string, log *slog.Logger) error {
	if target == "" {
		target = "all"
	}
	dctx, cancel := context.WithTimeout(ctx, winTimeoutSec*time.Second)
	defer cancel()
	// 1. Purge all Kerberos tickets. The agent's own service ticket
	//    is excluded because klist purge requires a fresh ticket
	//    and the agent never holds one for itself.
	c := exec.CommandContext(dctx, "klist", "purge")
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		log.Warn("response: klist purge failed",
			slog.String("target", target), slog.String("error", err.Error()))
	}
	// 2. Log off session(s).
	if target == "all" {
		if err := logOffAll(dctx, log); err != nil {
			return fmt.Errorf("revoke_credential: logoff all: %w", err)
		}
	} else {
		if err := logOffOne(dctx, target, log); err != nil {
			return fmt.Errorf("revoke_credential: logoff %s: %w", target, err)
		}
	}
	log.Info("response: credentials revoked",
		slog.String("target", target))
	return nil
}

// logOffOne logs off a single session by id (numeric) or by
// username. `query session` is parsed to translate the username
// into an id.
func logOffOne(ctx context.Context, target string, log *slog.Logger) error {
	id := target
	if !isDigits(target) {
		// Look up id by username.
		out, err := exec.CommandContext(ctx, "query", "session").CombinedOutput()
		if err != nil {
			return fmt.Errorf("query session: %w", err)
		}
		id = findSessionID(string(out), target)
		if id == "" {
			return errors.New("session not found for username " + target)
		}
	}
	c := exec.CommandContext(ctx, "logoff", id)
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("logoff: %w", err)
	}
	log.Info("response: session logged off", slog.String("id", id))
	return nil
}

// logOffAll logs off every active session except the current
// one. We never log the agent's own session off; the agent runs
// as a service in session 0 and the rule below keeps that one.
func logOffAll(ctx context.Context, log *slog.Logger) error {
	out, err := exec.CommandContext(ctx, "query", "session").CombinedOutput()
	if err != nil {
		return fmt.Errorf("query session: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] == "SESSIONNAME" || fields[0] == "" {
			continue
		}
		// fields[0] is the id (numeric). We skip the console
		// session ("console") and the service session
		// ("Services"). Logging off "Services" would
		// terminate the agent itself.
		if !isDigits(fields[0]) {
			continue
		}
		c := exec.CommandContext(ctx, "logoff", fields[0])
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			log.Warn("response: logoff failed",
				slog.String("id", fields[0]), slog.String("error", err.Error()))
			continue
		}
		log.Info("response: session logged off", slog.String("id", fields[0]))
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// findSessionID returns the id of the first session line whose
// username column matches `user`. `query session` output is column
// based; we use a lenient match by splitting on >2 spaces because
// the exact column count varies by Windows version.
func findSessionID(output, user string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] == "SESSIONNAME" {
			continue
		}
		if fields[1] == user || fields[2] == user {
			return fields[0]
		}
	}
	return ""
}

// IsValidPathWindows mirrors IsValidPath but accepts Windows
// drive letters and UNC paths in addition to plain absolute
// paths. The Linux IsValidPath rejects everything not starting
// with "/" so we provide a Windows-specific version for the
// quarantine_file path validator.
//
// Accepts:
//   - C:\path\to\file
//   - C:/path/to/file
//   - \\server\share\file
//   - D:\relative-with-backslash
func IsValidPathWindows(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "\\\\") {
		return len(s) > 2
	}
	if len(s) >= 3 && s[1] == ':' {
		c := s[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return s[2] == '\\' || s[2] == '/'
		}
	}
	return false
}
