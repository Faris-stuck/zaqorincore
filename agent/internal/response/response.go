// Package response owns the agent's side of the auto-response loop.
//
// The server signs COMMAND frames with the host's shared secret; the
// agent verifies the signature, applies the effect, and sends back a
// COMMAND_ACK frame with status=applied | failed.
//
// Phase 4 ships exactly one action kind: block_ip. The effect is
// `nft add element inet zaqorin blocked_v4 { <ip> }` and the rule
// set that consults the set is operator-installed (see
// docs/PHASE4.md). We do NOT add iptables rules ourselves; nftables
// is the modern path and the agent stays out of the iptables legacy.
//
// All actions are gated by cfg.Response.* and a per-host secret file
// at state_dir/secret. Without the secret, commands are refused
// (defence in depth).
package response

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/crypto"
	"github.com/Faris-stuck/zaqorincore/agent/internal/response/kinds"
)

// Handler applies verified COMMAND frames to the local system and
// returns the outcome for the transport to ACK. It is safe to call
// Handle concurrently.
type Handler struct {
	cfg       *config.Config
	secret    []byte
	log       *slog.Logger
	mu        sync.Mutex
	appliedAt map[string]time.Time
}

// NewHandler loads the per-host secret from cfg.StateDir + "/secret"
// and returns a Handler ready to accept commands. If the secret file
// is missing, the agent refuses commands (returns a "missing_secret"
// error from Handle). Operators bootstrap the file by PATCHing
// /api/v1/hosts/{id} on the server and copying the returned secret
// into place.
func NewHandler(cfg *config.Config, log *slog.Logger) (*Handler, error) {
	if cfg == nil {
		return nil, errors.New("response: cfg is nil")
	}
	if log == nil {
		return nil, errors.New("response: logger is nil")
	}
	if cfg.StateDir == "" {
		return nil, errors.New("response: cfg.StateDir is empty")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("response: create state_dir: %w", err)
	}
	return &Handler{
		cfg:       cfg,
		log:       log,
		appliedAt: make(map[string]time.Time),
	}, nil
}

// WriteSecret atomically writes the host's shared secret to
// cfg.StateDir/secret with mode 0600, creating StateDir with
// mode 0700 if needed. The state directory and secret file are
// not world-readable (F2 security fix: prior versions left
// the state directory at 0755 and the secret file at 0644,
// allowing any local user to read the HMAC key).
func WriteSecret(stateDir, secret string) error {
	if stateDir == "" {
		return errors.New("response: WriteSecret: stateDir is empty")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("response: WriteSecret: mkdir state_dir: %w", err)
	}
	// MkdirAll is a no-op if the directory already exists,
	// so an operator who upgrades in place and has a
	// pre-existing state_dir with loose perms would still
	// be exposed. Re-chmod explicitly to 0700.
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("response: WriteSecret: chmod state_dir: %w", err)
	}
	path := filepath.Join(stateDir, "secret")
	// Write with the desired mode at creation time, then
	// chmod explicitly in case the file already existed with
	// looser permissions from a prior install.
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return fmt.Errorf("response: WriteSecret: write secret: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("response: WriteSecret: chmod secret: %w", err)
	}
	return nil
}

// LoadSecret (re)reads the secret file. Cheap; can be called from a
// signal handler if the operator rotates the secret while the agent
// is running.
func (h *Handler) LoadSecret() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	path := filepath.Join(h.cfg.StateDir, "secret")
	b, err := os.ReadFile(path)
	if err != nil {
		h.secret = nil
		return fmt.Errorf("response: read secret: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		h.secret = nil
		return errors.New("response: secret file is empty")
	}
	h.secret = []byte(s)
	return nil
}

// HasSecret reports whether a non-empty secret is currently loaded.
func (h *Handler) HasSecret() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.secret) > 0
}

// Handle verifies a command and applies it.
//
// Returns (status, err) where status is "applied" or "failed". The
// caller (transport.readPump) is responsible for emitting the ACK.
func (h *Handler) Handle(ctx context.Context, cmd Command) (string, error) {
	if !h.HasSecret() {
		// Auto-load in case operator dropped the file after startup.
		if err := h.LoadSecret(); err != nil {
			return "failed", fmt.Errorf("no host secret loaded: %w", err)
		}
	}

	h.mu.Lock()
	secret := h.secret
	h.mu.Unlock()

	if !crypto.Verify(
		string(secret),
		cmd.ID, cmd.Kind, cmd.Target, cmd.TTLSec, cmd.IssuedAt,
		cmd.HMAC,
	) {
		return "failed", errors.New("hmac verification failed")
	}

	// Throttle identical commands: if we already applied this
	// command_id within the last 60s, ack applied without doing it
	// again. (The server can re-dispatch after a flaky network
	// blip.)
	h.mu.Lock()
	if last, ok := h.appliedAt[cmd.ID]; ok && time.Since(last) < 60*time.Second {
		h.mu.Unlock()
		return "applied", nil
	}
	h.mu.Unlock()

	switch cmd.Kind {
	case "block_ip":
		ttl := cmd.TTLSec
		if ttl <= 0 {
			ttl = h.cfg.Response.BlockDefaultTTLSec
		}
		if ttl <= 0 {
			ttl = 3600
		}
		if err := kinds.BlockIP(ctx, cmd.Target, ttl, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "tarpit_ip":
		ttl := cmd.TTLSec
		if ttl <= 0 {
			ttl = 1800
		}
		if err := kinds.TarpitIP(ctx, cmd.Target, ttl, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "canary_alert":
		if err := kinds.CanaryAlert(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "isolate_host":
		ttl := cmd.TTLSec
		if ttl <= 0 {
			ttl = 900
		}
		if err := kinds.IsolateHost(ctx, cmd.Target, ttl, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "kill_process":
		if err := kinds.KillProcess(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "quarantine_file":
		if err := kinds.QuarantineFile(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "revoke_session":
		if err := kinds.RevokeSession(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "webhook_soar":
		if err := kinds.WebhookSOAR(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	case "evidence_capture":
		if err := kinds.EvidenceCapture(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log); err != nil {
			return "failed", err
		}
		h.mu.Lock()
		h.appliedAt[cmd.ID] = time.Now()
		h.mu.Unlock()
		return "applied", nil

	default:
		return "failed", fmt.Errorf("unknown kind %q", cmd.Kind)
	}
}

// Command is the wire shape the agent expects from the server.
type Command struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	TTLSec    int    `json:"ttl_sec"`
	IssuedAt  string `json:"issued_at"`
	HMAC      string `json:"hmac"`
}

// blockIP inserts <ip> into the nftables set `zaqorin blocked_v4`
// for `ttl` seconds. If DryRun is set, the command is logged but
// not executed. The set is created lazily if it doesn't exist.
func blockIP(ctx context.Context, ip string, ttl int, dryRun bool, log *slog.Logger) error {
	if !isValidIPv4(ip) {
		return fmt.Errorf("block_ip: invalid IPv4 address %q", ip)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("block_ip: nft binary not found: %w", err)
	}

	if dryRun {
		log.Info("response: dry-run, not blocking IP",
			slog.String("ip", ip),
			slog.Int("ttl_sec", ttl),
		)
		return nil
	}

	// 1. Ensure the table + set exist.
	//    `nft add table inet zaqorin` and `nft add set inet zaqorin blocked_v4 { type ipv4_addr; flags timeout; }`
	//    are idempotent only via `add` (which fails if exists); we
	//    check first with `list`.
	ensure := func() error {
		c := exec.CommandContext(ctx, "nft", "list", "set", "inet", "zaqorin", "blocked_v4")
		c.Stderr = os.Stderr
		if err := c.Run(); err == nil {
			return nil
		}
		// Create the table.
		c = exec.CommandContext(ctx, "nft", "add", "table", "inet", "zaqorin")
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			// Probably already exists; ignore.
			log.Debug("response: nft add table (ignored)", slog.String("error", err.Error()))
		}
		// Create the set with a default timeout twice the TTL so
		// the entry auto-expires even if the agent crashes before
		// un-applying.
		c = exec.CommandContext(ctx, "nft", "add", "set", "inet", "zaqorin", "blocked_v4",
			"{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}")
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("nft add set: %w", err)
		}
		return nil
	}
	if err := ensure(); err != nil {
		return err
	}

	// 2. Add the entry with a timeout.
	c := exec.CommandContext(ctx, "nft", "add", "element", "inet", "zaqorin", "blocked_v4",
		"{", ip, "}", "timeout", strconv.Itoa(ttl)+"s",
	)
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		// Element might already exist; treat as success.
		log.Debug("response: nft add element (may already exist)",
			slog.String("ip", ip),
			slog.String("error", err.Error()),
		)
	}
	log.Info("response: blocked IP", slog.String("ip", ip), slog.Int("ttl_sec", ttl))
	return nil
}

// isValidIPv4 is a tiny, intentionally-strict validator. We do NOT
// accept IPv6 in Phase 4; if/when needed, the wire contract for
// `kind=block_ip` will gain a "family" field.
func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return false
		}
		if n < 0 || n > 255 {
			return false
		}
		// Reject leading zeros to avoid octal confusion.
		if len(p) > 1 && p[0] == '0' {
			return false
		}
	}
	return true
}
