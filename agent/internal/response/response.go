package response

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/crypto"
	"github.com/Faris-stuck/zaqorincore/agent/internal/response/kinds"
)

const maxCommandClockSkew = 5 * time.Minute
const maxAppliedCommandIDs = 10_000

type Handler struct {
	cfg       *config.Config
	secret    []byte
	log       *slog.Logger
	mu        sync.Mutex
	appliedAt map[string]time.Time
	inFlight  map[string]struct{}
}

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
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("response: chmod state_dir: %w", err)
	}
	return &Handler{
		cfg:       cfg,
		log:       log,
		appliedAt: make(map[string]time.Time),
		inFlight:  make(map[string]struct{}),
	}, nil
}

func WriteSecret(stateDir, secret string) error {
	if stateDir == "" {
		return errors.New("response: WriteSecret: stateDir is empty")
	}
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return errors.New("response: WriteSecret: secret is empty")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("response: WriteSecret: mkdir state_dir: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("response: WriteSecret: chmod state_dir: %w", err)
	}
	path := filepath.Join(stateDir, "secret")
	tmp, err := os.CreateTemp(stateDir, ".secret-*")
	if err != nil {
		return fmt.Errorf("response: WriteSecret: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("response: WriteSecret: chmod temp: %w", err)
	}
	if _, err := tmp.WriteString(secret + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("response: WriteSecret: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("response: WriteSecret: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("response: WriteSecret: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("response: WriteSecret: replace secret: %w", err)
	}
	return os.Chmod(path, 0o600)
}

func (h *Handler) LoadSecret() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(h.cfg.StateDir, "secret"))
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

func (h *Handler) HasSecret() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.secret) > 0
}

func (h *Handler) commandAllowed(kind string) bool {
	switch kind {
	case "block_ip":
		return h.cfg.Response.AllowBlockIP
	case "tarpit_ip":
		return h.cfg.Response.AllowTarpitIP
	case "kill_process":
		return h.cfg.Response.AllowKillProcess
	case "canary_alert":
		return h.cfg.Response.AllowCanaryAlert
	case "isolate_host":
		return h.cfg.Response.AllowIsolateHost
	case "quarantine_file":
		return h.cfg.Response.AllowQuarantineFile
	case "revoke_session":
		return h.cfg.Response.AllowRevokeSession
	case "webhook_soar":
		return h.cfg.Response.AllowWebhookSOAR
	case "evidence_capture":
		return h.cfg.Response.AllowEvidenceCapture
	default:
		return false
	}
}

func (h *Handler) reserveCommand(commandID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.appliedAt[commandID]; ok {
		return true
	}
	if _, ok := h.inFlight[commandID]; ok {
		return true
	}
	h.inFlight[commandID] = struct{}{}
	return false
}

func (h *Handler) releaseCommand(commandID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.inFlight, commandID)
}

func (h *Handler) rememberApplied(commandID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.appliedAt) >= maxAppliedCommandIDs {
		var oldestID string
		var oldest time.Time
		for id, at := range h.appliedAt {
			if oldestID == "" || at.Before(oldest) {
				oldestID, oldest = id, at
			}
		}
		if oldestID != "" {
			delete(h.appliedAt, oldestID)
		}
	}
	h.appliedAt[commandID] = time.Now().UTC()
}

func (h *Handler) Handle(ctx context.Context, cmd Command) (string, error) {
	if !h.HasSecret() {
		if err := h.LoadSecret(); err != nil {
			return "failed", fmt.Errorf("no host secret loaded: %w", err)
		}
	}
	h.mu.Lock()
	secret := append([]byte(nil), h.secret...)
	h.mu.Unlock()

	if strings.TrimSpace(cmd.ID) == "" || strings.TrimSpace(cmd.Kind) == "" {
		return "failed", errors.New("command id and kind are required")
	}
	issued, err := time.Parse(time.RFC3339, cmd.IssuedAt)
	if err != nil {
		return "failed", fmt.Errorf("invalid issued_at: %w", err)
	}
	now := time.Now().UTC()
	if issued.Before(now.Add(-maxCommandClockSkew)) || issued.After(now.Add(maxCommandClockSkew)) {
		return "failed", errors.New("command expired or issued too far in the future")
	}
	if !crypto.Verify(string(secret), cmd.ID, cmd.Kind, cmd.Target, cmd.TTLSec, cmd.IssuedAt, cmd.HMAC) {
		return "failed", errors.New("hmac verification failed")
	}
	if !h.commandAllowed(cmd.Kind) {
		return "failed", fmt.Errorf("action kind %q is disabled by local policy", cmd.Kind)
	}
	if h.reserveCommand(cmd.ID) {
		return "applied", nil
	}
	defer h.releaseCommand(cmd.ID)

	var applyErr error
	switch cmd.Kind {
	case "block_ip":
		ttl := cmd.TTLSec
		if ttl <= 0 {
			ttl = h.cfg.Response.BlockDefaultTTLSec
		}
		if ttl <= 0 {
			ttl = 3600
		}
		applyErr = kinds.BlockIP(ctx, cmd.Target, ttl, h.cfg.DryRun, h.log)
	case "tarpit_ip":
		ttl := cmd.TTLSec
		if ttl <= 0 {
			ttl = 1800
		}
		applyErr = kinds.TarpitIPWithTTL(ctx, cmd.Target, ttl, h.cfg.DryRun, h.log)
	case "canary_alert":
		applyErr = kinds.CanaryAlertUnderRoot(ctx, cmd.Target, h.cfg.StateDir, h.cfg.DryRun, h.log)
	case "isolate_host":
		ttl := cmd.TTLSec
		if ttl <= 0 {
			ttl = 900
		}
		applyErr = kinds.IsolateHostWithTTL(ctx, cmd.Target, ttl, h.cfg.DryRun, h.log)
	case "kill_process":
		applyErr = kinds.KillProcess(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log)
	case "quarantine_file":
		applyErr = kinds.QuarantineFile(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log)
	case "revoke_session":
		applyErr = kinds.RevokeSessionState(ctx, cmd.Target, h.cfg.StateDir, h.cfg.DryRun, h.log)
	case "webhook_soar":
		applyErr = kinds.WebhookSOARStrict(ctx, cmd.Target, h.cfg.DryRun, h.log)
	case "evidence_capture":
		applyErr = kinds.EvidenceCapture(ctx, cmd.Target, cmd.TTLSec, h.cfg.DryRun, h.log)
	default:
		applyErr = fmt.Errorf("unknown kind %q", cmd.Kind)
	}
	if applyErr != nil {
		return "failed", applyErr
	}
	h.rememberApplied(cmd.ID)
	return "applied", nil
}

type Command struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	TTLSec   int    `json:"ttl_sec"`
	IssuedAt string `json:"issued_at"`
	HMAC     string `json:"hmac"`
}
