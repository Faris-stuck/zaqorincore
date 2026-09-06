package response_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/crypto"
	"github.com/Faris-stuck/zaqorincore/agent/internal/response"
)

func newTestHandler(t *testing.T) (*response.Handler, *config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{StateDir: dir, DryRun: true, Response: config.Response{AllowBlockIP: true, BlockDefaultTTLSec: 60}}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h, err := response.NewHandler(cfg, log)
	if err != nil { t.Fatalf("NewHandler: %v", err) }
	return h, cfg, dir
}

func freshIssuedAt() string { return time.Now().UTC().Format(time.RFC3339) }

func TestHandlerRejectsWithoutSecret(t *testing.T) {
	h, _, _ := newTestHandler(t)
	status, err := h.Handle(context.Background(), response.Command{ID: "x", Kind: "block_ip", Target: "1.2.3.4"})
	if err == nil || !strings.Contains(err.Error(), "no host secret") { t.Fatalf("expected missing-secret error, got status=%q err=%v", status, err) }
}

func TestHandlerAcceptsValidSignatureAndReturnsApplied(t *testing.T) {
	h, _, dir := newTestHandler(t)
	secret := "alpha-bravo-charlie-1234"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil { t.Fatal(err) }
	if err := h.LoadSecret(); err != nil { t.Fatal(err) }
	issuedAt := freshIssuedAt()
	sig := crypto.Sign(secret, "cmd-1", "block_ip", "203.0.113.42", 60, issuedAt)
	status, err := h.Handle(context.Background(), response.Command{ID: "cmd-1", Kind: "block_ip", Target: "203.0.113.42", TTLSec: 60, IssuedAt: issuedAt, HMAC: sig})
	if err != nil { t.Fatalf("Handle: %v", err) }
	if status != "applied" { t.Fatalf("status=%q, want applied", status) }
}

func TestHandlerRejectsBadSignature(t *testing.T) {
	h, _, dir := newTestHandler(t)
	secret := "real-secret"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil { t.Fatal(err) }
	if err := h.LoadSecret(); err != nil { t.Fatal(err) }
	status, err := h.Handle(context.Background(), response.Command{ID: "x", Kind: "block_ip", Target: "1.2.3.4", IssuedAt: freshIssuedAt(), HMAC: strings.Repeat("0", 64)})
	if err == nil || status != "failed" { t.Fatalf("expected failed, got status=%q err=%v", status, err) }
}

func TestHandlerRejectsInvalidIPv4(t *testing.T) {
	h, _, dir := newTestHandler(t)
	secret := "k"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil { t.Fatal(err) }
	_ = h.LoadSecret()
	for _, bad := range []string{"1.2.3", "1.2.3.4.5", "abc", "1.2.3.256", "1.2.3.04", "::1"} {
		issuedAt := freshIssuedAt()
		sig := crypto.Sign(secret, "x", "block_ip", bad, 60, issuedAt)
		_, err := h.Handle(context.Background(), response.Command{ID: "x", Kind: "block_ip", Target: bad, IssuedAt: issuedAt, HMAC: sig})
		if err == nil { t.Fatalf("expected error for %q", bad) }
	}
}

func TestHandlerThrottlesDuplicateCommand(t *testing.T) {
	h, _, dir := newTestHandler(t)
	secret := "k"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil { t.Fatal(err) }
	_ = h.LoadSecret()
	issuedAt := freshIssuedAt()
	sig := crypto.Sign(secret, "cmd-dup", "block_ip", "1.2.3.4", 60, issuedAt)
	cmd := response.Command{ID: "cmd-dup", Kind: "block_ip", Target: "1.2.3.4", IssuedAt: issuedAt, HMAC: sig, TTLSec: 60}
	if s, err := h.Handle(context.Background(), cmd); err != nil || s != "applied" { t.Fatalf("first call: status=%q err=%v", s, err) }
	if s, err := h.Handle(context.Background(), cmd); err != nil || s != "applied" { t.Fatalf("second call: status=%q err=%v", s, err) }
}

func TestHandlerRejectsUnknownKind(t *testing.T) {
	h, _, dir := newTestHandler(t)
	secret := "k"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil { t.Fatal(err) }
	_ = h.LoadSecret()
	issuedAt := freshIssuedAt()
	sig := crypto.Sign(secret, "x", "drop_table", "main", 60, issuedAt)
	status, err := h.Handle(context.Background(), response.Command{ID: "x", Kind: "drop_table", Target: "main", IssuedAt: issuedAt, HMAC: sig})
	if err == nil || status != "failed" { t.Fatalf("expected failed, got status=%q err=%v", status, err) }
}

func TestHandlerRejectsExpiredAndFutureCommands(t *testing.T) {
	h, _, dir := newTestHandler(t)
	secret := "k"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil { t.Fatal(err) }
	_ = h.LoadSecret()
	for _, issuedAt := range []string{
		time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339),
		time.Now().UTC().Add(6 * time.Minute).Format(time.RFC3339),
	} {
		sig := crypto.Sign(secret, "x", "block_ip", "1.2.3.4", 60, issuedAt)
		status, err := h.Handle(context.Background(), response.Command{ID: "x", Kind: "block_ip", Target: "1.2.3.4", TTLSec: 60, IssuedAt: issuedAt, HMAC: sig})
		if err == nil || status != "failed" { t.Fatalf("expected stale/future command to fail, got status=%q err=%v", status, err) }
	}
}

func TestLoadSecretFileMissing(t *testing.T) {
	h, _, _ := newTestHandler(t)
	if err := h.LoadSecret(); err == nil { t.Fatal("expected error from missing secret file") }
}

func TestHasSecretReflectsLoad(t *testing.T) {
	h, _, dir := newTestHandler(t)
	if h.HasSecret() { t.Fatal("HasSecret should be false before LoadSecret") }
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("abc"), 0o600); err != nil { t.Fatal(err) }
	if err := h.LoadSecret(); err != nil { t.Fatal(err) }
	if !h.HasSecret() { t.Fatal("HasSecret should be true after successful LoadSecret") }
}

func TestHandlerDefaultTTLWhenZero(t *testing.T) {
	h, _, dir := newTestHandler(t)
	secret := "k"
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secret), 0o600); err != nil { t.Fatal(err) }
	_ = h.LoadSecret()
	issuedAt := freshIssuedAt()
	sig := crypto.Sign(secret, "x", "block_ip", "1.2.3.4", 0, issuedAt)
	if s, err := h.Handle(context.Background(), response.Command{ID: "x", Kind: "block_ip", Target: "1.2.3.4", IssuedAt: issuedAt, HMAC: sig}); err != nil || s != "applied" { t.Fatalf("status=%q err=%v", s, err) }
}

func TestWriteSecretEnforcesTightPerms(t *testing.T) {
	parent := t.TempDir(); dir := filepath.Join(parent, "state")
	if err := os.MkdirAll(dir, 0o755); err != nil { t.Fatal(err) }
	preExisting := filepath.Join(dir, "secret")
	if err := os.WriteFile(preExisting, []byte("old\n"), 0o644); err != nil { t.Fatal(err) }
	if err := response.WriteSecret(dir, "supersecret-value"); err != nil { t.Fatalf("WriteSecret: %v", err) }
	st, err := os.Stat(dir); if err != nil { t.Fatal(err) }
	if got := st.Mode().Perm(); got != 0o700 { t.Errorf("state_dir mode = %o, want 0o700", got) }
	path := filepath.Join(dir, "secret")
	fst, err := os.Stat(path); if err != nil { t.Fatal(err) }
	if got := fst.Mode().Perm(); got != 0o600 { t.Errorf("secret file mode = %o, want 0o600", got) }
	b, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	if string(b) != "supersecret-value\n" { t.Errorf("secret file content = %q", string(b)) }
}

func TestWriteSecretRejectsEmptyStateDir(t *testing.T) {
	if err := response.WriteSecret("", "x"); err == nil { t.Fatal("expected error for empty stateDir") }
}
