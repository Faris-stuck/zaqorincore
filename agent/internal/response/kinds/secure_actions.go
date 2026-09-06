package kinds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxWebhookBodyBytes = 1 << 20
	maxWebhookTimeout   = 10 * time.Second
)

// CanaryAlertUnderRoot confines a remotely requested canary path to the
// agent's private state directory. Absolute paths are accepted only when
// they resolve beneath that root; symlink escapes are rejected.
func CanaryAlertUnderRoot(ctx context.Context, target, stateDir string, dryRun bool, log *slog.Logger) error {
	if strings.TrimSpace(stateDir) == "" {
		return errors.New("canary_alert: state directory is empty")
	}
	if strings.TrimSpace(target) == "" {
		return errors.New("canary_alert: path is empty")
	}
	root, err := filepath.Abs(filepath.Join(stateDir, "canaries"))
	if err != nil {
		return fmt.Errorf("canary_alert: resolve root: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("canary_alert: create root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("canary_alert: chmod root: %w", err)
	}

	candidate := target
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return fmt.Errorf("canary_alert: resolve path: %w", err)
	}
	inside, err := filepath.Rel(root, candidate)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
		return fmt.Errorf("canary_alert: path escapes managed canary root")
	}

	parent := filepath.Dir(candidate)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("canary_alert: create parent: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("canary_alert: resolve parent: %w", err)
	}
	resolvedParent, err = filepath.Abs(resolvedParent)
	if err != nil {
		return fmt.Errorf("canary_alert: resolve parent absolute path: %w", err)
	}
	resolvedRoot, _ := filepath.EvalSymlinks(root)
	resolvedRoot, _ = filepath.Abs(resolvedRoot)
	rel, err := filepath.Rel(resolvedRoot, resolvedParent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("canary_alert: parent resolves outside managed canary root")
	}

	if dryRun {
		log.Info("response: dry-run, canary confined", slog.String("path", candidate))
		return nil
	}
	f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("canary_alert: create marker: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString("zaqorin-canary\n"); err != nil {
		return fmt.Errorf("canary_alert: write marker: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("canary_alert: sync marker: %w", err)
	}
	log.Info("response: canary placed", slog.String("path", candidate))
	return nil
}

// RevokeSessionState persists a local revocation record. It deliberately does
// not claim to terminate a remote authentication session by itself; consumers
// of the denylist can enforce the revocation at the local auth boundary.
func RevokeSessionState(_ context.Context, sessionID, stateDir string, dryRun bool, log *slog.Logger) error {
	id := strings.TrimSpace(sessionID)
	if id == "" {
		return errors.New("revoke_session: empty session id")
	}
	if len(id) > 256 || strings.ContainsAny(id, "/\\\x00\r\n") {
		return errors.New("revoke_session: invalid session id")
	}
	if strings.TrimSpace(stateDir) == "" {
		return errors.New("revoke_session: state directory is empty")
	}
	path := filepath.Join(stateDir, "revoked_sessions")
	if dryRun {
		log.Info("response: dry-run, session revocation not persisted", slog.String("session", id))
		return nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("revoke_session: create state dir: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return fmt.Errorf("revoke_session: chmod state dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("revoke_session: open denylist: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(id + "\n"); err != nil {
		return fmt.Errorf("revoke_session: write denylist: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("revoke_session: sync denylist: %w", err)
	}
	log.Info("response: session revocation recorded", slog.String("session", id))
	return nil
}

func WebhookSOARStrict(ctx context.Context, rawURL string, dryRun bool, log *slog.Logger) error {
	u, err := url.ParseRequestURI(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("webhook_soar: invalid URL")
	}
	if u.User != nil {
		return errors.New("webhook_soar: URL userinfo is forbidden")
	}
	if u.Scheme != "https" {
		return errors.New("webhook_soar: only https URLs are allowed")
	}
	if !webhookHostAllowed(u.Hostname()) {
		return errors.New("webhook_soar: destination is not in the local SOAR allowlist")
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("webhook_soar: DNS resolution failed")
	}
	for _, ip := range ips {
		if !isPublicWebhookIP(ip) {
			return fmt.Errorf("webhook_soar: destination resolves to a non-public address")
		}
	}
	if dryRun {
		log.Info("response: dry-run, webhook allowed by policy", slog.String("host", strings.ToLower(u.Hostname())))
		return nil
	}

	timeout := maxWebhookTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body := strings.NewReader(`{"source":"zaqorincore","action":"webhook_soar"}`)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, u.String(), body)
	if err != nil {
		return fmt.Errorf("webhook_soar: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Pin the connection to the already-validated public addresses, which
	// prevents a DNS answer from changing between validation and connect.
	transport.DialContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
		var lastErr error
		for _, ip := range ips {
			d := net.Dialer{Timeout: 5 * time.Second}
			conn, dialErr := d.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), "443"))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
	client := &http.Client{
		Transport: transport,
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook_soar: request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, maxWebhookBodyBytes+1)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook_soar: remote returned HTTP %d", resp.StatusCode)
	}
	log.Info("response: SOAR webhook delivered", slog.String("host", strings.ToLower(u.Hostname())))
	return nil
}

func webhookHostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	// Fail closed. Operators explicitly name the exact SOAR hosts the agent
	// is permitted to reach: ZAQORIN_SOAR_ALLOWLIST="soar.example.com,siem.example.com".
	for _, item := range strings.Split(os.Getenv("ZAQORIN_SOAR_ALLOWLIST"), ",") {
		if strings.EqualFold(strings.TrimSpace(item), host) && host != "" {
			return true
		}
	}
	return false
}

func isPublicWebhookIP(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() && !ip.IsUnspecified() && !ip.IsUnspecified()
}
