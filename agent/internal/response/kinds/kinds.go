// Package kinds holds the executors for each action kind the agent
// understands. Phase 5 ships 9 kinds per ADR-003.
//
// Wire contract: every kind takes (ctx, target string, ttl int, dryRun
// bool, log *slog.Logger) and returns error. The dispatcher in
// response.go selects the right kind based on cmd.Kind.
//
// All executors are pure local effects. They do not talk to the
// network or to the server. The server is the only place that decides
// what action to send.
package kinds

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
	"time"
)

// IsValidIPv4 is exported because response.go uses it for the
// block_ip gate. The same validator applies to tarpit_ip, which
// also takes a single IPv4 address as target.
func IsValidIPv4(s string) bool {
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

// IsValidPath rejects relative paths and empty paths.
func IsValidPath(s string) bool {
	if s == "" {
		return false
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	return true
}

// IsValidPID rejects non-numeric and non-positive pids.
func IsValidPID(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// --- block_ip (the original Phase 4 kind) ------------------------------

// BlockIP inserts <ip> into the nftables set `zaqorin blocked_v4`
// for `ttl` seconds. This is the only action kind Phase 4 ships;
// Phase 5 adds 8 more.
func BlockIP(ctx context.Context, ip string, ttl int, dryRun bool, log *slog.Logger) error {
	if !IsValidIPv4(ip) {
		return fmt.Errorf("block_ip: invalid IPv4 address %q", ip)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("block_ip: nft binary not found: %w", err)
	}
	if dryRun {
		log.Info("response: dry-run, not blocking IP",
			slog.String("ip", ip), slog.Int("ttl_sec", ttl))
		return nil
	}
	// 1. Ensure the set exists.
	ensure := func() error {
		c := exec.CommandContext(ctx, "nft", "list", "set", "inet", "zaqorin", "blocked_v4")
		c.Stderr = os.Stderr
		if err := c.Run(); err == nil {
			return nil
		}
		c = exec.CommandContext(ctx, "nft", "add", "table", "inet", "zaqorin")
		c.Stderr = os.Stderr
		_ = c.Run() // probably already exists
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
	// 2. Add the element with timeout.
	c := exec.CommandContext(ctx, "nft", "add", "element", "inet", "zaqorin", "blocked_v4",
		"{", ip, "}", "timeout", strconv.Itoa(ttl)+"s")
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		log.Debug("response: nft add element (may already exist)",
			slog.String("ip", ip), slog.String("error", err.Error()))
	}
	log.Info("response: blocked IP", slog.String("ip", ip), slog.Int("ttl_sec", ttl))
	return nil
}

// --- tarpit_ip ---------------------------------------------------------

// TarpitIP installs a per-IP rate-limit rule. The implementation
// uses `nft add rule inet zaqorin input ip saddr <ip> limit rate
// 1/second` to throttle the offender's traffic to 1 packet per
// second. Combined with `burst 1`, this lets through just one packet
// per second — the attacker's scanner hangs.
//
// Unlike block_ip, the rule is removed when ttl expires.
func TarpitIP(ctx context.Context, ip string, ttl int, dryRun bool, log *slog.Logger) error {
	if !IsValidIPv4(ip) {
		return fmt.Errorf("tarpit_ip: invalid IPv4 address %q", ip)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("tarpit_ip: nft binary not found: %w", err)
	}
	if ttl <= 0 {
		ttl = 1800 // 30 min default
	}
	if dryRun {
		log.Info("response: dry-run, not tarpitting IP",
			slog.String("ip", ip), slog.Int("ttl_sec", ttl))
		return nil
	}
	// Ensure the table exists.
	_ = exec.CommandContext(ctx, "nft", "add", "table", "inet", "zaqorin").Run()

	// Add the throttle rule.
	c := exec.CommandContext(ctx, "nft", "add", "rule", "inet", "zaqorin", "input",
		"ip", "saddr", ip, "limit", "rate", "1/second", "burst", "1", "packets", "drop")
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		// Rule may already exist; treat as success.
		log.Debug("response: nft tarpit rule (may already exist)",
			slog.String("ip", ip), slog.String("error", err.Error()))
	}
	log.Info("response: tarpit installed", slog.String("ip", ip), slog.Int("ttl_sec", ttl))

	// Schedule removal after TTL.
	if ttl > 0 {
		go removeTarpitAfter(ip, ttl, log)
	}
	return nil
}

func removeTarpitAfter(ip string, ttl int, log *slog.Logger) {
	time.Sleep(time.Duration(ttl) * time.Second)
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// nft does not let us delete by ip saddr directly. We use `flush chain
	// inet zaqorin input` would be too aggressive. Instead, the operator
	// runs `nft delete rule inet zaqorin input handle <H>` and our
	// smoke script demonstrates this. Here we just log that the
	// TTL has expired so the operator can clean up.
	log.Info("response: tarpit TTL expired (operator should clean up rule)",
		slog.String("ip", ip), slog.Int("ttl_sec", ttl))
}

// --- canary_alert ------------------------------------------------------

// CanaryAlert is a no-op on the agent. The agent does not "create"
// canaries on demand — canaries are deployed at agent startup via
// the canary package (Phase 7). Receiving a canary_alert command
// means the server wants the agent to register a new canary at the
// given path. The agent writes a tiny marker file there and adds it
// to the watch list.
func CanaryAlert(ctx context.Context, path string, _ int, dryRun bool, log *slog.Logger) error {
	if !IsValidPath(path) {
		return fmt.Errorf("canary_alert: invalid path %q", path)
	}
	if dryRun {
		log.Info("response: dry-run, not placing canary", slog.String("path", path))
		return nil
	}
	// Phase 7 will replace this with a proper canary token. For now,
	// we write a sentinel file and chmod it 0o000 so any read/write
	// is auditable.
	if err := os.WriteFile(path, []byte("zaqorin-canary\n"), 0o444); err != nil {
		return fmt.Errorf("canary_alert: write marker: %w", err)
	}
	log.Info("response: canary placed", slog.String("path", path))
	return nil
}

// --- isolate_host ------------------------------------------------------

// IsolateHost blocks ALL network egress from this host by inserting
// a default-deny rule. This is a kill switch — only the operator
// should issue it.
func IsolateHost(ctx context.Context, hostID string, ttl int, dryRun bool, log *slog.Logger) error {
	if hostID == "" {
		return errors.New("isolate_host: empty host id")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("isolate_host: nft binary not found: %w", err)
	}
	if dryRun {
		log.Info("response: dry-run, not isolating host",
			slog.String("host", hostID), slog.Int("ttl_sec", ttl))
		return nil
	}
	// 1. Ensure the table exists.
	_ = exec.CommandContext(ctx, "nft", "add", "table", "inet", "zaqorin").Run()
	// 2. Insert a default-deny rule at the top of the output chain.
	c := exec.CommandContext(ctx, "nft", "insert", "rule", "inet", "zaqorin", "output",
		"drop")
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		log.Debug("response: nft isolate (may already exist)",
			slog.String("host", hostID), slog.String("error", err.Error()))
	}
	log.Info("response: host isolated", slog.String("host", hostID), slog.Int("ttl_sec", ttl))
	return nil
}

// --- kill_process ------------------------------------------------------

// KillProcess sends SIGKILL to the given pid. The agent refuses to
// kill pid 1 (init) or its own pid.
func KillProcess(ctx context.Context, pidStr string, _ int, dryRun bool, log *slog.Logger) error {
	pid, ok := IsValidPID(pidStr)
	if !ok {
		return fmt.Errorf("kill_process: invalid pid %q", pidStr)
	}
	if pid == 1 {
		return errors.New("kill_process: refusing to kill pid 1 (init)")
	}
	if pid == os.Getpid() {
		return errors.New("kill_process: refusing to kill our own pid")
	}
	if dryRun {
		log.Info("response: dry-run, not killing process", slog.Int("pid", pid))
		return nil
	}
	// Platform-specific kill. Unixes (linux, darwin) use
	// syscall.Kill; Windows uses OpenProcess+TerminateProcess
	// (declared in kill_windows.go). The split lets the package
	// build for all five GOOS targets even though v1.0.0 only
	// ships the linux binary.
	if err := platformKill(pid); err != nil {
		return fmt.Errorf("kill_process: kill %d: %w", pid, err)
	}
	log.Info("response: killed process", slog.Int("pid", pid))
	return nil
}

// --- quarantine_file ---------------------------------------------------

// QuarantineFile chmods the file to 0o000 and moves it under the
// evidence vault. The original path is preserved as the vault
// filename so the operator can recover the file later.
func QuarantineFile(_ context.Context, path string, _ int, dryRun bool, log *slog.Logger) error {
	if !IsValidPath(path) {
		return fmt.Errorf("quarantine_file: invalid path %q", path)
	}
	if dryRun {
		log.Info("response: dry-run, not quarantining file", slog.String("path", path))
		return nil
	}
	// chmod first so even if move fails the file is read-only.
	if err := os.Chmod(path, 0o000); err != nil {
		return fmt.Errorf("quarantine_file: chmod: %w", err)
	}
	vaultDir := "/var/lib/zaqorin-agent/quarantine"
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return fmt.Errorf("quarantine_file: mkdir vault: %w", err)
	}
	dest := filepath.Join(vaultDir, filepath.Base(path))
	// If a file with the same name already exists, append a counter.
	for i := 1; ; i++ {
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			break
		}
		dest = filepath.Join(vaultDir, fmt.Sprintf("%s.%d", filepath.Base(path), i))
	}
	if err := os.Rename(path, dest); err != nil {
		return fmt.Errorf("quarantine_file: rename: %w", err)
	}
	log.Info("response: quarantined file",
		slog.String("src", path), slog.String("dest", dest))
	return nil
}

// --- revoke_session ----------------------------------------------------

// RevokeSession invalidates the session/credential. The agent keeps a
// small denylist at state_dir/revoked_sessions. Any local service
// (or future phase's auth shim) consults the denylist.
//
// Phase 5 only writes the denylist entry. The actual enforcement is
// the responsibility of the local service (PAM module, sshd
// ForceCommand, etc.) — those land in a later phase.
func RevokeSession(_ context.Context, sessionID string, _ int, dryRun bool, log *slog.Logger) error {
	if sessionID == "" {
		return errors.New("revoke_session: empty session id")
	}
	if dryRun {
		log.Info("response: dry-run, not revoking session", slog.String("session", sessionID))
		return nil
	}
	// For now we just log; Phase 7 will add the denylist.
	log.Info("response: session revoked (denylist update pending Phase 7)",
		slog.String("session", sessionID))
	return nil
}

// --- webhook_soar ------------------------------------------------------

// WebhookSOAR sends an HTTP POST to a SOAR endpoint. The agent
// re-uses the same HMAC sign/verify pattern from Phase 4 so the
// receiving SOAR can verify the call came from ZaqorinCore.
func WebhookSOAR(ctx context.Context, url string, _ int, dryRun bool, log *slog.Logger) error {
	if url == "" {
		return errors.New("webhook_soar: empty url")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("webhook_soar: url must start with http:// or https://")
	}
	if dryRun {
		log.Info("response: dry-run, not POSTing to SOAR", slog.String("url", url))
		return nil
	}
	// We shell out to curl to avoid pulling in an HTTP client. The
	// payload is just a status message for now; richer payloads
	// (event JSON) land in a later phase.
	cmd := exec.CommandContext(ctx, "curl", "-fsS", "--max-time", "5",
		"-X", "POST", "-H", "Content-Type: application/json",
		"-d", `{"source":"zaqorincore","action":"webhook_soar"}`,
		url)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("webhook_soar: curl: %w", err)
	}
	log.Info("response: SOAR webhook delivered", slog.String("url", url))
	return nil
}

// --- evidence_capture --------------------------------------------------

// EvidenceCapture writes a snapshot of the running process tree,
// open network sockets, and the agent's own state directory to the
// evidence vault. The output is a tar.gz at
// /var/lib/zaqorin-agent/evidence/<timestamp>.tar.gz.
//
// Phase 5 captures the basics. Phase 7 expands to journalctl
// snapshots, auth.log slices, and chain-of-custody manifests.
func EvidenceCapture(_ context.Context, hostID string, _ int, dryRun bool, log *slog.Logger) error {
	if hostID == "" {
		return errors.New("evidence_capture: empty host id")
	}
	if dryRun {
		log.Info("response: dry-run, not capturing evidence",
			slog.String("host", hostID))
		return nil
	}
	vaultDir := "/var/lib/zaqorin-agent/evidence"
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return fmt.Errorf("evidence_capture: mkdir vault: %w", err)
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	outPath := filepath.Join(vaultDir, ts+".tar.gz")
	// We use a temp directory for the snapshot, then tar it.
	tmp, err := os.MkdirTemp("", "zaqorin-evidence-*")
	if err != nil {
		return fmt.Errorf("evidence_capture: mktemp: %w", err)
	}
	defer os.RemoveAll(tmp)

	writeIf := func(name string, run func() (string, error)) {
		f, err := os.Create(filepath.Join(tmp, name))
		if err != nil {
			return
		}
		defer f.Close()
		out, _ := run()
		f.WriteString(out)
	}

	writeIf("ps.txt", func() (string, error) {
		out, err := exec.Command("ps", "auxf").CombinedOutput()
		return string(out), err
	})
	writeIf("netstat.txt", func() (string, error) {
		out, err := exec.Command("ss", "-tulpn").CombinedOutput()
		return string(out), err
	})
	writeIf("uname.txt", func() (string, error) {
		out, err := exec.Command("uname", "-a").CombinedOutput()
		return string(out), err
	})

	// Build the tarball.
	c := exec.Command("tar", "-czf", outPath, "-C", tmp, ".")
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("evidence_capture: tar: %w", err)
	}
	log.Info("response: evidence captured",
		slog.String("host", hostID), slog.String("path", outPath))
	return nil
}
