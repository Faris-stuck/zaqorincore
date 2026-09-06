package kinds

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

const maxContainmentTTLSeconds = 30 * 24 * 60 * 60

func TarpitIPWithTTL(ctx context.Context, ip string, ttl int, dryRun bool, log *slog.Logger) error {
	if !IsValidIPv4(ip) {
		return fmt.Errorf("tarpit_ip: invalid IPv4 address %q", ip)
	}
	if ttl <= 0 || ttl > maxContainmentTTLSeconds {
		return fmt.Errorf("tarpit_ip: ttl must be between 1 and %d seconds", maxContainmentTTLSeconds)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("tarpit_ip: nft binary not found: %w", err)
	}
	if dryRun {
		log.Info("response: dry-run, not tarpitting IP", slog.String("ip", ip), slog.Int("ttl_sec", ttl))
		return nil
	}
	if err := exec.CommandContext(ctx, "nft", "add", "table", "inet", "zaqorin").Run(); err != nil {
		log.Debug("response: nft table already present", slog.String("error", err.Error()))
	}
	comment := "zaqorin-tarpit-" + safeComment(ip)
	cmd := exec.CommandContext(ctx, "nft", "insert", "rule", "inet", "zaqorin", "input",
		"ip", "saddr", ip, "limit", "rate", "1/second", "burst", "1", "packets", "drop",
		"comment", comment)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tarpit_ip: nft insert rule: %w: %s", err, strings.TrimSpace(string(output)))
	}
	log.Info("response: tarpit installed", slog.String("ip", ip), slog.Int("ttl_sec", ttl))
	go removeRuleAfter("input", comment, ttl, log)
	return nil
}

func IsolateHostWithTTL(ctx context.Context, hostID string, ttl int, dryRun bool, log *slog.Logger) error {
	if strings.TrimSpace(hostID) == "" {
		return fmt.Errorf("isolate_host: empty host id")
	}
	if ttl <= 0 || ttl > maxContainmentTTLSeconds {
		return fmt.Errorf("isolate_host: ttl must be between 1 and %d seconds", maxContainmentTTLSeconds)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("isolate_host: nft binary not found: %w", err)
	}
	if dryRun {
		log.Info("response: dry-run, not isolating host", slog.String("host", hostID), slog.Int("ttl_sec", ttl))
		return nil
	}
	if err := exec.CommandContext(ctx, "nft", "add", "table", "inet", "zaqorin").Run(); err != nil {
		log.Debug("response: nft table already present", slog.String("error", err.Error()))
	}
	comment := "zaqorin-isolate-" + safeComment(hostID)
	cmd := exec.CommandContext(ctx, "nft", "insert", "rule", "inet", "zaqorin", "output", "counter", "drop", "comment", comment)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("isolate_host: nft insert rule: %w: %s", err, strings.TrimSpace(string(output)))
	}
	log.Info("response: host isolated", slog.String("host", hostID), slog.Int("ttl_sec", ttl))
	go removeRuleAfter("output", comment, ttl, log)
	return nil
}

func safeComment(s string) string {
	s = strings.NewReplacer("\n", "_", "\r", "_", "\"", "_", "'", "_").Replace(s)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func removeRuleAfter(chain, comment string, ttl int, log *slog.Logger) {
	timer := time.NewTimer(time.Duration(ttl) * time.Second)
	defer timer.Stop()
	<-timer.C
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", "zaqorin", chain).CombinedOutput()
	if err != nil {
		log.Warn("response: failed to inspect TTL rule", slog.String("chain", chain), slog.String("error", err.Error()))
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, comment) {
			continue
		}
		idx := strings.LastIndex(line, " # handle ")
		if idx < 0 {
			continue
		}
		handle := strings.TrimSpace(line[idx+len(" # handle "):])
		if handle == "" {
			continue
		}
		if err := exec.CommandContext(ctx, "nft", "delete", "rule", "inet", "zaqorin", chain, "handle", handle).Run(); err != nil {
			log.Warn("response: failed to remove TTL rule", slog.String("chain", chain), slog.String("handle", handle), slog.String("error", err.Error()))
			return
		}
		log.Info("response: containment TTL expired", slog.String("chain", chain), slog.String("rule_comment", comment))
		return
	}
	log.Warn("response: TTL rule not found at expiry", slog.String("chain", chain), slog.String("rule_comment", comment))
}
