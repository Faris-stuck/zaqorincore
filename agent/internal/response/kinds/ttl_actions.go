package kinds

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
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
	for _, args := range [][]string{
		{"add", "table", "inet", "zaqorin"},
		{"add", "set", "inet", "zaqorin", "tarpit_v4", "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"},
	} {
		if err := exec.CommandContext(ctx, "nft", args...).Run(); err != nil {
			log.Debug("response: nft setup already present", slog.String("error", err.Error()))
		}
	}
	cmd := exec.CommandContext(ctx, "nft", "add", "element", "inet", "zaqorin", "tarpit_v4", "{", ip, "timeout", strconv.Itoa(ttl)+"s", "}")
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("tarpit_ip: nft add element: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	log.Info("response: tarpit installed", slog.String("ip", ip), slog.Int("ttl_sec", ttl))
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
	go removeRuleAfter(comment, ttl, log)
	return nil
}

func safeComment(s string) string {
	s = strings.ReplaceAll(s, "\n", "_")
	s = strings.ReplaceAll(s, "\r", "_")
	if len(s) > 80 { s = s[:80] }
	return s
}

func removeRuleAfter(comment string, ttl int, log *slog.Logger) {
	timer := time.NewTimer(time.Duration(ttl) * time.Second)
	defer timer.Stop()
	<-timer.C
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", "zaqorin", "output").CombinedOutput()
	if err != nil { log.Warn("response: failed to inspect isolate rule", slog.String("error", err.Error())); return }
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if !strings.Contains(line, comment) { continue }
		idx := strings.LastIndex(line, " # handle ")
		if idx < 0 { continue }
		handle := strings.TrimSpace(line[idx+len(" # handle "):])
		if handle == "" { continue }
		if err := exec.CommandContext(ctx, "nft", "delete", "rule", "inet", "zaqorin", "output", "handle", handle).Run(); err != nil {
			log.Warn("response: failed to remove isolate rule", slog.String("error", err.Error()), slog.String("handle", handle))
			return
		}
		log.Info("response: host isolation TTL expired", slog.String("rule_comment", comment))
		return
	}
	log.Warn("response: isolate rule not found at TTL expiry", slog.String("rule_comment", comment))
}
