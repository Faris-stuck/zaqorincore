// Tests for the 9 action kind executors in kinds/kinds.go.
//
// We test the pure-validator helpers and the dry-run paths. The
// non-dry-run paths require nft / curl / kill and are smoke-tested
// against a real host, not in this unit test.
package kinds

import (
	"strings"
	"testing"
)

func TestIsValidIPv4(t *testing.T) {
	good := []string{"0.0.0.0", "1.2.3.4", "255.255.255.255", "203.0.113.42", "10.0.0.1"}
	for _, s := range good {
		if !IsValidIPv4(s) {
			t.Errorf("IsValidIPv4(%q) = false, want true", s)
		}
	}
	bad := []string{
		"",
		"1.2.3",
		"1.2.3.4.5",
		"1.2.3.x",
		"1.2.3.256",
		"1.2.3.-1",
		"1.2.3.01", // leading zero (octal trap)
		"abc",
		"::1",
	}
	for _, s := range bad {
		if IsValidIPv4(s) {
			t.Errorf("IsValidIPv4(%q) = true, want false", s)
		}
	}
}

func TestIsValidPath(t *testing.T) {
	good := []string{"/", "/tmp", "/var/log/auth.log", "/etc/passwd"}
	for _, s := range good {
		if !IsValidPath(s) {
			t.Errorf("IsValidPath(%q) = false, want true", s)
		}
	}
	bad := []string{"", "tmp/canary", "relative/path", "C:\\Windows"}
	for _, s := range bad {
		if IsValidPath(s) {
			t.Errorf("IsValidPath(%q) = true, want false", s)
		}
	}
}

func TestIsValidPID(t *testing.T) {
	good := []string{"1", "100", "99999"}
	for _, s := range good {
		if n, ok := IsValidPID(s); !ok || n <= 0 {
			t.Errorf("IsValidPID(%q) = (%d, %v), want (n>0, true)", s, n, ok)
		}
	}
	bad := []string{"", "0", "-1", "abc", "1.5", "1e3"}
	for _, s := range bad {
		if _, ok := IsValidPID(s); ok {
			t.Errorf("IsValidPID(%q) = ok, want !ok", s)
		}
	}
}

func TestBlockIPRejectsBadIP(t *testing.T) {
	// We don't need real nft to test the format gate. The dry-run
	// branch happens after the format check, so a bad IP must fail
	// before we ever look at nft.
	err := BlockIP(testContext(), "not-an-ip", 60, true, testLogger())
	if err == nil {
		t.Fatal("BlockIP accepted a bad IP")
	}
	if !strings.Contains(err.Error(), "invalid IPv4") {
		t.Errorf("error %q does not mention IPv4", err)
	}
}

func TestTarpitIPRejectsBadIP(t *testing.T) {
	err := TarpitIP(testContext(), "1.2.3", 60, true, testLogger())
	if err == nil {
		t.Fatal("TarpitIP accepted a malformed IP")
	}
	if !strings.Contains(err.Error(), "invalid IPv4") {
		t.Errorf("error %q does not mention IPv4", err)
	}
}

func TestCanaryAlertRejectsRelativePath(t *testing.T) {
	err := CanaryAlert(testContext(), "tmp/canary.txt", 0, true, testLogger())
	if err == nil {
		t.Fatal("CanaryAlert accepted a relative path")
	}
	if !strings.Contains(err.Error(), "invalid path") {
		t.Errorf("error %q does not mention path", err)
	}
}

func TestKillProcessRejectsPID1(t *testing.T) {
	err := KillProcess(testContext(), "1", 0, true, testLogger())
	if err == nil {
		t.Fatal("KillProcess accepted pid 1")
	}
	if !strings.Contains(err.Error(), "init") {
		t.Errorf("error %q does not mention init", err)
	}
}

func TestKillProcessRejectsBadPID(t *testing.T) {
	err := KillProcess(testContext(), "abc", 0, true, testLogger())
	if err == nil {
		t.Fatal("KillProcess accepted a non-numeric pid")
	}
}

func TestQuarantineFileRejectsRelativePath(t *testing.T) {
	err := QuarantineFile(testContext(), "etc/passwd", 0, true, testLogger())
	if err == nil {
		t.Fatal("QuarantineFile accepted a relative path")
	}
}

func TestRevokeSessionRejectsEmpty(t *testing.T) {
	err := RevokeSession(testContext(), "", 0, true, testLogger())
	if err == nil {
		t.Fatal("RevokeSession accepted empty session id")
	}
}

func TestWebhookSOARRejectsBadScheme(t *testing.T) {
	err := WebhookSOAR(testContext(), "ftp://example.com", 0, true, testLogger())
	if err == nil {
		t.Fatal("WebhookSOAR accepted ftp://")
	}
	if !strings.Contains(err.Error(), "http://") {
		t.Errorf("error %q does not mention http", err)
	}
}

func TestEvidenceCaptureRejectsEmpty(t *testing.T) {
	err := EvidenceCapture(testContext(), "", 0, true, testLogger())
	if err == nil {
		t.Fatal("EvidenceCapture accepted empty host id")
	}
}

// --- dry-run no-op tests for kinds that don't return early on bad input ---

func TestBlockIPDryRunGoodIP(t *testing.T) {
	// Dry-run must not call nft. The function should return nil.
	if err := BlockIP(testContext(), "203.0.113.42", 60, true, testLogger()); err != nil {
		t.Errorf("BlockIP dry-run: %v", err)
	}
}

func TestTarpitIPDryRunGoodIP(t *testing.T) {
	if err := TarpitIP(testContext(), "203.0.113.42", 60, true, testLogger()); err != nil {
		t.Errorf("TarpitIP dry-run: %v", err)
	}
}

func TestCanaryAlertDryRun(t *testing.T) {
	// Dry-run must not write the file. We use /tmp which exists on
	// every test machine.
	if err := CanaryAlert(testContext(), "/tmp/zaqorin-test-canary.txt", 0, true, testLogger()); err != nil {
		t.Errorf("CanaryAlert dry-run: %v", err)
	}
}

func TestRevokeSessionDryRun(t *testing.T) {
	if err := RevokeSession(testContext(), "session-1234", 0, true, testLogger()); err != nil {
		t.Errorf("RevokeSession dry-run: %v", err)
	}
}

func TestEvidenceCaptureDryRun(t *testing.T) {
	if err := EvidenceCapture(testContext(), "test-host", 0, true, testLogger()); err != nil {
		t.Errorf("EvidenceCapture dry-run: %v", err)
	}
}

func TestWebhookSOARDryRun(t *testing.T) {
	// Dry-run must not call curl. So a bad URL is fine in dry-run.
	// Test the success case:
	if err := WebhookSOAR(testContext(), "https://example.com/soar", 0, true, testLogger()); err != nil {
		t.Errorf("WebhookSOAR dry-run: %v", err)
	}
}
