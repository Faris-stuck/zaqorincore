package crypto_test

import (
	"strings"
	"testing"

	"github.com/Faris-stuck/zaqorincore/agent/internal/crypto"
)

func TestCanonicalByteStable(t *testing.T) {
	got := string(crypto.Canonical("abc-123", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z"))
	want := "abc-123|block_ip|1.2.3.4|60|2026-08-28T00:00:00Z"
	if got != want {
		t.Fatalf("canonical mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	secret := "s3cr3t-very-very-very-long-12345"
	cmdID := "cmd-1"
	kind := "block_ip"
	target := "203.0.113.42"
	ttl := 300
	issuedAt := "2026-08-28T10:00:00+00:00"
	sig := crypto.Sign(secret, cmdID, kind, target, ttl, issuedAt)
	if len(sig) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(sig), sig)
	}
	if !crypto.Verify(secret, cmdID, kind, target, ttl, issuedAt, sig) {
		t.Fatal("Verify returned false for a freshly signed value")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	secret := "s3cr3t"
	sig := crypto.Sign(secret, "id", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z")
	// Flip the last hex char.
	flipped := sig[:len(sig)-1]
	if sig[len(sig)-1] == '0' {
		flipped += "1"
	} else {
		flipped += "0"
	}
	if crypto.Verify(secret, "id", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z", flipped) {
		t.Fatal("Verify accepted a tampered signature")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	sig := crypto.Sign("alpha", "id", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z")
	if crypto.Verify("beta", "id", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z", sig) {
		t.Fatal("Verify accepted a signature from a different secret")
	}
}

func TestVerifyRejectsTamperedTarget(t *testing.T) {
	secret := "k"
	sig := crypto.Sign(secret, "id", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z")
	if crypto.Verify(secret, "id", "block_ip", "1.2.3.5", 60, "2026-08-28T00:00:00Z", sig) {
		t.Fatal("Verify accepted a signature for a different target")
	}
}

func TestVerifyRejectsNonHex(t *testing.T) {
	if crypto.Verify("k", "id", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z", "zzz") {
		t.Fatal("Verify accepted non-hex signature")
	}
}

func TestVerifyRejectsShortSignature(t *testing.T) {
	if crypto.Verify("k", "id", "block_ip", "1.2.3.4", 60, "2026-08-28T00:00:00Z", "abcd") {
		t.Fatal("Verify accepted a short signature")
	}
}

func TestParseHexMAC(t *testing.T) {
	if _, err := crypto.ParseHexMAC("abcd"); err == nil {
		t.Fatal("expected length error")
	}
	if _, err := crypto.ParseHexMAC(strings.Repeat("z", 64)); err == nil {
		t.Fatal("expected hex error")
	}
	if _, err := crypto.ParseHexMAC(strings.Repeat("a", 64)); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}
