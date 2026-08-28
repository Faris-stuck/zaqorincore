package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestCaptureProducesTarGzWithExpectedHashes(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "sub", "b.txt")
	writeFile(t, a, "alpha")
	writeFile(t, b, "bravo")

	got, err := Capture(context.Background(), nil, "alert-1", "host-1", "operator", []string{a, b})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if got.AlertID != "alert-1" {
		t.Fatalf("alert id: %q", got.AlertID)
	}
	if got.BundleSHA == "" {
		t.Fatalf("empty bundle sha")
	}
	// Source hashes are keyed by path relative to /.
	if len(got.SourceHashes) != 2 {
		t.Fatalf("expected 2 source hashes, got %d", len(got.SourceHashes))
	}
	for rel, h := range got.SourceHashes {
		if !strings.HasPrefix(rel, "tmp/") {
			t.Fatalf("unexpected rel key: %q", rel)
		}
		// Hash matches the file's contents.
		abs := "/" + filepath.ToSlash(rel)
		if h != fileSHA(t, abs) {
			t.Fatalf("hash mismatch for %q", rel)
		}
	}
	// Tarball should be a valid gzip stream.
	if !strings.HasPrefix(string(got.Tarball[:2]), "\x1f\x8b") {
		t.Fatalf("not a gzip header")
	}
}

func TestCaptureMissingFileFails(t *testing.T) {
	_, err := Capture(context.Background(), nil, "a", "h", "op", []string{"/nonexistent"})
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}
