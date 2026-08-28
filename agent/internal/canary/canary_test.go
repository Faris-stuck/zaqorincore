package canary

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSecret puts the canary secret into a temp file so
// fsnotify has something to watch without racing the test.
func writeSecret(t *testing.T, path, secret string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write canary: %v", err)
	}
}

func TestAddFileCanaryFiresOnAccess(t *testing.T) {
	dir := t.TempDir()
	canary := filepath.Join(dir, "marker.txt")
	writeSecret(t, canary, "secret-1")

	w := New(testLogger(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Add(ctx, Descriptor{
		ID:        "c1",
		Kind:      "file",
		Path:      canary,
		CreatedAt: time.Now(),
		Secret:    "secret-1",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Touch the canary file. fsnotify may coalesce multiple
	// events into one; we just need at least one touch.
	if err := os.WriteFile(canary, []byte("tampered\n"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	select {
	case got := <-w.Touches():
		if got.CanaryID != "c1" {
			t.Fatalf("canary id: got %q want %q", got.CanaryID, "c1")
		}
		if got.TouchedBy == "" {
			t.Fatalf("empty touched_by")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for touch")
	}
}

func TestAddFileCanaryCreatesMarkerIfMissing(t *testing.T) {
	dir := t.TempDir()
	canary := filepath.Join(dir, "fresh", "marker.txt")
	w := New(testLogger(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Add(ctx, Descriptor{
		ID:        "c2",
		Kind:      "file",
		Path:      canary,
		CreatedAt: time.Now(),
		Secret:    "fresh-secret",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("expected marker to be created: %v", err)
	}
}

func TestAddUnknownKindFails(t *testing.T) {
	w := New(testLogger(t))
	if err := w.Add(context.Background(), Descriptor{
		ID:   "c3",
		Kind: "lalala",
		Path: "/dev/null",
	}); err == nil {
		t.Fatalf("expected error for unknown kind")
	}
}

func TestRemoveStopsWatcher(t *testing.T) {
	dir := t.TempDir()
	canary := filepath.Join(dir, "m.txt")
	writeSecret(t, canary, "x")
	w := New(testLogger(t))
	ctx := context.Background()
	if err := w.Add(ctx, Descriptor{
		ID:   "c4",
		Kind: "file",
		Path: canary,
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	w.Remove("c4")
	if got := w.List(); len(got) != 0 {
		t.Fatalf("expected empty list after remove, got %v", got)
	}
}
