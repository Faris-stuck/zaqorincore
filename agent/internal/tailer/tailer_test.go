package tailer

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
)

// quietLogger drops everything. Tests assert on channel state, not logs.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// receiveLine waits up to d for a line on ch. Returns the line and true
// on success, or zero/false on timeout.
func receiveLine(t *testing.T, ch <-chan Line, d time.Duration) (Line, bool) {
	t.Helper()
	select {
	case l, ok := <-ch:
		return l, ok
	case <-time.After(d):
		return Line{}, false
	}
}

// waitForFileReady polls path's size until it stabilises or d elapses.
// Used to make sure the OS has flushed an append before we read.
// Required because the tailer polls (250ms) and reads in chunks; we want
// the kernel to settle before we hand the file to the next assertion.
func waitForFileReady(t *testing.T, path string, d time.Duration) {
	t.Helper()
	var last int64 = -1
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		fi, err := os.Stat(path)
		if err == nil {
			if last != -1 && last == fi.Size() {
				return
			}
			last = fi.Size()
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTailer_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("initial line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := New(config.LogSource{Name: "app", Path: path}, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := tl.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// The "initial line" must NOT be replayed — Phase 1 is forward-only.
	if l, ok := receiveLine(t, ch, 400*time.Millisecond); ok {
		t.Errorf("did not expect historical line, got %q", l.Raw)
	}

	// Append two new lines.
	if err := os.WriteFile(path, []byte("initial line\nsecond\nthird\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForFileReady(t, path, 2*time.Second)

	// We should get both. Poll interval is ~250ms. The nxadm/tail
	// library strips trailing newlines from line.Text, so we compare
	// without the newline.
	got := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for len(got) < 2 {
		select {
		case l, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed early; got=%v", got)
			}
			got[string(l.Raw)] = true
			if l.Source != "app" {
				t.Errorf("source = %q, want app", l.Source)
			}
		case <-deadline:
			t.Fatalf("timeout waiting for lines, got=%v", got)
		}
	}
	for _, want := range []string{"second", "third"} {
		if !got[want] {
			t.Errorf("missing line %q in %v", want, got)
		}
	}

	cancel()
	for range ch {
	}
}

func TestTailer_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := New(config.LogSource{Name: "app", Path: path}, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := tl.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for tailer to settle.
	time.Sleep(300 * time.Millisecond)

	// First write establishes a baseline.
	if err := os.WriteFile(path, []byte("pre-rotate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForFileReady(t, path, 2*time.Second)

	if l, ok := receiveLine(t, ch, 3*time.Second); !ok || string(l.Raw) != "pre-rotate" {
		t.Fatalf("expected pre-rotate, got %q ok=%v", l.Raw, ok)
	}

	// Rotate: rename current file, create a new one with the same name.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	// Give the tailer a moment to detect the deletion.
	time.Sleep(500 * time.Millisecond)

	// Now create the new file at the same path. Wait for the tailer
	// to detect the new inode (ReOpen), then write to it.
	newFile, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := newFile.Sync(); err != nil {
		t.Fatal(err)
	}
	newFile.Close()
	// Let the tailer re-open and seek-to-end.
	time.Sleep(500 * time.Millisecond)

	// Now write the post-rotate line.
	if err := os.WriteFile(path, []byte("post-rotate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForFileReady(t, path, 2*time.Second)

	if l, ok := receiveLine(t, ch, 5*time.Second); !ok || string(l.Raw) != "post-rotate" {
		t.Fatalf("expected post-rotate after rotation, got %q ok=%v", l.Raw, ok)
	}

	cancel()
	for range ch {
	}
}

func TestTailer_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := New(config.LogSource{Name: "app", Path: path}, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())

	ch, err := tl.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the goroutine time to start, then cancel.
	time.Sleep(200 * time.Millisecond)
	cancel()

	// Channel must close.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // pass
			}
		case <-deadline:
			t.Fatal("channel did not close within 5s of cancel")
		}
	}
}

func TestTailer_MissingFileThenAppears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "later.log")

	// File does not exist yet.
	tl := New(config.LogSource{Name: "later", Path: path}, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := tl.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Create the file a moment later.
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = os.WriteFile(path, []byte(""), 0o644)
		// Give the tailer time to re-open and seek-to-end.
		time.Sleep(500 * time.Millisecond)
		_ = os.WriteFile(path, []byte("hello\n"), 0o644)
	}()

	if l, ok := receiveLine(t, ch, 10*time.Second); !ok || string(l.Raw) != "hello" {
		t.Fatalf("expected hello after file appears, got %q ok=%v", l.Raw, ok)
	}
}

func TestTailer_EmptyPathRejected(t *testing.T) {
	tl := New(config.LogSource{Name: "x", Path: ""}, quietLogger())
	_, err := tl.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

func TestTailer_MultipleWritesConcurrent(t *testing.T) {
	// Stress: 4 writers append simultaneously, the tailer must receive
	// all 200 lines (no line should be lost, ordering is not guaranteed).
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	tl := New(config.LogSource{Name: "app", Path: path}, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := tl.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	const N = 200
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < N/4; i++ {
				line := []byte("from-w" + string(rune('0'+id)) + "-i" + string(rune('0'+i)) + "\n")
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					t.Errorf("open: %v", err)
					return
				}
				if _, err := f.Write(line); err != nil {
					t.Errorf("write: %v", err)
				}
				f.Close()
			}
		}(w)
	}

	got := 0
	deadline := time.After(20 * time.Second)
	for got < N {
		select {
		case _, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed at got=%d (expected %d)", got, N)
			}
			got++
		case <-deadline:
			t.Fatalf("timeout at got=%d (expected %d)", got, N)
		}
	}
	wg.Wait()
}
