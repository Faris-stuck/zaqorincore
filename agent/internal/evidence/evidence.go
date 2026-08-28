// Package evidence implements the agent side of the evidence
// locker (Phase 7, ADR-005).
//
// The agent receives an `evidence_capture` COMMAND frame from
// the server with a list of file paths. It tar+gz's them,
// computes two SHA-256s (one over the original files, one over
// the resulting tarball), and ships the bundle back to the
// server over the WS evidence.submit frame.
package evidence

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// SourceFile describes one file the operator wants to capture.
type SourceFile struct {
	Path string `json:"path"`
}

// Submit is the frame the agent sends back to the server.
type Submit struct {
	AlertID     string            `json:"alert_id"`
	HostID      string            `json:"host_id"`
	CapturedAt  time.Time         `json:"captured_at"`
	CapturedBy  string            `json:"captured_by"`
	BundleSHA   string            `json:"bundle_sha256"`
	SourceHashes map[string]string `json:"source_hashes"`
	Tarball     []byte            `json:"tarball"`
}

// Capture reads each path, builds a tar.gz bundle, and returns
// the Submit frame. The agent's main loop then writes the frame
// to the WS connection.
func Capture(
	ctx context.Context,
	log *slog.Logger,
	alertID string,
	hostID string,
	capturedBy string,
	paths []string,
) (*Submit, error) {
	sourceHashes := make(map[string]string, len(paths))
	for _, p := range paths {
		h, err := fileSHA256(p)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", p, err)
		}
		// Use a path relative to / for the map key. This keeps
		// the key stable across machines and matches what the
		// server's chain-of-custody sidecar expects.
		rel := relPath(p)
		sourceHashes[rel] = h
	}

	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		err := writeTarGz(pw, paths)
		_ = pw.CloseWithError(err)
		errCh <- err
	}()

	tarBytes, err := io.ReadAll(pr)
	if err != nil {
		return nil, fmt.Errorf("read tar: %w", err)
	}
	if err := <-errCh; err != nil {
		return nil, fmt.Errorf("build tar: %w", err)
	}

	bundleSHA := sha256.Sum256(tarBytes)
	return &Submit{
		AlertID:      alertID,
		HostID:       hostID,
		CapturedAt:   time.Now().UTC(),
		CapturedBy:   capturedBy,
		BundleSHA:    hex.EncodeToString(bundleSHA[:]),
		SourceHashes: sourceHashes,
		Tarball:      tarBytes,
	}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func relPath(p string) string {
	if rel, err := filepath.Rel("/", p); err == nil {
		return rel
	}
	return p
}

func writeTarGz(w io.Writer, paths []string) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for _, p := range paths {
		if err := addFile(tw, p); err != nil {
			return err
		}
	}
	return nil
}

func addFile(tw *tar.Writer, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = relPath(path)
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// Marshal a Submit to JSON bytes for the WS frame.
func Marshal(s *Submit) ([]byte, error) {
	return json.Marshal(s)
}
