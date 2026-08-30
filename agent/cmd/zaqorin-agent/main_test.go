package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestPrintVersionDefault verifies the default version literal
// (overridden at build time by -ldflags) renders with the expected
// "zaqorin-agent <version>\n" format.
func TestPrintVersionDefault(t *testing.T) {
	var buf bytes.Buffer
	printVersion(&buf)

	got := buf.String()
	want := "zaqorin-agent dev\n"
	if got != want {
		t.Fatalf("printVersion() = %q, want %q", got, want)
	}
}

// TestPrintVersionOverride exercises the -ldflags injection path:
// we mutate the package-level `version` variable to a fake release
// number, render, and restore. This mirrors how release builds
// stamp the real semver.
func TestPrintVersionOverride(t *testing.T) {
	const injected = "v2.2.0-test"
	orig := version
	version = injected
	defer func() { version = orig }()

	var buf bytes.Buffer
	printVersion(&buf)

	got := strings.TrimSpace(buf.String())
	want := "zaqorin-agent " + injected
	if got != want {
		t.Fatalf("printVersion() = %q, want %q", got, want)
	}
}