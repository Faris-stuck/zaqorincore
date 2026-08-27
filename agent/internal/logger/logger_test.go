package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNew_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New("warn", &buf, FormatJSON)

	log.Info("info message")  // dropped
	log.Warn("warn message")  // kept
	log.Error("error message") // kept

	out := buf.String()
	if strings.Contains(out, "info message") {
		t.Errorf("info should be dropped at warn level, got: %s", out)
	}
	if !strings.Contains(out, "warn message") {
		t.Errorf("warn should pass, got: %s", out)
	}
	if !strings.Contains(out, "error message") {
		t.Errorf("error should pass, got: %s", out)
	}
}

func TestNew_InvalidLevelFallsBack(t *testing.T) {
	var buf bytes.Buffer
	log, warn := NewWithWarning("trace", &buf, FormatJSON)
	if warn == nil {
		t.Fatal("expected warning for invalid level, got nil")
	}
	if !strings.Contains(warn.Error(), "trace") {
		t.Errorf("warning %q should mention the bad value", warn)
	}
	// Logger should still work at info.
	log.Info("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("logger should still emit, got: %s", buf.String())
	}
}

func TestNew_EmptyLevelDefaultsToInfo(t *testing.T) {
	var buf bytes.Buffer
	log, warn := NewWithWarning("", &buf, FormatJSON)
	if warn != nil {
		t.Errorf("empty level should not warn, got: %v", warn)
	}
	log.Info("hi")
	if !strings.Contains(buf.String(), "hi") {
		t.Errorf("expected info to pass, got: %s", buf.String())
	}
}

func TestNew_JSONIsLineDelimited(t *testing.T) {
	var buf bytes.Buffer
	log := New("info", &buf, FormatJSON)
	log.Info("first")
	log.Info("second", slog.String("key", "value"))

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}
	// Each line must parse as JSON.
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d not valid JSON: %v: %q", i, err, line)
		}
	}
}

func TestNew_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New("info", &buf, FormatText)
	log.Info("hello", slog.String("k", "v"))
	out := buf.String()
	// Text handler writes key=value pairs.
	if !strings.Contains(out, "hello") {
		t.Errorf("missing message: %s", out)
	}
	if !strings.Contains(out, "k=v") {
		t.Errorf("missing attribute: %s", out)
	}
	// And it must NOT be JSON.
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("text format emitted JSON: %s", out)
	}
}

func TestNew_DebugLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New("debug", &buf, FormatJSON)
	log.Debug("d")
	log.Info("i")
	if !strings.Contains(buf.String(), `"d"`) {
		t.Errorf("debug should pass at debug level, got: %s", buf.String())
	}
}

func TestParseLevel_AllValid(t *testing.T) {
	for _, s := range []string{"debug", "INFO", "Warn", "warning", "ERROR", ""} {
		if _, ok := parseLevel(s); !ok {
			t.Errorf("parseLevel(%q) returned ok=false; expected true", s)
		}
	}
}

func TestParseLevel_Invalid(t *testing.T) {
	for _, s := range []string{"trace", "fatal", "verbose", "all"} {
		if _, ok := parseLevel(s); ok {
			t.Errorf("parseLevel(%q) returned ok=true; expected false", s)
		}
	}
}
