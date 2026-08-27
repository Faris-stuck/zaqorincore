package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNew_GeneratesValidEvent(t *testing.T) {
	before := time.Now().UTC()
	ev := New("host-abc", SourceAuth, "Accepted publickey for faris from 1.2.3.4\n")
	after := time.Now().UTC()

	if ev.Schema != SchemaVersion {
		t.Errorf("Schema = %q, want %q", ev.Schema, SchemaVersion)
	}
	if ev.ID == "" {
		t.Error("ID is empty")
	}
	if !strings.Contains(ev.ID, "-") {
		// quick sanity check; full UUID parse in TestValidate
		t.Errorf("ID %q does not look like a UUID", ev.ID)
	}
	if ev.Timestamp.Before(before) || ev.Timestamp.After(after) {
		t.Errorf("Timestamp %v out of expected range [%v, %v]", ev.Timestamp, before, after)
	}
	if ev.HostID != "host-abc" {
		t.Errorf("HostID = %q, want %q", ev.HostID, "host-abc")
	}
	if ev.Source != SourceAuth {
		t.Errorf("Source = %q, want %q", ev.Source, SourceAuth)
	}
	if ev.Raw != "Accepted publickey for faris from 1.2.3.4\n" {
		t.Errorf("Raw = %q, want exact match", ev.Raw)
	}
	if ev.Metadata == nil {
		t.Error("Metadata should be an empty map, not nil")
	}
}

func TestValidate_AcceptsGoodEvent(t *testing.T) {
	ev := New("host-abc", SourceAuth, "x")
	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidate_RejectsBadEvents(t *testing.T) {
	base := New("host-abc", SourceAuth, "x")
	cases := []struct {
		name string
		mut  func(*Event)
	}{
		{"empty schema", func(e *Event) { e.Schema = "" }},
		{"empty id", func(e *Event) { e.ID = "" }},
		{"non-uuid id", func(e *Event) { e.ID = "not-a-uuid" }},
		{"zero timestamp", func(e *Event) { e.Timestamp = time.Time{} }},
		{"empty host", func(e *Event) { e.HostID = "" }},
		{"empty source", func(e *Event) { e.Source = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := base
			tc.mut(&ev)
			if err := ev.Validate(); err == nil {
				t.Errorf("Validate() = nil, want error")
			}
		})
	}
}

func TestMarshalJSON_StableShape(t *testing.T) {
	ev := New("host-abc", SourceAuth, "raw line\n")

	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Required keys must all be present.
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, k := range []string{"schema", "id", "timestamp", "host_id", "source", "raw"} {
		if _, ok := m[k]; !ok {
			t.Errorf("key %q missing from JSON: %s", k, data)
		}
	}
	// Metadata should be omitted when empty (omitempty).
	if _, ok := m["metadata"]; ok {
		t.Errorf("metadata key should be omitted when empty, got: %s", data)
	}
	// Timestamp must be a string, not a number.
	if _, ok := m["timestamp"].(string); !ok {
		t.Errorf("timestamp should be a string, got %T: %s", m["timestamp"], data)
	}
}

func TestRoundTrip_JSON(t *testing.T) {
	orig := New("host-abc", SourceAuth, "raw line with \"quotes\" and \n newline\n")
	orig.Metadata["src_ip"] = "10.0.0.1"
	orig.Metadata["user"] = "faris"

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ID != orig.ID {
		t.Errorf("ID: got %q, want %q", got.ID, orig.ID)
	}
	if !got.Timestamp.Equal(orig.Timestamp) {
		t.Errorf("Timestamp: got %v, want %v", got.Timestamp, orig.Timestamp)
	}
	if got.HostID != orig.HostID {
		t.Errorf("HostID: got %q, want %q", got.HostID, orig.HostID)
	}
	if got.Source != orig.Source {
		t.Errorf("Source: got %q, want %q", got.Source, orig.Source)
	}
	if got.Raw != orig.Raw {
		t.Errorf("Raw: got %q, want %q", got.Raw, orig.Raw)
	}
	if got.Metadata["src_ip"] != "10.0.0.1" {
		t.Errorf("Metadata[src_ip] = %q, want %q", got.Metadata["src_ip"], "10.0.0.1")
	}
	if got.Metadata["user"] != "faris" {
		t.Errorf("Metadata[user] = %q, want %q", got.Metadata["user"], "faris")
	}

	// And a second round trip should still work.
	data2, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal #2: %v", err)
	}
	var got2 Event
	if err := json.Unmarshal(data2, &got2); err != nil {
		t.Fatalf("Unmarshal #2: %v", err)
	}
	if got2.ID != orig.ID {
		t.Errorf("second-round ID: got %q, want %q", got2.ID, orig.ID)
	}
}

func TestUnmarshalJSON_MetadataDefault(t *testing.T) {
	// A payload with no "metadata" key should decode to an empty
	// (non-nil) map, never a nil map. This matters because nil
	// maps marshal as "null" and break consumers.
	payload := `{
		"schema": "1.0",
		"id": "11111111-2222-3333-4444-555555555555",
		"timestamp": "2026-01-02T03:04:05.000000006Z",
		"host_id": "host-abc",
		"source": "auth",
		"raw": "line"
	}`
	var ev Event
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ev.Metadata == nil {
		t.Fatal("Metadata is nil; want empty map")
	}
	// And re-marshalling should NOT emit "metadata":null.
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(out), `"metadata":null`) {
		t.Errorf("re-marshalled JSON contains null metadata: %s", out)
	}
}

func TestPool_RoundTrip(t *testing.T) {
	ev := Get()
	ev.Schema = SchemaVersion
	ev.ID = "11111111-2222-3333-4444-555555555555"
	ev.Timestamp = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ev.HostID = "host-abc"
	ev.Source = SourceAuth
	ev.Raw = "x"
	ev.Metadata["k"] = "v"

	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	ev.Put()

	// After Put, marshalling the same Event would be a use-after-free.
	// Just assert the JSON we got is well-formed and matches.
	var back Event
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Metadata["k"] != "v" {
		t.Errorf("metadata lost across pool round-trip")
	}
}
