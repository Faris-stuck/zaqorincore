// Package event defines the wire contract for events sent from the agent
// to the central server. The JSON shape produced here is the same shape
// the server will eventually consume, so changes are wire-protocol changes
// and must follow the project's SemVer rules.
package event

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SchemaVersion is bumped whenever the on-wire JSON shape changes in a
// non-backward-compatible way. The server will be able to refuse events
// whose version it does not understand.
const SchemaVersion = "1.0"

// Reserved source names. Detectectors in later phases will filter on these.
const (
	SourceAuth         = "auth"
	SourceNginxAccess  = "nginx_access"
	SourceNginxError   = "nginx_error"
	SourceModSecAudit  = "modsec_audit"
	SourceJournald     = "journald"
)

// Metadata key names. These MUST match the field names referenced
// by Sigma rules under server/rules/builtin/* and by the webtail
// parsers in pkg/webtail. They live here (not in pkg/webtail) so
// the agent and the rules can both reference them without an
// import cycle — pkg/* is downstream of internal/*.
const (
	WebKeySourceIP  = "src_ip"
	WebKeyMethod    = "http_method"
	WebKeyURI       = "uri"
	WebKeyStatus    = "status_code"
	WebKeyBytes     = "bytes_sent"
	WebKeyReferer   = "referer"
	WebKeyUserAgent = "user_agent"
	WebKeyAuthUser  = "auth_user"
)

// Event is the on-wire representation of a single log line the agent
// observed. Keep the field set small and stable — every field is a
// promise to the server.
type Event struct {
	// Schema is the wire-schema version (e.g. "1.0"). Forwarded to
	// the server so it can refuse unknown versions.
	Schema string `json:"schema"`

	// ID is a v4 UUID, unique per event. Generated at construction
	// time. The server may use it to deduplicate.
	ID string `json:"id"`

	// Timestamp is the moment the agent observed the line, in UTC,
	// RFC3339 with nanosecond precision. Do NOT use the log line's
	// own timestamp — the server may not trust the host clock and
	// needs a single source of truth.
	Timestamp time.Time `json:"timestamp"`

	// HostID is the agent's stable identifier (UUID v4, persisted
	// in state_dir on first run). Used by the server to group
	// events from the same host.
	HostID string `json:"host_id"`

	// Source identifies the log source that produced the line.
	// Typically one of the Source* constants above. Free-form
	// strings are allowed for custom sources.
	Source string `json:"source"`

	// Raw is the log line exactly as the agent read it, including
	// the trailing newline if present. UTF-8, no encoding
	// translation. Binary data is not supported in Phase 1.
	Raw string `json:"raw"`

	// Metadata carries optional structured hints. Phase 1 leaves
	// it empty; later phases will populate it (e.g. parsed fields
	// like "src_ip", "user", "status_code"). The map is owned by
	// the Event value; callers may mutate it freely.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// New constructs a fresh Event with a fresh UUID and the current
// wall-clock timestamp. hostID and source must be non-empty —
// callers should validate that upstream. The metadata map is
// initialised to a non-nil empty map so the JSON output is stable
// (the "omitempty" tag then drops it from the wire until the
// caller actually adds keys).
func New(hostID, source, raw string) Event {
	return Event{
		Schema:    SchemaVersion,
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		HostID:    hostID,
		Source:    source,
		Raw:       raw,
		Metadata:  map[string]string{},
	}
}

// Validate returns an error if the Event violates the minimum
// invariants. The agent runs this before sending; the server runs
// it again on receipt (defence in depth).
func (e Event) Validate() error {
	if e.Schema == "" {
		return fmt.Errorf("event: schema is required")
	}
	if e.ID == "" {
		return fmt.Errorf("event: id is required")
	}
	if _, err := uuid.Parse(e.ID); err != nil {
		return fmt.Errorf("event: id is not a valid UUID: %w", err)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("event: timestamp is required")
	}
	if e.HostID == "" {
		return fmt.Errorf("event: host_id is required")
	}
	if e.Source == "" {
		return fmt.Errorf("event: source is required")
	}
	return nil
}

// ---- JSON helpers ----
//
// We use explicit MarshalJSON / UnmarshalJSON (rather than relying
// on struct tags alone) so that:
//
//   - The wire timestamp is always a string, never a numeric epoch
//     (so a Lua script or shell one-liner can grep the field).
//   - The metadata map never serialises as null — a missing key on
//     unmarshal becomes an empty map, not a nil one.
//   - Unknown fields are preserved on round-trip (forward
//     compatibility for future server-side metadata).

// MarshalJSON renders the Event for the wire. Timestamp is emitted
// as RFC3339Nano in UTC. Metadata is omitted when empty.
func (e Event) MarshalJSON() ([]byte, error) {
	type wire struct {
		Schema    string            `json:"schema"`
		ID        string            `json:"id"`
		Timestamp string            `json:"timestamp"`
		HostID    string            `json:"host_id"`
		Source    string            `json:"source"`
		Raw       string            `json:"raw"`
		Metadata  map[string]string `json:"metadata,omitempty"`
	}
	return json.Marshal(wire{
		Schema:    e.Schema,
		ID:        e.ID,
		Timestamp: e.Timestamp.UTC().Format(time.RFC3339Nano),
		HostID:    e.HostID,
		Source:    e.Source,
		Raw:       e.Raw,
		Metadata:  e.Metadata,
	})
}

// UnmarshalJSON parses a wire payload back into an Event. The
// timestamp is parsed as RFC3339Nano.
func (e *Event) UnmarshalJSON(data []byte) error {
	type wire struct {
		Schema    string            `json:"schema"`
		ID        string            `json:"id"`
		Timestamp string            `json:"timestamp"`
		HostID    string            `json:"host_id"`
		Source    string            `json:"source"`
		Raw       string            `json:"raw"`
		Metadata  map[string]string `json:"metadata"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	ts, err := time.Parse(time.RFC3339Nano, w.Timestamp)
	if err != nil {
		return fmt.Errorf("event: parse timestamp: %w", err)
	}
	e.Schema = w.Schema
	e.ID = w.ID
	e.Timestamp = ts
	e.HostID = w.HostID
	e.Source = w.Source
	e.Raw = w.Raw
	if w.Metadata == nil {
		e.Metadata = map[string]string{}
	} else {
		e.Metadata = w.Metadata
	}
	return nil
}

// ---- Pooling ----
//
// The agent will produce a lot of these per second on a busy
// host. Allocating a fresh Event on every send shows up in the
// profile. The pool keeps the struct (not the metadata map, which
// is small and varies in size) on a free list.

var eventPool = sync.Pool{
	New: func() any {
		e := Event{Metadata: map[string]string{}}
		return &e
	},
}

// Get fetches a zero-value Event from the pool. The caller MUST
// call Put when done. The returned Event is ready for MarshalJSON;
// the caller is expected to overwrite the fields it cares about.
func Get() *Event {
	return eventPool.Get().(*Event)
}

// Put returns the Event to the pool. After calling Put, the
// caller must not touch the Event again.
func (e *Event) Put() {
	// Clear fields that may hold references to large buffers
	// before returning to the pool, so the GC can reclaim them.
	e.Schema = ""
	e.ID = ""
	e.Timestamp = time.Time{}
	e.HostID = ""
	e.Source = ""
	e.Raw = ""
	for k := range e.Metadata {
		delete(e.Metadata, k)
	}
	eventPool.Put(e)
}
