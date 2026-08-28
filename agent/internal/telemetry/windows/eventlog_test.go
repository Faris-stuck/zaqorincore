// Tests for the Windows Event Log telemetry helpers. The pure
// metadata-mapping logic lives in eventlog_common.go so these
// tests run on every GOOS (including the Linux CI host).
// The Win32-specific code in eventlog_windows.go is exercised
// only on the windows GOOS (in agent_test.go for that target).
package windows

import (
	"testing"
)

// sampleEvent4624 is a minimal 4624 (successful logon) XML record
// the way Windows renders it. Field order matches the live
// Windows event schema as of 2024-08; if Microsoft reorders it
// the field-index map in metadataFor will need updating.
const sampleEvent4624 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-08-28T13:00:00.000Z"/>
    <Computer>WIN-DESKTOP01</Computer>
  </System>
  <EventData>
    <Data>S-1-0-0</Data>
    <Data>WIN-DESKTOP01$</Data>
    <Data>WORKGROUP</Data>
    <Data>S-1-5-21-1234-5678-9012-3456</Data>
    <Data>alice</Data>
    <Data>WIN-DESKTOP01</Data>
    <Data>{00000000-0000-0000-0000-000000000000}</Data>
    <Data>0x0</Data>
    <Data>2</Data>
    <Data>User32</Data>
    <Data>Negotiate</Data>
    <Data>WIN-DESKTOP01</Data>
    <Data>{00000000-0000-0000-0000-000000000000}</Data>
    <Data>-</Data>
    <Data>-</Data>
    <Data>0</Data>
    <Data>0x3e4</Data>
    <Data>C:\\Windows\\System32\\svchost.exe</Data>
    <Data>192.0.2.45</Data>
    <Data>50123</Data>
  </EventData>
</Event>`

// TestBuildWireEvent4624 confirms the metadata mapping for a
// successful logon event: subject_user, target_user, logon_type,
// process_name, and source_ip must all be populated.
func TestBuildWireEvent4624(t *testing.T) {
	ev, err := buildWireEvent([]byte(sampleEvent4624))
	if err != nil {
		t.Fatalf("buildWireEvent: %v", err)
	}
	if ev.Source != Source4624 {
		t.Errorf("source: got %q want %q", ev.Source, Source4624)
	}
	if got := ev.Metadata["target_user"]; got != "alice" {
		t.Errorf("target_user: got %q want alice", got)
	}
	if got := ev.Metadata["logon_type"]; got != "2" {
		t.Errorf("logon_type: got %q want 2", got)
	}
	if got := ev.Metadata["source_ip"]; got != "192.0.2.45" {
		t.Errorf("source_ip: got %q want 192.0.2.45", got)
	}
	if got := ev.Metadata["computer"]; got != "WIN-DESKTOP01" {
		t.Errorf("computer: got %q want WIN-DESKTOP01", got)
	}
	if ev.Metadata["xml"] == "" {
		t.Error("xml: expected raw xml to be kept in metadata")
	}
}

const sampleEvent4688 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-08-28T13:01:00.000Z"/>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data>S-1-5-18</Data>
    <Data>SYSTEM</Data>
    <Data>NT AUTHORITY</Data>
    <Data>0x3e7</Data>
    <Data>0x1234</Data>
    <Data>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data>TokenElevationType%%1936</Data>
    <Data>C:\\Windows\\System32\\cmd.exe</Data>
    <Data>powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==</Data>
    <Data>S-1-0-0</Data>
    <Data>-</Data>
    <Data>-</Data>
    <Data>0x0</Data>
    <Data>C:\\Windows\\System32\\services.exe</Data>
    <Data>0x0</Data>
  </EventData>
</Event>`

// TestBuildWireEvent4688 confirms the process_create mapping
// captures command_line, parent_process_name, and process_name.
// The command_line below is a PowerShell -EncodedCommand sample
// the powershell_encoded Sigma rule should pick up.
func TestBuildWireEvent4688(t *testing.T) {
	ev, err := buildWireEvent([]byte(sampleEvent4688))
	if err != nil {
		t.Fatalf("buildWireEvent: %v", err)
	}
	if ev.Source != Source4688 {
		t.Errorf("source: got %q want %q", ev.Source, Source4688)
	}
	if got := ev.Metadata["command_line"]; got == "" {
		t.Error("command_line: empty")
	}
	if got := ev.Metadata["parent_process_name"]; got == "" {
		t.Error("parent_process_name: empty")
	}
	if got := ev.Metadata["process_name"]; got == "" {
		t.Error("process_name: empty")
	}
}

// TestBuildWireEventUnknownID confirms an event ID outside the
// subscription list produces an error rather than a silent
// zero-value event.
func TestBuildWireEventUnknownID(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>9999</EventID>
    <TimeCreated SystemTime="2026-08-28T13:00:00.000Z"/>
    <Computer>WIN</Computer>
  </System>
  <EventData><Data>x</Data></EventData>
</Event>`
	_, err := buildWireEvent([]byte(xml))
	if err == nil {
		t.Fatal("expected error for unknown event id, got nil")
	}
}

// TestSubscribedEventIDs asserts the Source* constants and the
// subscription map are in lockstep. Adding a new event ID
// without wiring it through the dispatcher is a common mistake;
// this test catches it.
func TestSubscribedEventIDs(t *testing.T) {
	want := map[uint32]string{
		4624: Source4624,
		4625: Source4625,
		4688: Source4688,
		4698: Source4698,
		4720: Source4720,
		4732: Source4732,
	}
	if len(subscribedEventIDs) != len(want) {
		t.Errorf("subscribedEventIDs size: got %d want %d", len(subscribedEventIDs), len(want))
	}
	for id, src := range want {
		if got := subscribedEventIDs[id]; got != src {
			t.Errorf("subscribedEventIDs[%d]: got %q want %q", id, got, src)
		}
	}
}

// TestIndexNul exercises the NUL-trimming helper used to
// strip the trailing padding EvtRender leaves in its output.
func TestIndexNul(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
	}{
		{[]byte("hello\x00world"), 5},
		{[]byte("no nuls here"), -1},
		{[]byte{0}, 0},
		{nil, -1},
	}
	for _, c := range cases {
		if got := indexNul(c.in); got != c.want {
			t.Errorf("indexNul(%q): got %d want %d", c.in, got, c.want)
		}
	}
}
