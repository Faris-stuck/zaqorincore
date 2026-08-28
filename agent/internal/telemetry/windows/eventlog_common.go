// Cross-platform helpers for the Windows Event Log backend.
//
// The XML-decoding and metadata-mapping functions live here so
// they can be unit-tested on Linux (the agent's CI host) and
// reused from the Windows-specific file (eventlog_windows.go)
// that owns the Win32 syscalls.
//
// Keeping these functions free of `syscall`/`unsafe` also means
// the file is safe to import from other packages (e.g. the
// server's smoke test) without dragging in wevtapi.dll.
package windows

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
)

// Source names emitted on the wire. Stable; Sigma rules and the
// server's detector pipeline key off them.
const (
	Source4624 = "windows.security.4624" // Successful logon
	Source4625 = "windows.security.4625" // Failed logon
	Source4688 = "windows.security.4688" // Process created
	Source4698 = "windows.security.4698" // Scheduled task created
	Source4720 = "windows.security.4720" // User account created
	Source4732 = "windows.security.4732" // Member added to security-enabled group
)

// EventIDs we subscribe to. Kept as a single map so the dispatch
// table is data-driven and easy to extend without code changes.
var subscribedEventIDs = map[uint32]string{
	4624: Source4624,
	4625: Source4625,
	4688: Source4688,
	4698: Source4698,
	4720: Source4720,
	4732: Source4732,
}

// evt is the subset of the Windows Event Log XML schema we care
// about. encoding/xml does the field-by-field decoding.
type evt struct {
	XMLName   xml.Name  `xml:"Event"`
	System    evtSystem `xml:"System"`
	EventData evtData   `xml:"EventData"`
}

type evtSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID uint32 `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
}

type evtData struct {
	Data []string `xml:"Data"`
}

// buildWireEvent converts a rendered XML event into the wire
// payload the rest of the agent already understands (event.Event).
//
// Source mapping is by EventID. Fields the Sigma rules downstream
// care about are extracted from EventData into a flat metadata map.
func buildWireEvent(xmlBytes []byte) (event.Event, error) {
	var e evt
	if err := xml.Unmarshal(xmlBytes, &e); err != nil {
		return event.Event{}, fmt.Errorf("decode xml: %w", err)
	}
	src, ok := subscribedEventIDs[e.System.EventID]
	if !ok {
		return event.Event{}, fmt.Errorf("eventlog: unknown event id %d", e.System.EventID)
	}
	meta := metadataFor(e)
	// Always keep the raw XML so analysts can re-parse with full
	// fidelity in the web console.
	meta["xml"] = string(xmlBytes)
	return event.Event{
		Schema:    event.SchemaVersion,
		Timestamp: time.Now().UTC(),
		Source:    src,
		Raw:       string(xmlBytes),
		Metadata:  meta,
	}, nil
}

// metadataFor maps EventData fields to friendly names per event ID.
// Field names match the Sigma rules under server/rules/builtin/
// windows_eventlog/. Where the field is positional (Data is a list)
// we pick by index; the field name comes from the Windows event
// schema and is documented in the rule's description.
func metadataFor(e evt) map[string]string {
	m := make(map[string]string, 8)
	m["event_id"] = fmt.Sprintf("%d", e.System.EventID)
	m["computer"] = e.System.Computer
	m["provider"] = e.System.Provider.Name
	m["system_time"] = e.System.TimeCreated.SystemTime

	// Positional EventData. Indices below are the *Windows* event
	// schema; if Microsoft reorders them in a future build the
	// Sigma rules will start firing oddly. Operators see a
	// `metadata.xml` field in the alert and can confirm.
	d := e.EventData.Data
	switch e.System.EventID {
	case 4624, 4625:
		// SubjectUserSid, SubjectUserName, SubjectDomainName,
		// TargetUserSid, TargetUserName, TargetDomainName,
		// Status, FailureReason, LogonType, LogonProcessName,
		// AuthenticationPackageName, WorkstationName, LogonGuid,
		// TransmittedServices, LmPackageName, KeyLength,
		// ProcessId, ProcessName, IpAddress, IpPort
		setIf(&m, "subject_user", d, 1)
		setIf(&m, "target_user", d, 4)
		setIf(&m, "logon_type", d, 8)
		setIf(&m, "logon_process", d, 9)
		setIf(&m, "auth_package", d, 10)
		setIf(&m, "workstation", d, 11)
		setIf(&m, "process_name", d, 17)
		setIf(&m, "source_ip", d, 18)
		setIf(&m, "source_port", d, 19)
	case 4688:
		// SubjectUserSid, SubjectUserName, SubjectDomainName,
		// SubjectLogonId, NewProcessId, NewProcessName,
		// TokenElevationType, ProcessId, CommandLine,
		// TargetUserSid, TargetUserName, TargetDomainName,
		// TargetLogonId, ParentProcessName, ParentProcessId
		setIf(&m, "subject_user", d, 1)
		setIf(&m, "new_process_name", d, 5)
		setIf(&m, "process_name", d, 5)
		setIf(&m, "process_id", d, 4)
		setIf(&m, "command_line", d, 8)
		setIf(&m, "parent_process_name", d, 13)
	case 4698:
		// SubjectUserSid, SubjectUserName, SubjectDomainName,
		// SubjectLogonId, TaskName, TaskContent
		setIf(&m, "subject_user", d, 1)
		setIf(&m, "task_name", d, 4)
		setIf(&m, "task_content", d, 5)
	case 4720:
		// SubjectUserSid, SubjectUserName, SubjectDomainName,
		// SubjectLogonId, TargetUserSid, TargetUserName,
		// TargetDomainName, PrivilegeList, SamAccountName,
		// DisplayName, UserPrincipalName, HomeDirectory,
		// HomePath, ScriptPath, ProfilePath, Workstations,
		// HoursOfWork, AllowedToDelegateTo, OldUacValue,
		// NewUacValue, UserAccountControl, UserParameters,
		// SidHistory, LogonHours, DnsHostName, ServicePrincipalName
		setIf(&m, "subject_user", d, 1)
		setIf(&m, "target_user", d, 5)
		setIf(&m, "privilege_list", d, 7)
	case 4732:
		// SubjectUserSid, SubjectUserName, SubjectDomainName,
		// SubjectLogonId, TargetUserSid, TargetUserName,
		// TargetDomainName, TargetSid, GroupName, MemberName,
		// MemberSid, SambaAccountName, SambaDomain, SambaSid
		setIf(&m, "subject_user", d, 1)
		setIf(&m, "target_user", d, 5)
		setIf(&m, "member_name", d, 9)
		setIf(&m, "group_name", d, 8)
	}
	// Normalize: trim surrounding spaces and "-"
	for k, v := range m {
		m[k] = strings.TrimSpace(v)
	}
	return m
}

func setIf(m *map[string]string, key string, d []string, idx int) {
	if idx >= len(d) {
		return
	}
	(*m)[key] = d[idx]
}

// indexNul returns the offset of the first NUL byte in b, or -1
// if no NUL is present. EvtRender pads its output with trailing
// NULs; the XML parser does not need them.
func indexNul(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
