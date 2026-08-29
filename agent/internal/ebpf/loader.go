// Package ebpf holds the eBPF kernel-telemetry backend for the
// ZaqorinCore agent (v1.1.0, see ADR-006).
//
// This file is the RUNTIME loader. It is NOT build-tagged:
// the bpf2go-generated Go file (probes/obj/zaqorin_probes_bpfel.go)
// embeds the compiled BPF ELF as []byte, so a plain `go build`
// succeeds with no toolchain on the host. The kernel check in
// NewReal handles the "no BPF available at runtime" case
// (older kernel, no CAP_BPF, no objects, etc.) by returning
// (nil, reason) and letting NewBackend fall back to the
// NotImplemented stub in ebpf.go.
//
// The BPF programs themselves live in ./probes/c/*.c. They
// are compiled to ELF objects via `make ebpf` which invokes
// bpf2go from cilium/ebpf/cmd/bpf2go. The generated objects
// are placed at ./probes/obj/ and embedded in the Go binary
// by bpf2go's _Zaqorin_probesBytes blob.
//
// Runtime fallback chain (Availability):
//
//  1. kernel >= 5.4 AND CAP_BPF AND embedded objects present
//     AND bpf() syscall succeeds → real probes
//  2. otherwise → NotImplemented stub (logs once, returns)
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
	bpfobj "github.com/Faris-stuck/zaqorincore/agent/internal/ebpf/probes/obj"
)

// bpfEvent mirrors the C struct in probes/common.h byte-for-byte.
// The Go binary.Read decoder depends on this layout being
// unchanged; if you change a field, change the C struct too.
type bpfEvent struct {
	Hdr  bpfEventHdr
	Body bpfEventBody
}

type bpfEventHdr struct {
	Tag  uint32
	Pid  uint32
	UID  uint32
	Pad  uint32
	Comm [16]byte
}

type bpfEventBody struct {
	Execve  execveBody
	Openat  openatBody
	Connect connectBody
	Ptrace  ptraceBody
	Setuid  setuidBody
}

type execveBody struct {
	Argv0 [256]byte
	Argv1 [256]byte
	Argv2 [256]byte
	Argv3 [256]byte
}

type openatBody struct {
	Filename [256]byte
}

type connectBody struct {
	DstIP   [16]byte
	DstPort uint32
	IsV6    uint8
	_       [3]byte
}

type ptraceBody struct {
	TargetPID uint32
	Request   uint32
}

type setuidBody struct {
	NewUID uint32
}

// Tag constants must match probes/common.h.
const (
	tagExecve  = 0x78656500
	tagOpenat  = 0x786f6600
	tagConnect = 0x78636e00
	tagPtrace  = 0x78707400
	tagSetuid  = 0x78737500
)

// probeSpec is one BPF program in the single combined
// CollectionSpec. We load one Collection (from
// loadZaqorin_probes) that contains all five programs and
// the shared "events" ring buffer. Each program attaches to
// its tracepoint independently.
type probeSpec struct {
	Name      string // "execve", "openat", ...
	SourceTag string // wire source suffix: "ebpf/execve"
	ProgName  string // bpf2go-generated Programs field name
	Category  string // tracepoint category
	EventName string // tracepoint event
}

// allProbes lists the five BPF programs shipped in v1.1.0.
// Order matches ADR-006.
var allProbes = []probeSpec{
	{
		Name: "execve", SourceTag: "ebpf/execve",
		ProgName:  "HandleExecve",
		Category:  "syscalls", EventName: "sys_enter_execve",
	},
	{
		Name: "openat", SourceTag: "ebpf/openat",
		ProgName:  "HandleOpenat",
		Category:  "syscalls", EventName: "sys_enter_openat",
	},
	{
		Name: "connect", SourceTag: "ebpf/connect",
		ProgName:  "HandleConnect",
		Category:  "syscalls", EventName: "sys_enter_connect",
	},
	{
		Name: "ptrace", SourceTag: "ebpf/ptrace",
		ProgName:  "HandlePtrace",
		Category:  "syscalls", EventName: "sys_enter_ptrace",
	},
	{
		Name: "setuid", SourceTag: "ebpf/setuid",
		ProgName:  "HandleSetuid",
		Category:  "syscalls", EventName: "sys_enter_setuid",
	},
}

// LoadConfig configures the loader. The zero value is OK and
// will load all five probes with the default ring buffer size.
type LoadConfig struct {
	// Probes is the set of probe names to load. Empty = all
	// (the v1.1.0 default). Operators can disable individual
	// probes by listing the others.
	Probes []string

	// RingBufferBytes is the size of the shared ring buffer.
	// Zero = 256 KiB (the ADR-006 default). Currently
	// informational only; the actual size is set at compile
	// time via __uint(max_entries, ...) in probes_main.bpf.c.
	RingBufferBytes int

	// AgentID is the host identifier used in every event.
	AgentID string
}

// LoadResult tells the agent caller what was successfully
// loaded. If the BPF backend is unavailable, Loaded is empty
// and the agent should fall back to the file-tail backend.
type LoadResult struct {
	Loaded []string // probe names successfully attached
	Reason string   // human-readable reason if Loaded is empty
}

// Real is the working BPF backend. It owns the loaded
// collection, the per-probe links, and the ring buffer reader.
type Real struct {
	logger  *slog.Logger
	cfg     LoadConfig
	hostID  string
	objs    *bpfobj.BpfObjects
	links   []link.Link
	reader  *ringbuf.Reader
	dropped atomic.Uint64
}

// NewReal attempts to build the BPF backend according to cfg.
// If the kernel is too old, CAP_BPF is missing, or the
// embedded objects cannot be loaded, it returns (nil, reason).
// Callers should fall back to NewNotImplemented() in that case.
func NewReal(logger *slog.Logger, cfg LoadConfig) (*Real, string) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Sprintf("ebpf: not linux (GOOS=%s)", runtime.GOOS)
	}
	major, minor, err := kernelVersion()
	if err != nil {
		return nil, fmt.Sprintf("ebpf: cannot read /proc/version: %v", err)
	}
	if major < 5 || (major == 5 && minor < 4) {
		return nil, fmt.Sprintf("ebpf: kernel %d.%d < 5.4", major, minor)
	}
	// Remove the rlimit on locked memory so BPF maps can
	// allocate. Best-effort; some kernels ignore it.
	if err := rlimit.RemoveMemlock(); err != nil {
		// Not fatal; some kernels permit the load anyway.
		logger.Warn("ebpf: remove memlock rlimit failed",
			slog.String("error", err.Error()))
	}

	objs, err := bpfobj.LoadObjects()
	if err != nil {
		return nil, fmt.Sprintf("ebpf: loadAndAssign: %v", err)
	}

	// Resolve which probes to attach.
	probesToLoad := allProbes
	if len(cfg.Probes) > 0 {
		probesToLoad = nil
		for _, p := range allProbes {
			for _, want := range cfg.Probes {
				if p.Name == want {
					probesToLoad = append(probesToLoad, p)
				}
			}
		}
	}
	if len(probesToLoad) == 0 {
		objs.Close()
		return nil, "ebpf: no probes selected (empty cfg.Probes filter)"
	}

	r := &Real{
		logger: logger, cfg: cfg, hostID: cfg.AgentID,
		objs: objs,
	}
	rd, rderr := ringbuf.NewReader(objs.Events)
	if rderr != nil {
		objs.Close()
		return nil, fmt.Sprintf("ebpf: open ringbuf: %v", rderr)
	}
	r.reader = rd

	for _, p := range probesToLoad {
		prog := lookupProgram(objs, p.ProgName)
		if prog == nil {
			cleanup(r)
			return nil, fmt.Sprintf("ebpf: program %q not in collection", p.ProgName)
		}
		l, lerr := link.Tracepoint(p.Category, p.EventName, prog, nil)
		if lerr != nil {
			cleanup(r)
			return nil, fmt.Sprintf("ebpf: attach %s: %v", p.Name, lerr)
		}
		r.links = append(r.links, l)
		logger.Info("ebpf: probe attached",
			slog.String("probe", p.Name),
			slog.String("source", p.SourceTag),
		)
	}
	return r, ""
}

// lookupProgram returns the cilium/ebpf Program with the
// given name from the loaded objects struct. Returns nil if
// the symbol was not present in the compiled object (e.g.
// the program was excluded by the C preprocessor).
func lookupProgram(objs *bpfobj.BpfObjects, name string) *ebpf.Program {
	switch name {
	case "HandleExecve":
		return objs.HandleExecve
	case "HandleOpenat":
		return objs.HandleOpenat
	case "HandleConnect":
		return objs.HandleConnect
	case "HandlePtrace":
		return objs.HandlePtrace
	case "HandleSetuid":
		return objs.HandleSetuid
	default:
		return nil
	}
}

// Name implements Backend.
func (r *Real) Name() string { return "ebpf" }

// Run implements Backend. It blocks until ctx is canceled,
// reading records from the shared ring buffer and converting
// each to a wire Event delivered to handler. The handler is
// expected to be the existing app dispatcher (it accepts a
// pre-built event.Event — Run calls handler with the
// JSON-serialised wire bytes per the Backend interface).
func (r *Real) Run(ctx context.Context, handler func(event []byte) error) error {
	defer cleanup(r)
	r.logger.Info("ebpf: runtime started",
		slog.Int("probes", len(r.links)))
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("ebpf: shutdown signal received")
			return ctx.Err()
		default:
		}
		rec, err := r.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// ringbuf.ErrClosed means cleanup ran.
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			r.logger.Warn("ebpf: ringbuf read",
				slog.String("error", err.Error()))
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Copy the raw record bytes because ringbuf reuses
		// the underlying buffer on the next Read.
		raw := make([]byte, len(rec.RawSample))
		copy(raw, rec.RawSample)
		if len(raw) < 32 {
			continue
		}
		ev, source, ok := decode(raw)
		if !ok {
			continue
		}
		wire := encodeWire(ev, source)
		if err := handler(wire); err != nil {
			r.logger.Debug("ebpf: handler error",
				slog.String("error", err.Error()))
		}
	}
}

func cleanup(r *Real) {
	if r.reader != nil {
		_ = r.reader.Close()
	}
	for _, l := range r.links {
		_ = l.Close()
	}
	if r.objs != nil {
		r.objs.Close()
	}
}

// decode parses a raw ring buffer record into a decoded
// in-memory event. Returns (event, source-tag, ok).
func decode(raw []byte) (event.Event, string, bool) {
	var be bpfEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &be); err != nil {
		return event.Event{}, "", false
	}
	e := event.New(
		currentHostID(), // filled at construction; see below
		"",
		"",
	)
	e.Metadata = map[string]string{}
	switch be.Hdr.Tag {
	case tagExecve:
		e.Source = "ebpf/execve"
		e.Raw = cStr(be.Body.Execve.Argv0[:])
		e.Metadata["pid"] = strconv.FormatUint(uint64(be.Hdr.Pid), 10)
		e.Metadata["uid"] = strconv.FormatUint(uint64(be.Hdr.UID), 10)
		e.Metadata["comm"] = cStr(be.Hdr.Comm[:])
		e.Metadata["argv0"] = cStr(be.Body.Execve.Argv0[:])
		e.Metadata["argv1"] = cStr(be.Body.Execve.Argv1[:])
		e.Metadata["argv2"] = cStr(be.Body.Execve.Argv2[:])
		e.Metadata["argv3"] = cStr(be.Body.Execve.Argv3[:])
	case tagOpenat:
		e.Source = "ebpf/openat"
		fn := cStr(be.Body.Openat.Filename[:])
		e.Raw = fn
		e.Metadata["pid"] = strconv.FormatUint(uint64(be.Hdr.Pid), 10)
		e.Metadata["uid"] = strconv.FormatUint(uint64(be.Hdr.UID), 10)
		e.Metadata["comm"] = cStr(be.Hdr.Comm[:])
		e.Metadata["filename"] = fn
	case tagConnect:
		e.Source = "ebpf/connect"
		port := be.Body.Connect.DstPort
		// Ports are stored in network byte order by
		// the kernel tracepoint; convert to host.
		hostPort := (port>>8)&0xff | (port&0xff)<<8
		var ip string
		if be.Body.Connect.IsV6 == 0 {
			ip = net.IP(be.Body.Connect.DstIP[:4]).String()
		} else {
			ip = net.IP(be.Body.Connect.DstIP[:16]).String()
		}
		e.Raw = fmt.Sprintf("%s:%d", ip, hostPort)
		e.Metadata["pid"] = strconv.FormatUint(uint64(be.Hdr.Pid), 10)
		e.Metadata["uid"] = strconv.FormatUint(uint64(be.Hdr.UID), 10)
		e.Metadata["comm"] = cStr(be.Hdr.Comm[:])
		e.Metadata["dst_ip"] = ip
		e.Metadata["dst_port"] = strconv.Itoa(int(hostPort))
	case tagPtrace:
		e.Source = "ebpf/ptrace"
		e.Raw = fmt.Sprintf("ptrace req=%d target=%d",
			be.Body.Ptrace.Request, be.Body.Ptrace.TargetPID)
		e.Metadata["pid"] = strconv.FormatUint(uint64(be.Hdr.Pid), 10)
		e.Metadata["uid"] = strconv.FormatUint(uint64(be.Hdr.UID), 10)
		e.Metadata["comm"] = cStr(be.Hdr.Comm[:])
		e.Metadata["target_pid"] = strconv.FormatUint(uint64(be.Body.Ptrace.TargetPID), 10)
		e.Metadata["request"] = strconv.FormatUint(uint64(be.Body.Ptrace.Request), 10)
	case tagSetuid:
		e.Source = "ebpf/setuid"
		e.Raw = fmt.Sprintf("setuid %d -> %d", be.Hdr.UID, be.Body.Setuid.NewUID)
		e.Metadata["pid"] = strconv.FormatUint(uint64(be.Hdr.Pid), 10)
		e.Metadata["uid"] = strconv.FormatUint(uint64(be.Hdr.UID), 10)
		e.Metadata["comm"] = cStr(be.Hdr.Comm[:])
		e.Metadata["new_uid"] = strconv.FormatUint(uint64(be.Body.Setuid.NewUID), 10)
	default:
		return event.Event{}, "", false
	}
	return e, e.Source, true
}

// cStr turns a C-style NUL-terminated byte buffer into a Go
// string, trimming the terminator. We DO NOT trim by null in
// the middle of the string — pass through verbatim except for
// the final NUL.
func cStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// hostID is the agent's stable identifier, looked up at
// runtime via ResolveAgentID; it is set once when the loader
// is constructed. Tests may override it via loadHostID.
var (
	hostIDMu sync.RWMutex
	hostID   = "unset"
)

func currentHostID() string {
	hostIDMu.RLock()
	defer hostIDMu.RUnlock()
	return hostID
}

// SetHostID is called by app.Run before Run() to install the
// agent's resolved host ID. Exported because app is in a
// different package.
func SetHostID(id string) {
	hostIDMu.Lock()
	defer hostIDMu.Unlock()
	hostID = id
}

// encodeWire marshals an event to its on-wire JSON form, the
// same shape the file-tail path produces. This is what the
// existing transport.Send accepts, so the BPF backend is a
// drop-in replacement that requires no server changes.
func encodeWire(e event.Event, _ string) []byte {
	if e.Metadata == nil {
		e.Metadata = map[string]string{}
	}
	out, err := json.Marshal(e)
	if err != nil {
		return []byte("{}")
	}
	return out
}

// kernelVersion parses /proc/version to extract the kernel
// major.minor version. Example line:
//
//	Linux version 5.15.0-91-generic (buildd@lcy02-amd64-038) ...
func kernelVersion() (int, int, error) {
	data, err := readFileOS("/proc/version")
	if err != nil {
		return 0, 0, err
	}
	return parseKernelVersion(string(data))
}

// readFileOS is split out so tests can supply a fixture
// without touching the real /proc.
func readFileOS(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func parseKernelVersion(s string) (int, int, error) {
	// "Linux version 6.8.0-110-generic (...)"
	idx := strings.Index(s, "version ")
	if idx < 0 {
		return 0, 0, fmt.Errorf("no 'version' in: %s", strings.TrimSpace(s))
	}
	rest := s[idx+len("version "):]
	// Parse "MAJOR.MINOR..." (skip patch + suffix).
	dot := strings.Index(rest, ".")
	if dot < 0 {
		return 0, 0, fmt.Errorf("no '.' in: %s", rest)
	}
	major, err1 := strconv.Atoi(rest[:dot])
	minor := 0
	minorStr := rest[dot+1:]
	for i := 0; i < len(minorStr); i++ {
		if minorStr[i] < '0' || minorStr[i] > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	if minorStr != "" {
		minor, err1 = strconv.Atoi(minorStr)
	}
	if err1 != nil {
		return 0, 0, err1
	}
	return major, minor, nil
}
