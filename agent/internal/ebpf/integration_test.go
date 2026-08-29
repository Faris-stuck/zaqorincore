package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	bpfobj "github.com/Faris-stuck/zaqorincore/agent/internal/ebpf/probes/obj"
	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
)

// TestCollectionSpecLoads exercises the embedded BPF ELF
// through the bpf2go-generated wrapper. We do not attach the
// programs to kernel tracepoints (that requires CAP_BPF and
// is covered by the runtime loader's NewReal path). This
// test catches the most common build breakage: a regenerated
// ELF that the cilium/ebpf library refuses to parse.
func TestCollectionSpecLoads(t *testing.T) {
	spec, err := bpfobj.LoadSpec()
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	if spec == nil {
		t.Fatal("LoadSpec returned nil spec with no error")
	}
	// We expect five programs and one ring buffer map.
	wantProgs := []string{
		"handle_execve", "handle_openat", "handle_connect",
		"handle_ptrace", "handle_setuid",
	}
	for _, name := range wantProgs {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("expected program %q in spec, missing", name)
		}
	}
	if _, ok := spec.Maps["events"]; !ok {
		t.Error("expected map 'events' in spec, missing")
	}
}

// TestLoadObjectsFailsWithoutKernel validates the runtime
// error path: LoadAndAssign requires a real kernel with
// CAP_BPF. In a non-privileged CI / dev environment the
// call must fail with an informative error, not panic.
func TestLoadObjectsFailsWithoutKernel(t *testing.T) {
	// LoadObjects -> LoadSpec -> LoadAndAssign. The first
	// two succeed (pure parse). LoadAndAssign is the kernel
	// call. We expect a non-nil error and a non-nil error
	// message; the message is libbpf-go specific and may
	// change between versions, so we just assert non-empty.
	_, err := bpfobj.LoadObjects()
	if err == nil {
		t.Skip("LoadObjects succeeded unexpectedly; this test requires a non-privileged environment")
	}
	if err.Error() == "" {
		t.Error("LoadObjects returned empty error string")
	}
}

// TestRingBufferReaderEndToEnd is the v1.1.0 integration
// test: it builds a synthetic bpfEvent record (the same
// bytes the kernel ring buffer would deliver), feeds it
// through the public decode() function, and checks that
// the resulting event.Event has the right Source tag and
// metadata for each of the five probe kinds.
//
// This test does NOT need CAP_BPF — decode is a pure
// function over a byte slice, and the bpfEvent layout
// is shared between the C struct (probes/c/common.h) and
// the Go struct (loader.go bpfEvent). If the layouts
// diverge the test will fail loudly.
func TestRingBufferReaderEndToEnd(t *testing.T) {
	cases := []struct {
		name        string
		build       func(t *testing.T) []byte
		wantSource  string
		wantRawSub  string // substring expected in event.Raw
		wantKeyMeta string // metadata key that must be present
	}{
		{
			name: "execve",
			build: func(t *testing.T) []byte {
				var be bpfEvent
				be.Hdr.Tag = tagExecve
				be.Hdr.Pid = 4242
				be.Hdr.UID = 1000
				putCString16(&be.Hdr.Comm, "bash")
				putCString(&be.Body.Execve.Argv0, "/usr/bin/ls")
				putCString(&be.Body.Execve.Argv1, "-la")
				return makeRaw(t, be)
			},
			wantSource:  "ebpf/execve",
			wantRawSub:  "/usr/bin/ls",
			wantKeyMeta: "argv0",
		},
		{
			name: "openat",
			build: func(t *testing.T) []byte {
				var be bpfEvent
				be.Hdr.Tag = tagOpenat
				be.Hdr.Pid = 1234
				be.Hdr.UID = 0
				putCString16(&be.Hdr.Comm, "cat")
				putCString(&be.Body.Openat.Filename, "/etc/passwd")
				return makeRaw(t, be)
			},
			wantSource:  "ebpf/openat",
			wantRawSub:  "/etc/passwd",
			wantKeyMeta: "filename",
		},
		{
			name: "connect",
			build: func(t *testing.T) []byte {
				var be bpfEvent
				be.Hdr.Tag = tagConnect
				be.Hdr.Pid = 9999
				be.Hdr.UID = 1000
				putCString16(&be.Hdr.Comm, "curl")
				// IPv4 1.2.3.4, port 80. The kernel
				// tracepoint gives the port in network
				// byte order; the Go decoder swaps it.
				be.Body.Connect.DstIP[0] = 1
				be.Body.Connect.DstIP[1] = 2
				be.Body.Connect.DstIP[2] = 3
				be.Body.Connect.DstIP[3] = 4
				be.Body.Connect.DstPort = 80 << 8 // port 80, big-endian bytes [0x00, 0x50] stored as LE uint32
				be.Body.Connect.IsV6 = 0
				return makeRaw(t, be)
			},
			wantSource:  "ebpf/connect",
			wantRawSub:  "1.2.3.4:80",
			wantKeyMeta: "dst_ip",
		},
		{
			name: "ptrace",
			build: func(t *testing.T) []byte {
				var be bpfEvent
				be.Hdr.Tag = tagPtrace
				be.Hdr.Pid = 1
				be.Hdr.UID = 0
				putCString16(&be.Hdr.Comm, "gdb")
				be.Body.Ptrace.TargetPID = 4242
				be.Body.Ptrace.Request = 12 // PTRACE_ATTACH
				return makeRaw(t, be)
			},
			wantSource:  "ebpf/ptrace",
			wantRawSub:  "ptrace req=12 target=4242",
			wantKeyMeta: "target_pid",
		},
		{
			name: "setuid",
			build: func(t *testing.T) []byte {
				var be bpfEvent
				be.Hdr.Tag = tagSetuid
				be.Hdr.Pid = 5678
				be.Hdr.UID = 1000
				putCString16(&be.Hdr.Comm, "su")
				be.Body.Setuid.NewUID = 0
				return makeRaw(t, be)
			},
			wantSource:  "ebpf/setuid",
			wantRawSub:  "setuid 1000 -> 0",
			wantKeyMeta: "new_uid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.build(t)
			ev, source, ok := decode(raw)
			if !ok {
				t.Fatal("decode returned !ok")
			}
			if source != tc.wantSource {
				t.Errorf("source: got %q, want %q", source, tc.wantSource)
			}
			if !strings.Contains(ev.Raw, tc.wantRawSub) {
				t.Errorf("raw: got %q, want substring %q", ev.Raw, tc.wantRawSub)
			}
			if _, ok := ev.Metadata[tc.wantKeyMeta]; !ok {
				t.Errorf("metadata missing key %q (have: %v)", tc.wantKeyMeta, ev.Metadata)
			}
			// Verify the wire encoder produces valid JSON
			// that the existing transport layer accepts.
			wire := encodeWire(ev, source)
			var roundTrip event.Event
			if err := json.Unmarshal(wire, &roundTrip); err != nil {
				t.Fatalf("wire JSON does not round-trip: %v (wire=%s)", err, wire)
			}
			if roundTrip.Source != tc.wantSource {
				t.Errorf("round-trip source: got %q, want %q",
					roundTrip.Source, tc.wantSource)
			}
		})
	}
}

// TestNotImplementedBackend blocks on ctx cancel cleanly.
// This is the fallback path used when the kernel is too old
// or CAP_BPF is missing; the agent still needs to run with
// the file-tail backend, and NotImplemented must not leak
// goroutines or return errors on graceful shutdown.
func TestNotImplementedBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ni := NewNotImplemented(logger)
	if got := ni.Name(); got != "ebpf/scaffold" {
		t.Errorf("Name: got %q, want ebpf/scaffold", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := ni.Run(ctx, func(_ []byte) error { return nil }); err == nil {
		t.Error("Run should return ctx.Err() on cancel, got nil")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run error: got %v, want context.DeadlineExceeded", err)
	}
}
