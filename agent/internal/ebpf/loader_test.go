// Tests for the eBPF loader's event decoder. The BPF
// programs themselves run inside the kernel and are not
// unit-testable in this environment, but the C↔Go struct
// layout and the ring-buffer → wire-event translation are
// pure functions that we can verify here.
//
// These tests also serve as a live spec: if you change the
// C struct in probes/common.h, the assertions below will
// fail until the Go side is updated to match.
package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// makeRaw is the test-only constructor for a bpfEvent record
// as it would arrive from the ring buffer. It builds the
// little-endian byte layout byte-for-byte.
func makeRaw(t *testing.T, ev bpfEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, ev); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func putCString(dst *[256]byte, s string) {
	copy(dst[:], s)
	for i := len(s); i < len(dst); i++ {
		dst[i] = 0
	}
}

func putCString16(dst *[16]byte, s string) {
	copy(dst[:], s)
	for i := len(s); i < len(dst); i++ {
		dst[i] = 0
	}
}

func TestDecodeExecve(t *testing.T) {
	SetHostID("host-A")
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: tagExecve, Pid: 4242, UID: 0, Pad: 0}}
	putCString16(&ev.Hdr.Comm, "bash")
	putCString(&ev.Body.Execve.Argv0, "/bin/sh")
	putCString(&ev.Body.Execve.Argv1, "-c")
	putCString(&ev.Body.Execve.Argv2, "id")
	putCString(&ev.Body.Execve.Argv3, "")
	raw := makeRaw(t, ev)

	got, src, ok := decode(raw)
	if !ok {
		t.Fatal("decode execve: ok=false")
	}
	if src != "ebpf/execve" {
		t.Errorf("source = %q, want ebpf/execve", src)
	}
	if got.Metadata["pid"] != "4242" {
		t.Errorf("pid = %q, want 4242", got.Metadata["pid"])
	}
	if got.Metadata["uid"] != "0" {
		t.Errorf("uid = %q, want 0", got.Metadata["uid"])
	}
	if got.Metadata["comm"] != "bash" {
		t.Errorf("comm = %q, want bash", got.Metadata["comm"])
	}
	if got.Metadata["argv0"] != "/bin/sh" {
		t.Errorf("argv0 = %q, want /bin/sh", got.Metadata["argv0"])
	}
	if got.Metadata["argv1"] != "-c" {
		t.Errorf("argv1 = %q, want -c", got.Metadata["argv1"])
	}
	if got.Metadata["argv2"] != "id" {
		t.Errorf("argv2 = %q, want id", got.Metadata["argv2"])
	}
}

func TestDecodeOpenat(t *testing.T) {
	SetHostID("host-B")
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: tagOpenat, Pid: 99, UID: 1000}}
	putCString16(&ev.Hdr.Comm, "ssh")
	putCString(&ev.Body.Openat.Filename, "/home/alice/.ssh/id_rsa")
	raw := makeRaw(t, ev)

	got, src, ok := decode(raw)
	if !ok {
		t.Fatal("decode openat: ok=false")
	}
	if src != "ebpf/openat" {
		t.Errorf("source = %q, want ebpf/openat", src)
	}
	if got.Metadata["filename"] != "/home/alice/.ssh/id_rsa" {
		t.Errorf("filename = %q", got.Metadata["filename"])
	}
	if got.Metadata["uid"] != "1000" {
		t.Errorf("uid = %q, want 1000", got.Metadata["uid"])
	}
}

func TestDecodeConnectV4(t *testing.T) {
	SetHostID("host-C")
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: tagConnect, Pid: 12, UID: 0}}
	putCString16(&ev.Hdr.Comm, "nc")
	// 1.2.3.4 in network byte order in the first 4 bytes.
	ip := net.ParseIP("1.2.3.4").To4()
	copy(ev.Body.Connect.DstIP[:], ip)
	ev.Body.Connect.DstPort = 0x1500 // host port 21 in network order
	ev.Body.Connect.IsV6 = 0
	raw := makeRaw(t, ev)

	got, src, ok := decode(raw)
	if !ok {
		t.Fatal("decode connect v4: ok=false")
	}
	if src != "ebpf/connect" {
		t.Errorf("source = %q, want ebpf/connect", src)
	}
	if got.Metadata["dst_ip"] != "1.2.3.4" {
		t.Errorf("dst_ip = %q", got.Metadata["dst_ip"])
	}
	if got.Metadata["dst_port"] != "21" {
		t.Errorf("dst_port = %q, want 21", got.Metadata["dst_port"])
	}
}

func TestDecodeConnectV6(t *testing.T) {
	SetHostID("host-D")
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: tagConnect, Pid: 13, UID: 1000}}
	putCString16(&ev.Hdr.Comm, "curl")
	ip := net.ParseIP("2001:db8::1").To16()
	copy(ev.Body.Connect.DstIP[:], ip)
	ev.Body.Connect.DstPort = 0x901f // host port 8080 in network order
	ev.Body.Connect.IsV6 = 1
	raw := makeRaw(t, ev)

	got, _, ok := decode(raw)
	if !ok {
		t.Fatal("decode connect v6: ok=false")
	}
	want := "2001:db8::1"
	if got.Metadata["dst_ip"] != want {
		t.Errorf("dst_ip = %q, want %q", got.Metadata["dst_ip"], want)
	}
	if got.Metadata["dst_port"] != "8080" {
		t.Errorf("dst_port = %q, want 8080", got.Metadata["dst_port"])
	}
}

func TestDecodePtrace(t *testing.T) {
	SetHostID("host-E")
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: tagPtrace, Pid: 50, UID: 0}}
	putCString16(&ev.Hdr.Comm, "gdb")
	ev.Body.Ptrace.Request = 12 // PTRACE_ATTACH
	ev.Body.Ptrace.TargetPID = 1234
	raw := makeRaw(t, ev)

	got, src, ok := decode(raw)
	if !ok {
		t.Fatal("decode ptrace: ok=false")
	}
	if src != "ebpf/ptrace" {
		t.Errorf("source = %q, want ebpf/ptrace", src)
	}
	if got.Metadata["target_pid"] != "1234" {
		t.Errorf("target_pid = %q, want 1234", got.Metadata["target_pid"])
	}
	if got.Metadata["request"] != "12" {
		t.Errorf("request = %q, want 12", got.Metadata["request"])
	}
}

func TestDecodeSetuid(t *testing.T) {
	SetHostID("host-F")
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: tagSetuid, Pid: 60, UID: 1000}}
	putCString16(&ev.Hdr.Comm, "su")
	ev.Body.Setuid.NewUID = 0
	raw := makeRaw(t, ev)

	got, src, ok := decode(raw)
	if !ok {
		t.Fatal("decode setuid: ok=false")
	}
	if src != "ebpf/setuid" {
		t.Errorf("source = %q, want ebpf/setuid", src)
	}
	if got.Metadata["uid"] != "1000" {
		t.Errorf("uid = %q, want 1000", got.Metadata["uid"])
	}
	if got.Metadata["new_uid"] != "0" {
		t.Errorf("new_uid = %q, want 0", got.Metadata["new_uid"])
	}
}

func TestDecodeRejectsUnknownTag(t *testing.T) {
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: 0xdeadbeef}}
	raw := makeRaw(t, ev)
	if _, _, ok := decode(raw); ok {
		t.Fatal("decode with unknown tag should return ok=false")
	}
}

func TestEncodeWireShape(t *testing.T) {
	SetHostID("host-G")
	ev := bpfEvent{Hdr: bpfEventHdr{Tag: tagExecve, Pid: 1, UID: 0}}
	putCString16(&ev.Hdr.Comm, "sh")
	putCString(&ev.Body.Execve.Argv0, "/bin/sh")
	raw := makeRaw(t, ev)
	got, _, _ := decode(raw)
	wire := encodeWire(got, "ebpf/execve")
	s := string(wire)
	for _, want := range []string{
		`"source":"ebpf/execve"`,
		`"comm":"sh"`,
		`"argv0":"/bin/sh"`,
		`"pid":"1"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("wire json missing %s\nfull: %s", want, s)
		}
	}
}

func TestCStrTrimsAtNul(t *testing.T) {
	b := make([]byte, 16)
	copy(b, "abc")
	// b[3] is already 0
	if got := cStr(b); got != "abc" {
		t.Errorf("cStr = %q, want abc", got)
	}
}
