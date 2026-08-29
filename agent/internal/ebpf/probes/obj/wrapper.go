// Package obj re-exports the bpf2go-generated BPF objects
// so that the rest of the agent (loader.go) can access them
// without depending on bpf2go's per-version naming.
//
// bpf2go v0.16 emits the CollectionSpec bytes plus
// loadZaqorin_probes / loadZaqorin_probesObjects helpers as
// package-private identifiers. We re-export the bytes
// (via MustBytes) and a small typed wrapper that the loader
// uses to call LoadAndAssign with our own exported
// BpfProbes / BpfMaps structs.
//
// IMPORTANT: this file is hand-maintained and must survive
// `make ebpf`, which deletes everything in the obj/ directory
// before regenerating. The Makefile's `clean` target only
// removes *.o and *.go; do NOT add wrapper.go to that glob.
package obj

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// MustBytes returns the embedded BPF ELF as a byte slice.
// The slice is a copy — callers may mutate it freely.
func MustBytes() []byte {
	out := make([]byte, len(_Zaqorin_probesBytes))
	copy(out, _Zaqorin_probesBytes)
	return out
}

// LoadSpec parses the embedded BPF ELF into a CollectionSpec.
// Use this in tests and in the runtime loader; the loader
// then calls CollectionSpec.LoadAndAssign with its own
// BpfProbes / BpfMaps targets.
func LoadSpec() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(MustBytes())
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("bpf: parse CollectionSpec: %w", err)
	}
	return spec, nil
}

// BpfProbes is the post-load view of the BPF programs. Field
// names and ebpf tags must match the symbols in the compiled
// ELF (the bpf2go-generated _Zaqorin_probesProgramSpecs is
// authoritative).
type BpfProbes struct {
	HandleConnect *ebpf.Program `ebpf:"handle_connect"`
	HandleExecve  *ebpf.Program `ebpf:"handle_execve"`
	HandleOpenat  *ebpf.Program `ebpf:"handle_openat"`
	HandlePtrace  *ebpf.Program `ebpf:"handle_ptrace"`
	HandleSetuid  *ebpf.Program `ebpf:"handle_setuid"`
}

// BpfMaps is the post-load view of the BPF maps. Same rules
// as BpfProbes: field names + ebpf tags must match the ELF.
type BpfMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

// BpfObjects bundles programs and maps and implements
// io.Closer for clean teardown.
type BpfObjects struct {
	BpfProbes
	BpfMaps
}

// Close releases every program and map FD. Idempotent.
func (o *BpfObjects) Close() error {
	var firstErr error
	closers := []interface {
		Close() error
	}{
		o.HandleConnect, o.HandleExecve, o.HandleOpenat,
		o.HandlePtrace, o.HandleSetuid,
		o.Events,
	}
	for _, c := range closers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// LoadObjects is a convenience wrapper that combines LoadSpec
// and LoadAndAssign. The caller owns the returned BpfObjects
// and must Close it when done.
//
// This call requires CAP_BPF and a 5.4+ kernel. In a
// non-privileged test environment (CI, dev workstation
// without sudo) the call returns a non-nil error; the
// integration test asserts that error path.
func LoadObjects() (*BpfObjects, error) {
	spec, err := LoadSpec()
	if err != nil {
		return nil, err
	}
	objs := &BpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, fmt.Errorf("bpf: LoadAndAssign: %w", err)
	}
	return objs, nil
}
