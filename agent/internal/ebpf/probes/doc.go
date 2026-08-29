// Package probes holds the eBPF programs compiled by bpf2go.
//
// The actual SEC() functions live in probes_main.bpf.c (which
// #includes the per-syscall monitor files). bpf2go generates
// a typed Programs struct exposing one method per SEC() —
// HandleExecve, HandleOpenat, HandleConnect, HandlePtrace,
// HandleSetuid. The Go loader calls each one in turn to attach
// it to its kernel tracepoint.
//
// Regenerate the embedded .o via `make ebpf` (agent/Makefile).
// The Makefile target invokes bpf2go via `go run` since bpf2go
// is a Go program, not a standalone binary.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,amd64 -output-dir ./obj -output-stem zaqorin_probes ./c/probes_main.bpf.c
package probes
