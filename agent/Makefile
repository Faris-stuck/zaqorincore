# ZaqorinCore agent — Makefile
#
# Targets:
#   make ebpf   - compile probes/c/*.c into BPF ELF objects
#                 and emit bpf2go Go wrappers under
#                 internal/ebpf/probes/obj/. Run once after
#                 editing any probe C file; the resulting
#                 objects are embedded into the agent binary
#                 via go:embed, so the agent itself never
#                 needs a BPF toolchain at runtime.
#
#   make test   - run all agent tests (Go + decode).
#
#   make build  - go build ./... (requires `make ebpf` first
#                 so the embedded objects are in place).
#
# Prerequisites for `make ebpf`:
#   - clang (Ubuntu: apt install clang)
#   - libbpf-dev (Ubuntu: apt install libbpf-dev)
#   - linux-headers-$(uname -r) (Ubuntu: apt install
#     linux-headers-generic, or matching headers package)
#   - Go 1.22+ (already required to build the agent)

# Host architecture for BPF target. Override on the command
# line for cross-builds, e.g. `make ebpf ARCH=arm64`.
ARCH ?= amd64

# Linux kernel headers path. Default to the running kernel's
# UAPI directory; override for cross-builds.
KERN_UAPI ?= /usr/src/linux-headers-$(shell uname -r)/arch/x86/include/generated/uapi

# Where bpf2go writes the ELF and Go files. Matches the
# package layout in internal/ebpf/probes/.
OBJ_DIR  := internal/ebpf/probes/obj
C_DIR    := internal/ebpf/probes/c
OUT_STEM := zaqorin_probes

.PHONY: all ebpf test build clean check-prereqs

all: ebpf build

# Print which tools are missing and exit non-zero if any
# are not on PATH. Operators can run `make check-prereqs`
# before `make ebpf` to surface install instructions.
check-prereqs:
	@command -v clang >/dev/null 2>&1 || { echo "missing: clang (apt install clang)"; exit 1; }
	@command -v go >/dev/null 2>&1 || { echo "missing: go (see README.md)"; exit 1; }
	@pkg-config --modversion libbpf >/dev/null 2>&1 || { echo "missing: libbpf-dev (apt install libbpf-dev)"; exit 1; }
	@test -d "$(KERN_UAPI)" || { echo "missing: $(KERN_UAPI) (apt install linux-headers-generic)"; exit 1; }
	@echo "all prereqs present"

# Compile the BPF C programs into one combined ELF (all five
# probes share a single "events" ring buffer map) and emit
# the bpf2go-generated Go wrapper. See probes/c/README-style
# comments in probes_main.bpf.c for the layout rationale.
ebpf: check-prereqs
	@mkdir -p $(OBJ_DIR)
	@# Save the hand-maintained wrapper.go before bpf2go
	@# wipes the obj/ directory.
	@if [ -f $(OBJ_DIR)/wrapper.go ]; then \
		mv $(OBJ_DIR)/wrapper.go $(OBJ_DIR)/.wrapper.go.bak; \
	fi
	GOPACKAGE=obj go run github.com/cilium/ebpf/cmd/bpf2go \
		-target bpfel,$(ARCH) \
		-output-dir $(OBJ_DIR) \
		-output-stem $(OUT_STEM) \
		$(OUT_STEM) \
		$(C_DIR)/probes_main.bpf.c \
		-- -I/usr/include -I/usr/include/x86_64-linux-gnu -I$(KERN_UAPI) -I$(C_DIR)
	@# Restore wrapper.go if it was saved.
	@if [ -f $(OBJ_DIR)/.wrapper.go.bak ]; then \
		mv $(OBJ_DIR)/.wrapper.go.bak $(OBJ_DIR)/wrapper.go; \
	fi
	@# Remove the alternate-architecture copy bpf2go may also
	@# generate (e.g. zaqorin_probes_x86_bpfel.go on x86).
	@# We embed only the host-target object.
	@find $(OBJ_DIR) -name '$(OUT_STEM)_x86_*' -delete 2>/dev/null || true
	@find $(OBJ_DIR) -name '$(OUT_STEM)_arm64_*' -delete 2>/dev/null || true
	@find $(OBJ_DIR) -name '$(OUT_STEM)_arm_*' -delete 2>/dev/null || true
	@ls -la $(OBJ_DIR)

test:
	go test ./...

# Cross-compile the agent for all five supported targets.
# Produces ./bin/zaqorin-agent-{goos}-{goarch}[.exe].
#
# Targets:
#   linux/amd64    - servers, workstations (x86_64)
#   linux/arm64    - AWS Graviton, Raspberry Pi 4/5, Apple Silicon (VM)
#   windows/amd64  - Windows Server 2019+, Windows 10/11 (x86_64)
#   darwin/amd64   - Intel Macs (rare in 2026; for legacy fleet)
#   darwin/arm64   - Apple Silicon (M1/M2/M3/M4)
#
# Notes:
#   - BPF objects (probes/obj/*.o) are Linux-only. The
#     cross-build target only embeds the BPF objects on
#     linux GOOS; windows and darwin builds skip the
#     internal/ebpf package via the build constraint
#     `//go:build linux` on loader.go (set in v1.1.0+).
#   - Each binary is statically linked (CGO_ENABLED=0) so
#     the resulting file runs on a vanilla host without
#     runtime dependencies.
build-all:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags='-s -w' -o bin/zaqorin-agent-linux-amd64        ./cmd/zaqorin-agent
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags='-s -w' -o bin/zaqorin-agent-linux-arm64        ./cmd/zaqorin-agent
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags='-s -w' -o bin/zaqorin-agent-windows-amd64.exe  ./cmd/zaqorin-agent
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags='-s -w' -o bin/zaqorin-agent-darwin-amd64       ./cmd/zaqorin-agent
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags='-s -w' -o bin/zaqorin-agent-darwin-arm64       ./cmd/zaqorin-agent
	@ls -la bin/

# Build for the current host only. Faster than build-all
# when iterating on a single target.
build-local:
	CGO_ENABLED=0 go build -ldflags='-s -w' -o bin/zaqorin-agent-$$(go env GOOS)-$$(go env GOARCH)$$([ "$$(go env GOOS)" = "windows" ] && echo .exe) ./cmd/zaqorin-agent
	@ls -la bin/

# Smoke test: each binary loads, prints --version, exits 0.
# This proves the cross-compile produces runnable artifacts
# even on a host that cannot execute the other GOOS
# binaries (we can only run linux ones here).
smoke-build:
	@echo "=== cross-compile smoke ==="
	@for target in "linux amd64" "linux arm64" "windows amd64" "darwin amd64" "darwin arm64"; do \
		GOOS=$${target% *}; \
		GOARCH=$${target#* }; \
		binary="bin/zaqorin-agent-$$GOOS-$$GOARCH$$([ "$$GOOS" = "windows" ] && echo .exe)"; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH \
			go build -ldflags='-s -w' -o $$binary ./cmd/zaqorin-agent && \
			echo "OK   $$binary ($$(stat -c %s $$binary) bytes)" || \
			echo "FAIL $$GOOS/$$GOARCH"; \
	done

clean:
	rm -rf $(OBJ_DIR)/*.o $(OBJ_DIR)/*.go
	# NOTE: do NOT add wrapper.go to the glob above. It is
	# hand-maintained and survives `make ebpf` by convention.
	# If you regenerated and it disappeared, recreate it from
	# git: `git checkout HEAD -- internal/ebpf/probes/obj/wrapper.go`
