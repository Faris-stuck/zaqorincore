# ZaqorinCore agent — Makefile
#
# Run `make help` for a list of targets.

# ---- Config ----
BINARY      := zaqorin-agent
CMD_PATH    := ./cmd/zaqorin-agent
BUILD_DIR   := ./bin
LDFLAGS     := -s -w -buildid=

# Cross-compile targets (override on the command line, e.g. `make build GOOS=linux GOARCH=arm64`).
GOOS        ?= $(shell go env GOOS)
GOARCH      ?= $(shell go env GOARCH)

# ---- Phony targets ----
.PHONY: all help build test test-race test-cover vet lint clean run smoke tidy fmt

# Default goal.
all: vet test build

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build a static binary into ./bin/$(BINARY).
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -trimpath -ldflags='$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)
	@echo "✓ built $(BUILD_DIR)/$(BINARY)"

test: ## Run unit tests.
	go test -count=1 ./...

test-race: ## Run unit tests with -race.
	go test -race -count=1 ./...

test-cover: ## Run unit tests with coverage report.
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

vet: ## Run go vet.
	go vet ./...

lint: vet ## Alias for vet (placeholder for future golangci-lint).

fmt: ## Run go fmt.
	gofmt -s -w .

tidy: ## Tidy module dependencies.
	go mod tidy

clean: ## Remove build artifacts.
	rm -rf $(BUILD_DIR) coverage.out

run: build ## Build and run with a local config (uses ./agent.toml if present).
	@if [ -f ./agent.toml ]; then \
		./$(BUILD_DIR)/$(BINARY) --config ./agent.toml; \
	else \
		echo "no ./agent.toml found; running with --help"; \
		./$(BUILD_DIR)/$(BINARY) --help; \
	fi

smoke: build ## Run the end-to-end smoke test (requires websocat).
	./scripts/smoke.sh
