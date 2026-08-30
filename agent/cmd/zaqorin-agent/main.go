// Command zaqorin-agent tails local log files and ships each new
// line to the central server over WebSocket.
//
// Phase 4: also accepts signed COMMAND frames and applies them via
// the response package. Each host has a shared secret persisted at
// cfg.StateDir + "/secret" — without it, commands are refused.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Faris-stuck/zaqorincore/agent/internal/app"
	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/logger"
	"github.com/Faris-stuck/zaqorincore/agent/internal/response"
)

// version is the agent's semver string. The default "dev" is
// overridden at build time via:
//
//	go build -ldflags "-X main.version=vX.Y.Z" ./cmd/zaqorin-agent
//
// Leaving it at "dev" in source keeps local `go run` and tests
// useful while CI can stamp real release numbers.
var version = "dev"

const usage = `zaqorin-agent — Cyber Sentinel log tail + auto-response daemon

Usage:
  zaqorin-agent [flags]

Flags:
  --config <path>     path to the agent TOML config (default /etc/zaqorin/agent.toml)
  --log-format <fmt>  log output format: json or text (default json)
  --version           print version and exit
  --help              print this help and exit
`

// printVersion writes the agent name + version (overridable at
// build time via -ldflags "-X main.version=vX.Y.Z") to w followed
// by a newline. Exposed as a helper so main_test.go can assert the
// format without invoking main().
func printVersion(w io.Writer) {
	fmt.Fprintf(w, "zaqorin-agent %s\n", version)
}

func main() {
	cfgPath := flag.String("config", "/etc/zaqorin/agent.toml", "path to the agent TOML config file")
	formatStr := flag.String("log-format", "json", "log output format: json or text")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *showVersion {
		printVersion(os.Stdout)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zaqorin-agent: %v\n", err)
		os.Exit(1)
	}

	agentID, generated, err := config.ResolveAgentID(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zaqorin-agent: resolve agent_id: %v\n", err)
		os.Exit(1)
	}
	cfg.AgentID = agentID

	var format logger.Format
	switch *formatStr {
	case "text":
		format = logger.FormatText
	case "json", "":
		format = logger.FormatJSON
	default:
		fmt.Fprintf(os.Stderr, "zaqorin-agent: unknown log format %q, defaulting to json\n", *formatStr)
		format = logger.FormatJSON
	}
	log, warn := logger.NewWithWarning(cfg.LogLevel, os.Stderr, format)
	if warn != nil {
		log.Warn("zaqorin-agent: bad log_level in config", slog.String("error", warn.Error()))
	}
	if generated {
		log.Info("zaqorin-agent: generated new agent_id", slog.String("agent_id", agentID))
	} else {
		log.Info("zaqorin-agent: using existing agent_id", slog.String("agent_id", agentID))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Phase 4: build the response handler. The handler loads its
	// secret from cfg.StateDir + "/secret" at startup. If the
	// file is missing, the handler still starts but every
	// command will be refused.
	//
	// Operator bootstraps the secret by:
	//   1. server: PATCH /api/v1/hosts/{agent_id} (the server
	//      returns the secret in the response body)
	//   2. drop the secret at cfg.StateDir/secret (mode 0600)
	handler, err := response.NewHandler(cfg, log)
	if err != nil {
		log.Error("zaqorin-agent: build response handler failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := handler.LoadSecret(); err != nil {
		log.Warn("zaqorin-agent: host secret not loaded (auto-block disabled until set)",
			slog.String("path", cfg.StateDir+"/secret"),
			slog.String("error", err.Error()),
		)
	} else {
		log.Info("zaqorin-agent: host secret loaded", slog.String("path", cfg.StateDir+"/secret"))
	}

	cmdHandler := func(ctx context.Context, cmd app.Command) (string, error) {
		return handler.Handle(ctx, response.Command{
			ID:       cmd.ID,
			Kind:     cmd.Kind,
			Target:   cmd.Target,
			TTLSec:   cmd.TTLSec,
			IssuedAt: cmd.IssuedAt,
			HMAC:     cmd.HMAC,
		})
	}

	if err := app.Run(ctx, app.Dependencies{
		Config:         cfg,
		Logger:         log,
		CommandHandler: cmdHandler,
	}); err != nil {
		log.Error("zaqorin-agent: run failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
