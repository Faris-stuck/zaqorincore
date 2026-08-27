// Command zaqorin-agent tails local log files and ships each new
// line to the central server over WebSocket. Phase 1 ships transport
// only — no detection, no auto-response.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Faris-stuck/zaqorincore/agent/internal/app"
	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/logger"
)

func main() {
	cfgPath := flag.String("config", "/etc/zaqorin/agent.toml", "path to the agent TOML config file")
	formatStr := flag.String("log-format", "json", "log output format: json or text")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zaqorin-agent: %v\n", err)
		os.Exit(1)
	}

	// Resolve the agent's stable identity: either the operator-pinned
	// UUID in the config, or a fresh UUID v4 persisted in state_dir.
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

	// Root context, cancelled on SIGINT/SIGTERM. We use a buffered
	// channel so a misbehaving signal handler cannot drop a signal.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := app.Run(ctx, app.Dependencies{
		Config: cfg,
		Logger: log,
	}); err != nil {
		log.Error("zaqorin-agent: run failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
