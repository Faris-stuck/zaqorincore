// Command zaqorin-agent tails local log files and ships each new line to the central server.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Faris-stuck/zaqorincore/agent/internal/app"
	"github.com/Faris-stuck/zaqorincore/agent/internal/config"
	"github.com/Faris-stuck/zaqorincore/agent/internal/logger"
	"github.com/Faris-stuck/zaqorincore/agent/internal/response"
)

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

	handler, err := response.NewHandler(cfg, log)
	if err != nil {
		log.Error("zaqorin-agent: build response handler failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := handler.LoadSecret(); err != nil {
		log.Warn("zaqorin-agent: host secret not loaded (agent cannot authenticate until set)",
			slog.String("path", cfg.StateDir+"/secret"),
			slog.String("error", err.Error()),
		)
	} else {
		log.Info("zaqorin-agent: host secret loaded", slog.String("path", cfg.StateDir+"/secret"))
		secret, readErr := os.ReadFile(filepath.Join(cfg.StateDir, "secret"))
		if readErr != nil {
			log.Error("zaqorin-agent: failed to load handshake secret", slog.String("error", readErr.Error()))
			os.Exit(1)
		}
		cfg.SharedSecret = strings.TrimSpace(string(secret))
		if cfg.SharedSecret == "" {
			log.Error("zaqorin-agent: handshake secret is empty")
			os.Exit(1)
		}
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
