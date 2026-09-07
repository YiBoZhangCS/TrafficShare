package launcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"trafficshare/internal/agent"
	"trafficshare/internal/config"
	"trafficshare/internal/controlserver"
	"trafficshare/internal/windowsnet"
)

type Mode struct {
	Role           string
	EmbeddedServer bool
}

func Run(ctx context.Context, mode Mode) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if mode.Role != "provider" && mode.Role != "consumer" {
		return fmt.Errorf("unsupported launcher role %q", mode.Role)
	}
	configPath := config.DefaultAgentConfigPath(mode.Role)
	_, statErr := os.Stat(configPath)
	cfg, err := config.LoadIfExists(configPath)
	if err != nil {
		return err
	}
	if os.IsNotExist(statErr) {
		applyFirstRunDefaults(&cfg, mode.Role)
	}
	cfg.Agent.Role = mode.Role
	if mode.EmbeddedServer {
		cfg.Server.Listen = "0.0.0.0:8787"
		cfg.Agent.ServerURL = "http://127.0.0.1:8787"
	}
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	if mode.EmbeddedServer {
		if err := ensureControlServer(runCtx, cfg); err != nil {
			return err
		}
	}
	args := []string{"ui", "--config", configPath, "--role", mode.Role, "--desktop"}
	if mode.EmbeddedServer {
		args = append(args, "--server-url", cfg.Agent.ServerURL, "--embedded-server")
	}
	cli := agent.CLI{Stdout: io.Discard, Stderr: io.Discard, Stdin: os.Stdin, Runner: windowsnet.ExecRunner{}}
	return cli.Run(runCtx, args)
}

func applyFirstRunDefaults(cfg *config.Config, role string) {
	root := config.ProgramDataDir()
	cfg.Agent.Role = role
	cfg.Agent.StateDir = filepath.Join(root, "state", role)
	cfg.Agent.LogPath = filepath.Join(root, "logs", role+".jsonl")
	cfg.Agent.KeyPath = filepath.Join(root, "keys", role+".key")
	if role == "provider" {
		cfg.Agent.UIListen = "127.0.0.1:9080"
	} else {
		cfg.Agent.UIListen = "127.0.0.1:9081"
	}
}

func ensureControlServer(ctx context.Context, cfg config.Config) error {
	if healthy(cfg.Agent.ServerURL) {
		return nil
	}
	errCh := make(chan error, 1)
	go func() { errCh <- controlserver.Run(ctx, cfg) }()
	deadline := time.NewTimer(8 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case err := <-errCh:
			return err
		case <-ticker.C:
			if healthy(cfg.Agent.ServerURL) {
				return nil
			}
		case <-deadline.C:
			return fmt.Errorf("embedded control server did not become ready")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func healthy(baseURL string) bool {
	client := http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get(baseURL + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
