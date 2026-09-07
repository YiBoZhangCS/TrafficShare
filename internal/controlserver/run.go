package controlserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trafficshare/internal/api"
	"trafficshare/internal/auth"
	"trafficshare/internal/config"
	"trafficshare/internal/database"
	"trafficshare/internal/logging"
)

// Run starts the reusable control plane used by both the local Host and cloud server.
func Run(ctx context.Context, cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Server.DatabasePath), 0o700); err != nil {
		return err
	}
	db, err := database.Open(cfg.Server.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	logger, err := logging.New("server", cfg.Server.LogPath)
	if err != nil {
		return err
	}
	defer logger.Close()
	repo := database.Repository{DB: db}
	server := &api.Server{Repo: repo, Auth: auth.Service{Repo: repo, TokenTTL: cfg.Server.TokenTTL}, HeartbeatTTL: cfg.Server.HeartbeatTTL, Tunnel: cfg.Tunnel}
	go sweep(ctx, server, logger)
	protocol := "http"
	if cfg.Server.TLSCertPath != "" {
		protocol = "https"
	}
	logger.Info("", "control server started", "listen", cfg.Server.Listen, "protocol", protocol)
	if err := api.ListenAndServeTLS(ctx, cfg.Server.Listen, server.Handler(), cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath); err != nil {
		return fmt.Errorf("run control server: %w", err)
	}
	return nil
}

func sweep(ctx context.Context, server *api.Server, logger *logging.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := server.Sweep(ctx); err != nil {
				logger.Error("", "sweeper failed", err)
			}
		}
	}
}
