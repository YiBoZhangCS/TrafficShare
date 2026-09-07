package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"trafficshare/internal/config"
	"trafficshare/internal/controlserver"
)

func main() {
	configPath := flag.String("config", "", "path to JSON configuration")
	listen := flag.String("listen", "", "override listen address")
	databasePath := flag.String("database", "", "override SQLite database path")
	logPath := flag.String("log", "", "override structured log path")
	tlsCert := flag.String("tls-cert", "", "TLS certificate path")
	tlsKey := flag.String("tls-key", "", "TLS private key path")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	if *listen != "" {
		cfg.Server.Listen = *listen
	}
	if *databasePath != "" {
		cfg.Server.DatabasePath = *databasePath
	}
	if *logPath != "" {
		cfg.Server.LogPath = *logPath
	}
	if *tlsCert != "" || *tlsKey != "" {
		cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath = *tlsCert, *tlsKey
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := controlserver.Run(ctx, cfg); err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
