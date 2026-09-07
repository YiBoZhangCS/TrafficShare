package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"trafficshare/internal/elevate"
	"trafficshare/internal/launcher"
	"trafficshare/internal/notify"
)

func main() {
	if relaunched, err := elevate.EnsureAdministrator(); err != nil || relaunched {
		if err != nil {
			notify.Error(err.Error())
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := launcher.Run(ctx, launcher.Mode{Role: "provider"}); err != nil {
		notify.Error(err.Error())
		os.Exit(1)
	}
}
