package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"trafficshare/internal/agent"
	"trafficshare/internal/elevate"
	"trafficshare/internal/launcher"
	"trafficshare/internal/windowsnet"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) < 2 || os.Args[1] == "host" {
		if relaunched, err := elevate.EnsureAdministrator(); err != nil || relaunched {
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		}
		if err := launcher.Run(ctx, launcher.Mode{Role: "provider", EmbeddedServer: true}); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] != "agent" {
		fmt.Fprintln(os.Stderr, "Usage: TrafficShare [host] | TrafficShare agent <command> [options]")
		os.Exit(2)
	}
	cli := agent.CLI{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, Runner: windowsnet.ExecRunner{}}
	if err := cli.Run(ctx, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
