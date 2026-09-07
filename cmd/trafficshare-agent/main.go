package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"trafficshare/internal/agent"
	"trafficshare/internal/windowsnet"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cli := agent.CLI{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, Runner: windowsnet.ExecRunner{}}
	if err := cli.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
