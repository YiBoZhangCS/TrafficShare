package windowsnet

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"trafficshare/internal/logging"
)

type Result struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
}

type CommandRunner interface {
	Run(ctx context.Context, program string, args ...string) (Result, error)
}

type ExecRunner struct {
	Logger *logging.Logger
}

func (r ExecRunner) Run(ctx context.Context, program string, args ...string) (Result, error) {
	logger := r.Logger
	if logger == nil {
		logger, _ = logging.New("windowsnet", "")
	}
	start := time.Now()
	cmd := exec.CommandContext(ctx, program, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(start)}
	if err != nil {
		result.ExitCode = -1
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
		if logger != nil {
			logger.Error("", "external command failed", err, "program", program, "exit_code", result.ExitCode, "stderr", result.Stderr)
		}
		return result, fmt.Errorf("%s failed (exit %d): %s: %w", program, result.ExitCode, result.Stderr, err)
	}
	if logger != nil {
		logger.Info("", "external command completed", "program", program, "exit_code", 0, "duration_ms", result.Duration.Milliseconds())
	}
	return result, nil
}

func RunPowerShell(ctx context.Context, runner CommandRunner, script string) (Result, error) {
	return runner.Run(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}
