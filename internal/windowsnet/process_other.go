//go:build !windows

package windowsnet

import "os/exec"

func configureCommand(*exec.Cmd) {}
