//go:build windows

package windowsnet

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestExternalCommandsNeverCreateConsoleWindows(t *testing.T) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", "'ok'")
	configureCommand(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow {
		t.Fatal("external command window is not hidden")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatal("external command does not use CREATE_NO_WINDOW")
	}
}
