//go:build windows

package elevate

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// EnsureAdministrator relaunches the current executable through the Windows
// UAC prompt when it is not already elevated. The caller should exit when
// relaunched is true.
func EnsureAdministrator() (relaunched bool, err error) {
	member, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	token := windows.Token(0)
	isAdmin, err := token.IsMember(member)
	if err != nil {
		return false, err
	}
	if isAdmin {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return false, err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err := windows.ShellExecute(0, verb, file, nil, cwd, windows.SW_SHOWNORMAL); err != nil {
		return false, err
	}
	return true, nil
}
