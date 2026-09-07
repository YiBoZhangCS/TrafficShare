//go:build !windows

package elevate

func EnsureAdministrator() (bool, error) { return false, nil }
