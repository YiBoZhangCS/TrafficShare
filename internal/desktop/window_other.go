//go:build !windows

package desktop

import (
	"context"
	"errors"
)

func Run(context.Context, string, string) error {
	return errors.New("embedded desktop window is currently supported on Windows only")
}
