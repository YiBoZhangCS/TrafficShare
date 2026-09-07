//go:build !windows

package notify

import (
	"fmt"
	"os"
)

func Error(message string) { fmt.Fprintln(os.Stderr, "TrafficShare:", message) }
