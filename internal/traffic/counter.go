package traffic

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"trafficshare/internal/windowsnet"
)

type Counter struct {
	RX uint64 `json:"rx_bytes"`
	TX uint64 `json:"tx_bytes"`
}

func (c Counter) Total() uint64 { return c.RX + c.TX }

type Baseline struct {
	Last Counter `json:"last"`
	Used Counter `json:"used"`
}

// Advance accumulates deltas. If a tunnel restart resets a peer counter, the
// current value becomes the delta rather than underflowing.
func (b Baseline) Advance(current Counter) Baseline {
	b.Used.RX += delta(b.Last.RX, current.RX)
	b.Used.TX += delta(b.Last.TX, current.TX)
	b.Last = current
	return b
}

func delta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

type Reader struct {
	Runner windowsnet.CommandRunner
	WGExe  string
}

func (r Reader) Peer(ctx context.Context, tunnel, publicKey string) (Counter, error) {
	if r.Runner == nil || r.WGExe == "" {
		return Counter{}, errors.New("wg.exe is required to read peer counters")
	}
	result, err := r.Runner.Run(ctx, r.WGExe, "show", tunnel, "dump")
	if err != nil {
		return Counter{}, err
	}
	return ParseDump(result.Stdout, publicKey)
}

// ParseDump parses the official `wg show <interface> dump` tab-separated form.
func ParseDump(text, publicKey string) (Counter, error) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	line := 0
	for scanner.Scan() {
		line++
		if line == 1 {
			continue // interface row
		}
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 8 || fields[0] != publicKey {
			continue
		}
		rx, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return Counter{}, fmt.Errorf("parse rx counter: %w", err)
		}
		tx, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return Counter{}, fmt.Errorf("parse tx counter: %w", err)
		}
		return Counter{RX: rx, TX: tx}, nil
	}
	if err := scanner.Err(); err != nil {
		return Counter{}, err
	}
	return Counter{}, errors.New("WireGuard peer not found")
}
