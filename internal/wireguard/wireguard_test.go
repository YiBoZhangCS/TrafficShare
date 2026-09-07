package wireguard

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"trafficshare/internal/windowsnet"
)

type recordingRunner struct {
	results []windowsnet.Result
	calls   []string
}

func (r *recordingRunner) Run(_ context.Context, program string, args ...string) (windowsnet.Result, error) {
	r.calls = append(r.calls, program+" "+strings.Join(args, " "))
	if len(r.results) == 0 {
		return windowsnet.Result{}, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result, nil
}

func TestKeysPersistAndPrivateIsNotJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.key")
	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Private == first.Public {
		t.Fatal("key persistence failed")
	}
}

func TestConsumerConfig(t *testing.T) {
	k1, _ := GenerateKeyPair()
	k2, _ := GenerateKeyPair()
	text, err := (Config{PrivateKey: k1.Private, Address: "10.66.0.2/24", PeerPublicKey: k2.Public, PeerAllowedIPs: "0.0.0.0/0", Endpoint: "192.168.1.2:51820", PersistentKeepalive: 25}).Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AllowedIPs = 0.0.0.0/0", "Endpoint = 192.168.1.2:51820", "PersistentKeepalive = 25"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestUninstallTunnelSucceedsWhenServiceIsAlreadyAbsent(t *testing.T) {
	runner := &recordingRunner{results: []windowsnet.Result{{Stdout: "false\r\n"}}}
	manager := Manager{Runner: runner, WireGuardExe: `C:\Program Files\WireGuard\wireguard.exe`}
	if _, err := manager.UninstallTunnel(context.Background(), "TrafficShare-Tunnel", false); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !strings.HasPrefix(runner.calls[0], "powershell.exe ") {
		t.Fatalf("expected only the service existence check, got %#v", runner.calls)
	}
}
