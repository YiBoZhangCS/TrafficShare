package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/curve25519"
	"trafficshare/internal/windowsnet"
)

type KeyPair struct {
	Private string `json:"-"`
	Public  string `json:"public_key"`
}

func GenerateKeyPair() (KeyPair, error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		return KeyPair{}, err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Private: base64.StdEncoding.EncodeToString(private), Public: base64.StdEncoding.EncodeToString(public)}, nil
}

func LoadOrCreateKey(path string) (KeyPair, error) {
	if b, err := os.ReadFile(path); err == nil {
		privateText := strings.TrimSpace(string(b))
		private, err := base64.StdEncoding.DecodeString(privateText)
		if err != nil || len(private) != curve25519.ScalarSize {
			return KeyPair{}, errors.New("invalid stored WireGuard private key")
		}
		public, err := curve25519.X25519(private, curve25519.Basepoint)
		if err != nil {
			return KeyPair{}, err
		}
		return KeyPair{Private: privateText, Public: base64.StdEncoding.EncodeToString(public)}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return KeyPair{}, err
	}
	key, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return KeyPair{}, err
	}
	if err := os.WriteFile(path, []byte(key.Private+"\n"), 0o600); err != nil {
		return KeyPair{}, err
	}
	return key, nil
}

type Config struct {
	PrivateKey          string
	Address             string
	ListenPort          int
	PeerPublicKey       string
	PeerAllowedIPs      string
	Endpoint            string
	PersistentKeepalive int
}

func (c Config) Render() (string, error) {
	if c.PrivateKey == "" || c.Address == "" {
		return "", errors.New("WireGuard private key and address are required")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\r\nPrivateKey = %s\r\nAddress = %s\r\n", c.PrivateKey, c.Address)
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\r\n", c.ListenPort)
	}
	if c.PeerPublicKey != "" {
		fmt.Fprintf(&b, "\r\n[Peer]\r\nPublicKey = %s\r\nAllowedIPs = %s\r\n", c.PeerPublicKey, c.PeerAllowedIPs)
		if c.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\r\n", c.Endpoint)
		}
		if c.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\r\n", c.PersistentKeepalive)
		}
	}
	return b.String(), nil
}

func WriteConfig(path string, cfg Config) error {
	text, err := cfg.Render()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text), 0o600)
}

type Manager struct {
	Runner       windowsnet.CommandRunner
	WireGuardExe string
	WGExe        string
}

var safeTunnelName = regexp.MustCompile(`^TrafficShare-[A-Za-z0-9_.-]+$`)

func (m Manager) AddPeer(ctx context.Context, tunnelName, publicKey, allowedIPs string) (windowsnet.Result, error) {
	if m.Runner == nil || m.WGExe == "" {
		return windowsnet.Result{}, errors.New("wg.exe is required")
	}
	if !strings.HasPrefix(tunnelName, windowsnet.ResourcePrefix) {
		return windowsnet.Result{}, errors.New("refusing untagged tunnel")
	}
	return m.Runner.Run(ctx, m.WGExe, "set", tunnelName, "peer", publicKey, "allowed-ips", allowedIPs)
}
func (m Manager) RemovePeer(ctx context.Context, tunnelName, publicKey string) (windowsnet.Result, error) {
	if m.Runner == nil || m.WGExe == "" {
		return windowsnet.Result{}, errors.New("wg.exe is required")
	}
	if !strings.HasPrefix(tunnelName, windowsnet.ResourcePrefix) {
		return windowsnet.Result{}, errors.New("refusing untagged tunnel")
	}
	return m.Runner.Run(ctx, m.WGExe, "set", tunnelName, "peer", publicKey, "remove")
}

func (m Manager) Status(ctx context.Context, tunnelName string) (windowsnet.Result, error) {
	if m.Runner == nil || m.WGExe == "" {
		return windowsnet.Result{}, errors.New("wg.exe is required")
	}
	if !strings.HasPrefix(tunnelName, windowsnet.ResourcePrefix) {
		return windowsnet.Result{}, errors.New("refusing untagged tunnel")
	}
	return m.Runner.Run(ctx, m.WGExe, "show", tunnelName)
}

// WaitForTunnel handles the asynchronous WireGuard for Windows service start.
// The installer can return several seconds before the virtual IP interface is
// registered with Windows CIM.
func (m Manager) WaitForTunnel(ctx context.Context, tunnelName string, timeoutSeconds int) error {
	if m.Runner == nil {
		return errors.New("WireGuard command runner is required")
	}
	if !safeTunnelName.MatchString(tunnelName) {
		return errors.New("invalid TrafficShare tunnel name")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 20
	}
	script := fmt.Sprintf(`$deadline=(Get-Date).AddSeconds(%d);do{$interface=Get-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction SilentlyContinue;if($interface){exit 0};Start-Sleep -Milliseconds 250}while((Get-Date)-lt $deadline);Write-Error "Timed out waiting for WireGuard interface %s";exit 1`, timeoutSeconds, tunnelName, tunnelName)
	_, err := windowsnet.RunPowerShell(ctx, m.Runner, script)
	return err
}

func (m Manager) InstallTunnel(ctx context.Context, configPath string, dryRun bool) (windowsnet.Result, error) {
	if dryRun {
		return windowsnet.Result{}, nil
	}
	if m.Runner == nil || m.WireGuardExe == "" {
		return windowsnet.Result{}, errors.New("WireGuard for Windows is required")
	}
	return m.Runner.Run(ctx, m.WireGuardExe, "/installtunnelservice", configPath)
}

func (m Manager) UninstallTunnel(ctx context.Context, tunnelName string, dryRun bool) (windowsnet.Result, error) {
	if !safeTunnelName.MatchString(tunnelName) {
		return windowsnet.Result{}, errors.New("refusing to uninstall untagged tunnel")
	}
	if dryRun {
		return windowsnet.Result{}, nil
	}
	if m.Runner == nil || m.WireGuardExe == "" {
		return windowsnet.Result{}, errors.New("WireGuard for Windows is required")
	}
	serviceName := "WireGuardTunnel$" + tunnelName
	check := fmt.Sprintf("if (Get-Service -Name '%s' -ErrorAction SilentlyContinue) { 'true' } else { 'false' }", serviceName)
	result, err := windowsnet.RunPowerShell(ctx, m.Runner, check)
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(result.Stdout) != "true" {
		return result, nil
	}
	return m.Runner.Run(ctx, m.WireGuardExe, "/uninstalltunnelservice", tunnelName)
}
