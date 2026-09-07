package config

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultServerListen = "0.0.0.0:8787"
	DefaultUIListen     = "127.0.0.1:9080"
)

type Config struct {
	Server ServerConfig `json:"server"`
	Agent  AgentConfig  `json:"agent"`
	Tunnel TunnelConfig `json:"tunnel"`
}

type ServerConfig struct {
	Listen       string        `json:"listen"`
	DatabasePath string        `json:"database_path"`
	LogPath      string        `json:"log_path"`
	TLSCertPath  string        `json:"tls_cert_path,omitempty"`
	TLSKeyPath   string        `json:"tls_key_path,omitempty"`
	TokenTTL     time.Duration `json:"token_ttl"`
	HeartbeatTTL time.Duration `json:"heartbeat_ttl"`
}

type AgentConfig struct {
	Role         string        `json:"role"`
	ServerURL    string        `json:"server_url"`
	UIListen     string        `json:"ui_listen"`
	StateDir     string        `json:"state_dir"`
	LogPath      string        `json:"log_path"`
	Token        string        `json:"token,omitempty"`
	Username     string        `json:"username,omitempty"`
	DeviceID     string        `json:"device_id,omitempty"`
	DeviceName   string        `json:"device_name,omitempty"`
	TunnelName   string        `json:"tunnel_name"`
	KeyPath      string        `json:"key_path"`
	PollInterval time.Duration `json:"poll_interval"`
}

type TunnelConfig struct {
	Prefix     string `json:"prefix"`
	ProviderIP string `json:"provider_ip"`
	ConsumerIP string `json:"consumer_ip"`
	Port       int    `json:"port"`
	NATName    string `json:"nat_name"`
}

func Default() Config {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = "."
	}
	root := filepath.Join(programData, "TrafficShare")
	return Config{
		Server: ServerConfig{Listen: DefaultServerListen, DatabasePath: filepath.Join(root, "trafficshare.db"), LogPath: filepath.Join(root, "logs", "server.jsonl"), TokenTTL: 24 * time.Hour, HeartbeatTTL: 20 * time.Second},
		Agent:  AgentConfig{Role: "consumer", ServerURL: "http://127.0.0.1:8787", UIListen: DefaultUIListen, StateDir: filepath.Join(root, "state"), LogPath: filepath.Join(root, "logs", "agent.jsonl"), TunnelName: "TrafficShare-Tunnel", KeyPath: filepath.Join(root, "keys", "device.key"), PollInterval: 5 * time.Second},
		Tunnel: TunnelConfig{Prefix: "10.66.0.0/24", ProviderIP: "10.66.0.1/24", ConsumerIP: "10.66.0.2/24", Port: 51820, NATName: "TrafficShare-NAT"},
	}
}

func ProgramDataDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = "."
	}
	return filepath.Join(programData, "TrafficShare")
}

func DefaultAgentConfigPath(role string) string {
	if role != "provider" {
		role = "consumer"
	}
	return filepath.Join(ProgramDataDir(), role+".json")
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadIfExists(path string) (Config, error) {
	cfg, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	return cfg, err
}

func (c Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (c Config) Validate() error {
	if (c.Server.TLSCertPath == "") != (c.Server.TLSKeyPath == "") {
		return errors.New("server TLS certificate and key must be configured together")
	}
	if c.Agent.UIListen != "" {
		host, _, err := net.SplitHostPort(c.Agent.UIListen)
		if err != nil || host != "127.0.0.1" {
			return errors.New("agent UI must listen on 127.0.0.1")
		}
	}
	if c.Tunnel.Port < 1 || c.Tunnel.Port > 65535 {
		return errors.New("tunnel port must be between 1 and 65535")
	}
	if c.Agent.Role != "provider" && c.Agent.Role != "consumer" {
		return errors.New("agent role must be provider or consumer")
	}
	return nil
}
