package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const resourcePrefix = "TrafficShare-"

type Route struct {
	DestinationPrefix string `json:"destination_prefix"`
	InterfaceIndex    int    `json:"interface_index"`
	NextHop           string `json:"next_hop"`
	Metric            int    `json:"metric,omitempty"`
}

type Snapshot struct {
	SessionID         string    `json:"session_id"`
	Role              string    `json:"role"`
	CreatedAt         time.Time `json:"created_at"`
	Completed         bool      `json:"completed"`
	OriginalRoutes    []Route   `json:"original_routes"`
	OriginalGateway   string    `json:"original_gateway"`
	OriginalDNS       []string  `json:"original_dns"`
	OriginalInterface int       `json:"original_interface_index"`
	AddedRoutes       []Route   `json:"added_routes"`
	FirewallRules     []string  `json:"firewall_rules"`
	NATNames          []string  `json:"nat_names"`
	TunnelName        string    `json:"tunnel_name"`
	TunnelConfigPath  string    `json:"tunnel_config_path,omitempty"`
	PeerPublicKey     string    `json:"peer_public_key,omitempty"`
}

func (s Snapshot) Validate() error {
	if s.SessionID == "" || strings.ContainsAny(s.SessionID, `/\\:; "'`) {
		return errors.New("invalid session id")
	}
	for _, name := range append(append([]string{}, s.FirewallRules...), s.NATNames...) {
		if !strings.HasPrefix(name, resourcePrefix) {
			return fmt.Errorf("refusing untagged resource %q", name)
		}
	}
	if s.TunnelName != "" && !strings.HasPrefix(s.TunnelName, resourcePrefix) {
		return fmt.Errorf("refusing untagged tunnel %q", s.TunnelName)
	}
	return nil
}

type Store struct {
	Dir string
}

func (s Store) Save(snapshot Snapshot) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = time.Now().UTC()
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	path := s.path(snapshot.SessionID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s Store) Load(sessionID string) (Snapshot, error) {
	b, err := os.ReadFile(s.path(sessionID))
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(b, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s Store) MarkCompleted(sessionID string) error {
	snapshot, err := s.Load(sessionID)
	if err != nil {
		return err
	}
	snapshot.Completed = true
	return s.Save(snapshot)
}

func (s Store) Incomplete() ([]Snapshot, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []Snapshot
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var snapshot Snapshot
		if err := json.Unmarshal(b, &snapshot); err != nil {
			return nil, fmt.Errorf("decode %s: %w", entry.Name(), err)
		}
		if err := snapshot.Validate(); err != nil {
			return nil, err
		}
		if !snapshot.Completed {
			result = append(result, snapshot)
		}
	}
	return result, nil
}

func (s Store) path(sessionID string) string {
	return filepath.Join(s.Dir, sessionID+".json")
}
