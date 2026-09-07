package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trafficshare/internal/client"
	"trafficshare/internal/config"
	"trafficshare/internal/database"
	"trafficshare/internal/logging"
	"trafficshare/internal/state"
	"trafficshare/internal/traffic"
	"trafficshare/internal/windowsnet"
	"trafficshare/internal/wireguard"
)

type App struct {
	Config         config.Config
	Runner         windowsnet.CommandRunner
	Logger         *logging.Logger
	EmbeddedServer bool
}

type Preview struct {
	Doctor windowsnet.DoctorReport `json:"doctor"`
	Plan   windowsnet.Plan         `json:"plan"`
}

func (a App) api() client.Client {
	return client.Client{BaseURL: a.Config.Agent.ServerURL, Token: a.Config.Agent.Token}
}
func (a App) store() state.Store { return state.Store{Dir: a.Config.Agent.StateDir} }

func (a App) PreviewProvider(ctx context.Context, sessionID string) (Preview, error) {
	report, err := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
	if err != nil {
		return Preview{}, err
	}
	controlPort := 0
	if a.EmbeddedServer {
		controlPort = 8787
	}
	plan, err := windowsnet.ProviderPlan(windowsnet.PlanOptions{SessionID: sessionID, TunnelAlias: a.Config.Agent.TunnelName, TunnelPrefix: a.Config.Tunnel.Prefix, NATName: a.Config.Tunnel.NATName, ListenPort: a.Config.Tunnel.Port, ControlPort: controlPort, FirewallProfile: report.DefaultAdapter.Profile})
	if err != nil {
		return Preview{}, err
	}
	return Preview{Doctor: report, Plan: plan}, nil
}

func (a App) PreviewConsumer(ctx context.Context, sessionID, endpointIP string) (Preview, error) {
	report, err := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
	if err != nil {
		return Preview{}, err
	}
	d := report.DefaultAdapter
	if d.Name == "" {
		return Preview{}, errors.New("default IPv4 route was not detected")
	}
	plan, err := windowsnet.ConsumerPlan(windowsnet.PlanOptions{SessionID: sessionID, TunnelAlias: a.Config.Agent.TunnelName, TunnelPrefix: a.Config.Tunnel.Prefix, NATName: a.Config.Tunnel.NATName, EndpointIP: endpointIP, InterfaceIndex: d.Index, Gateway: d.Gateway, ListenPort: a.Config.Tunnel.Port})
	if err != nil {
		return Preview{}, err
	}
	return Preview{Doctor: report, Plan: plan}, nil
}

type SetupOptions struct {
	SessionID, EndpointIP, PeerPublicKey string
	DryRun                               bool
}

func (a App) SetupProvider(ctx context.Context, o SetupOptions) (Preview, error) {
	preview, err := a.PreviewProvider(ctx, o.SessionID)
	if err != nil {
		return Preview{}, err
	}
	if o.DryRun {
		return preview, nil
	}
	if !preview.Doctor.Administrator {
		return preview, errors.New("Administrator privileges are required")
	}
	if preview.Doctor.WireGuardExe == "" {
		return preview, errors.New("WireGuard for Windows is required")
	}
	if preview.Doctor.NATReadError != "" {
		return preview, errors.New("existing NAT configurations could not be read; refusing to modify the network")
	}
	firewall := windowsnet.ResourcePrefix + "WireGuard-UDP-" + o.SessionID
	if err := windowsnet.EnsureNoProviderConflicts(ctx, a.Runner, a.Config.Tunnel.NATName, a.Config.Agent.TunnelName, firewall); err != nil {
		return preview, err
	}
	key, err := wireguard.LoadOrCreateKey(a.Config.Agent.KeyPath)
	if err != nil {
		return preview, err
	}
	configPath := a.tunnelConfigPath()
	cfg := wireguard.Config{PrivateKey: key.Private, Address: a.Config.Tunnel.ProviderIP, ListenPort: a.Config.Tunnel.Port, PeerPublicKey: o.PeerPublicKey, PeerAllowedIPs: "10.66.0.2/32"}
	if err := a.saveSnapshot(o.SessionID, "provider", preview, configPath, "", o.PeerPublicKey); err != nil {
		return preview, err
	}
	if err := wireguard.WriteConfig(configPath, cfg); err != nil {
		return preview, err
	}
	manager := wireguard.Manager{Runner: a.Runner, WireGuardExe: preview.Doctor.WireGuardExe}
	if _, err := manager.InstallTunnel(ctx, configPath, false); err != nil {
		return preview, err
	}
	if err := manager.WaitForTunnel(ctx, a.Config.Agent.TunnelName, 20); err != nil {
		return preview, err
	}
	if _, err := (windowsnet.Engine{Runner: a.Runner}).Apply(ctx, preview.Plan, false); err != nil {
		return preview, err
	}
	return preview, nil
}

func (a App) SetupConsumer(ctx context.Context, o SetupOptions) (Preview, error) {
	preview, err := a.PreviewConsumer(ctx, o.SessionID, o.EndpointIP)
	if err != nil {
		return Preview{}, err
	}
	if o.DryRun {
		return preview, nil
	}
	if !preview.Doctor.Administrator {
		return preview, errors.New("Administrator privileges are required")
	}
	if preview.Doctor.WireGuardExe == "" {
		return preview, errors.New("WireGuard for Windows is required")
	}
	if o.PeerPublicKey == "" {
		return preview, errors.New("provider WireGuard public key is required")
	}
	ipv6Rule := windowsnet.ResourcePrefix + "Block-IPv6-" + o.SessionID
	if err := windowsnet.EnsureNoConsumerConflicts(ctx, a.Runner, o.EndpointIP, preview.Doctor.DefaultAdapter.Index, a.Config.Agent.TunnelName, ipv6Rule); err != nil {
		return preview, err
	}
	key, err := wireguard.LoadOrCreateKey(a.Config.Agent.KeyPath)
	if err != nil {
		return preview, err
	}
	configPath := a.tunnelConfigPath()
	cfg := wireguard.Config{PrivateKey: key.Private, Address: a.Config.Tunnel.ConsumerIP, PeerPublicKey: o.PeerPublicKey, PeerAllowedIPs: "0.0.0.0/0", Endpoint: fmt.Sprintf("%s:%d", o.EndpointIP, a.Config.Tunnel.Port), PersistentKeepalive: 25}
	if err := a.saveSnapshot(o.SessionID, "consumer", preview, configPath, o.EndpointIP, o.PeerPublicKey); err != nil {
		return preview, err
	}
	// The exception route and IPv6 block must exist before the full-tunnel interface starts.
	if _, err := (windowsnet.Engine{Runner: a.Runner}).Apply(ctx, preview.Plan, false); err != nil {
		return preview, err
	}
	if err := wireguard.WriteConfig(configPath, cfg); err != nil {
		return preview, err
	}
	manager := wireguard.Manager{Runner: a.Runner, WireGuardExe: preview.Doctor.WireGuardExe}
	if _, err := manager.InstallTunnel(ctx, configPath, false); err != nil {
		return preview, err
	}
	if err := manager.WaitForTunnel(ctx, a.Config.Agent.TunnelName, 20); err != nil {
		return preview, err
	}
	return preview, nil
}

func (a App) saveSnapshot(sessionID, role string, preview Preview, configPath, endpointIP, peerPublicKey string) error {
	d := preview.Doctor.DefaultAdapter
	s := state.Snapshot{SessionID: sessionID, Role: role, OriginalGateway: d.Gateway, OriginalDNS: d.DNS, OriginalInterface: d.Index, TunnelName: a.Config.Agent.TunnelName, TunnelConfigPath: configPath, PeerPublicKey: peerPublicKey}
	if d.Gateway != "" {
		s.OriginalRoutes = []state.Route{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: d.Index, NextHop: d.Gateway}}
	}
	for _, action := range preview.Plan.Actions {
		switch {
		case strings.Contains(action.Resource, "NAT"):
			s.NATNames = append(s.NATNames, action.Resource)
		case strings.Contains(action.Resource, "WireGuard-UDP"), strings.Contains(action.Resource, "Block-IPv6"), strings.Contains(action.Resource, "Control-TCP"):
			s.FirewallRules = append(s.FirewallRules, action.Resource)
		}
	}
	if endpointIP != "" {
		s.AddedRoutes = append(s.AddedRoutes, state.Route{DestinationPrefix: endpointIP + "/32", InterfaceIndex: d.Index, NextHop: d.Gateway})
	}
	return a.store().Save(s)
}

func (a App) Disconnect(ctx context.Context, sessionID string, dryRun bool) (windowsnet.Plan, error) {
	snapshot, err := a.store().Load(sessionID)
	if err != nil {
		return windowsnet.Plan{}, err
	}
	report, err := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
	if err != nil {
		return windowsnet.Plan{}, err
	}
	manager := wireguard.Manager{Runner: a.Runner, WireGuardExe: report.WireGuardExe}
	if _, err := manager.UninstallTunnel(ctx, snapshot.TunnelName, dryRun); err != nil && !dryRun {
		return windowsnet.Plan{}, err
	}
	plan, err := (state.Restorer{Runner: a.Runner, Store: a.store()}).Restore(ctx, snapshot, dryRun)
	if err != nil {
		return plan, err
	}
	if !dryRun && snapshot.TunnelConfigPath != "" {
		_ = os.Remove(snapshot.TunnelConfigPath)
	}
	return plan, nil
}

func (a App) Repair(ctx context.Context, dryRun bool) ([]windowsnet.Plan, error) {
	snapshots, err := a.store().Incomplete()
	if err != nil {
		return nil, err
	}
	plans := make([]windowsnet.Plan, 0, len(snapshots))
	for _, snapshot := range snapshots {
		plan, err := a.Disconnect(ctx, snapshot.SessionID, dryRun)
		plans = append(plans, plan)
		if err != nil {
			return plans, fmt.Errorf("repair session %s: %w", snapshot.SessionID, err)
		}
	}
	return plans, nil
}

func (a App) tunnelConfigPath() string {
	return filepath.Join(a.Config.Agent.StateDir, "configs", a.Config.Agent.TunnelName+".conf")
}

func (a App) Status(ctx context.Context) (map[string]any, error) {
	report, err := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
	if err != nil {
		return nil, err
	}
	snapshots, err := a.store().Incomplete()
	if err != nil {
		return nil, err
	}
	details := make([]map[string]any, 0, len(snapshots))
	for _, snapshot := range snapshots {
		item := map[string]any{"state": snapshot}
		if a.Config.Agent.Token != "" {
			if view, err := a.api().SessionView(ctx, snapshot.SessionID); err == nil {
				item["server"] = view
			}
		}
		if snapshot.PeerPublicKey != "" && report.WGExe != "" {
			if counter, err := (traffic.Reader{Runner: a.Runner, WGExe: report.WGExe}).Peer(ctx, a.Config.Agent.TunnelName, snapshot.PeerPublicKey); err == nil {
				item["wireguard"] = counter
			}
		}
		details = append(details, item)
	}
	return map[string]any{"current_user": a.Config.Agent.Username, "device_id": a.Config.Agent.DeviceID, "role": a.Config.Agent.Role, "lan_ip": report.DefaultAdapter.IPv4, "default_interface": report.DefaultAdapter.Name, "tunnel_name": a.Config.Agent.TunnelName, "sessions": details}, nil
}

func (a App) Login(ctx context.Context, username, password string) (config.Config, error) {
	login, err := a.api().Login(ctx, username, password)
	if err != nil {
		return a.Config, err
	}
	cfg := a.Config
	cfg.Agent.Token = login.Token
	cfg.Agent.Username = login.User.Username
	return cfg, nil
}

func (a App) Register(ctx context.Context, username, password string) error {
	return a.api().Register(ctx, username, password)
}

func (a App) RegisterDevice(ctx context.Context) (database.Device, error) {
	report, err := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
	if err != nil {
		return database.Device{}, err
	}
	if report.DefaultAdapter.IPv4 == "" {
		return database.Device{}, errors.New("LAN IPv4 was not detected")
	}
	key, err := wireguard.LoadOrCreateKey(a.Config.Agent.KeyPath)
	if err != nil {
		return database.Device{}, err
	}
	name := a.Config.Agent.DeviceName
	if name == "" {
		name, _ = os.Hostname()
	}
	d, err := a.api().RegisterDevice(ctx, database.Device{ID: a.Config.Agent.DeviceID, DeviceName: name, Role: a.Config.Agent.Role, LANIP: report.DefaultAdapter.IPv4, TunnelPublicKey: key.Public})
	return d, err
}

func (a App) CreateShare(ctx context.Context, receiver string, quotaBytes int64, duration time.Duration) (database.Share, error) {
	return a.api().CreateShare(ctx, receiver, quotaBytes, time.Now().UTC().Add(duration))
}

func (a App) Connect(ctx context.Context, shareID string, dryRun bool) (database.Session, Preview, error) {
	if a.Config.Agent.Role != "consumer" {
		return database.Session{}, Preview{}, errors.New("connect requires consumer role")
	}
	if a.Config.Agent.DeviceID == "" {
		return database.Session{}, Preview{}, errors.New("register this device first")
	}
	var s database.Session
	var cfg database.TunnelConfig
	var err error
	if dryRun {
		cfg, err = a.api().PreviewSession(ctx, shareID, a.Config.Agent.DeviceID)
	} else {
		s, cfg, err = a.api().CreateSession(ctx, shareID, a.Config.Agent.DeviceID)
	}
	if err != nil {
		return database.Session{}, Preview{}, err
	}
	reachable, reachErr := windowsnet.ProviderReachable(ctx, a.Runner, cfg.ProviderLANIP)
	if reachErr != nil || !reachable {
		if s.ID != "" {
			_ = a.api().Disconnect(ctx, s.ID)
		}
		return s, Preview{}, errors.New("Provider is not reachable on current LAN")
	}
	sessionApp := a
	sessionApp.Config.Tunnel.Prefix = cfg.TunnelPrefix
	sessionApp.Config.Tunnel.ProviderIP = cfg.ProviderTunnelIP
	sessionApp.Config.Tunnel.ConsumerIP = cfg.ConsumerTunnelIP
	sessionApp.Config.Tunnel.Port = cfg.Port
	sessionID := s.ID
	if dryRun {
		sessionID = "preview-connection"
	}
	preview, err := sessionApp.SetupConsumer(ctx, SetupOptions{SessionID: sessionID, EndpointIP: cfg.ProviderLANIP, PeerPublicKey: cfg.ProviderPublicKey, DryRun: dryRun})
	if err != nil {
		if s.ID != "" {
			_ = a.api().Disconnect(ctx, s.ID)
		}
		return s, preview, err
	}
	return s, preview, nil
}

func (a App) Heartbeat(ctx context.Context) ([]string, error) {
	if a.Config.Agent.DeviceID == "" {
		return nil, errors.New("device is not registered")
	}
	report, err := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
	if err != nil {
		return nil, err
	}
	return a.api().Heartbeat(ctx, a.Config.Agent.DeviceID, report.DefaultAdapter.IPv4)
}
