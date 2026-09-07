package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"trafficshare/internal/config"
	"trafficshare/internal/database"
	"trafficshare/internal/logging"
	"trafficshare/internal/state"
	"trafficshare/internal/traffic"
	"trafficshare/internal/webui"
	"trafficshare/internal/windowsnet"
	"trafficshare/internal/wireguard"
)

type LocalController struct {
	mu              sync.Mutex
	App             App
	ConfigPath      string
	providerPreview time.Time
	connectPreviews map[string]time.Time
	RoleLocked      string
	EmbeddedServer  bool
}

func (c *LocalController) app() App { c.mu.Lock(); defer c.mu.Unlock(); return c.App }
func (c *LocalController) Settings(_ context.Context) (webui.Settings, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := c.App.Config
	return webui.Settings{Role: cfg.Agent.Role, RoleLocked: c.RoleLocked != "", ServerURL: cfg.Agent.ServerURL, DeviceName: cfg.Agent.DeviceName, Username: cfg.Agent.Username, DeviceID: cfg.Agent.DeviceID, Authenticated: cfg.Agent.Token != "", EmbeddedServer: c.EmbeddedServer, ConfigPath: c.ConfigPath}, nil
}
func (c *LocalController) UpdateSettings(_ context.Context, role, serverURL, deviceName string) (webui.Settings, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	role = strings.TrimSpace(role)
	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	deviceName = strings.TrimSpace(deviceName)
	if c.RoleLocked != "" {
		role = c.RoleLocked
	}
	if role != "provider" && role != "consumer" {
		return webui.Settings{}, errors.New("role must be provider or consumer")
	}
	parsed, err := url.Parse(serverURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return webui.Settings{}, errors.New("control server URL must be a valid http:// or https:// address")
	}
	if len(deviceName) > 80 {
		return webui.Settings{}, errors.New("device name must not exceed 80 characters")
	}
	snapshots, err := (state.Store{Dir: c.App.Config.Agent.StateDir}).Incomplete()
	if err != nil {
		return webui.Settings{}, err
	}
	changedIdentity := role != c.App.Config.Agent.Role || serverURL != c.App.Config.Agent.ServerURL || (deviceName != "" && deviceName != c.App.Config.Agent.DeviceName)
	if changedIdentity && len(snapshots) > 0 {
		return webui.Settings{}, errors.New("disconnect or repair active TrafficShare sessions before changing identity settings")
	}
	cfg := c.App.Config
	if role != cfg.Agent.Role || serverURL != cfg.Agent.ServerURL {
		cfg.Agent.Token, cfg.Agent.Username, cfg.Agent.DeviceID = "", "", ""
	}
	if deviceName != cfg.Agent.DeviceName {
		cfg.Agent.DeviceID = ""
	}
	cfg.Agent.Role, cfg.Agent.ServerURL, cfg.Agent.DeviceName = role, serverURL, deviceName
	if err := cfg.Validate(); err != nil {
		return webui.Settings{}, err
	}
	if err := cfg.Save(c.ConfigPath); err != nil {
		return webui.Settings{}, err
	}
	c.App.Config = cfg
	return webui.Settings{Role: cfg.Agent.Role, RoleLocked: c.RoleLocked != "", ServerURL: cfg.Agent.ServerURL, DeviceName: cfg.Agent.DeviceName, Username: cfg.Agent.Username, DeviceID: cfg.Agent.DeviceID, Authenticated: cfg.Agent.Token != "", EmbeddedServer: c.EmbeddedServer, ConfigPath: c.ConfigPath}, nil
}
func (c *LocalController) ControlHealth(ctx context.Context) error { return c.app().api().Health(ctx) }
func (c *LocalController) Doctor(ctx context.Context) (windowsnet.DoctorReport, error) {
	return (windowsnet.Doctor{Runner: c.app().Runner}).Inspect(ctx)
}
func (c *LocalController) Status(ctx context.Context) (map[string]any, error) {
	return c.app().Status(ctx)
}
func (c *LocalController) Login(ctx context.Context, username, password string, register bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if register {
		if err := c.App.Register(ctx, username, password); err != nil {
			return err
		}
	}
	cfg, err := c.App.Login(ctx, username, password)
	if err != nil {
		return err
	}
	if err := cfg.Save(c.ConfigPath); err != nil {
		return err
	}
	c.App.Config = cfg
	return nil
}
func (c *LocalController) RegisterDevice(ctx context.Context) (database.Device, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, err := c.App.RegisterDevice(ctx)
	if err != nil {
		return database.Device{}, err
	}
	c.App.Config.Agent.DeviceID = d.ID
	c.App.Config.Agent.DeviceName = d.DeviceName
	if err := c.App.Config.Save(c.ConfigPath); err != nil {
		return database.Device{}, err
	}
	return d, nil
}
func (c *LocalController) ProviderInit(ctx context.Context, apply bool) (any, error) {
	a := c.app()
	if a.Config.Agent.Role != "provider" {
		return nil, errors.New("agent role is not provider")
	}
	sessionID := "provider-network"
	if a.Config.Agent.DeviceID != "" {
		sessionID = "provider-" + a.Config.Agent.DeviceID
	}
	if apply {
		c.mu.Lock()
		valid := time.Since(c.providerPreview) < 10*time.Minute
		c.mu.Unlock()
		if !valid {
			return nil, errors.New("run Provider dry-run preview before applying")
		}
	}
	preview, err := a.SetupProvider(ctx, SetupOptions{SessionID: sessionID, DryRun: !apply})
	if err == nil && !apply {
		c.mu.Lock()
		c.providerPreview = time.Now()
		c.mu.Unlock()
	}
	return preview, err
}
func (c *LocalController) CreateShare(ctx context.Context, receiver string, quota int64, duration time.Duration) (database.Share, error) {
	return c.app().CreateShare(ctx, receiver, quota, duration)
}
func (c *LocalController) ProviderShares(ctx context.Context) ([]database.Share, error) {
	return c.app().api().ProviderShares(ctx)
}
func (c *LocalController) StopShare(ctx context.Context, id string) error {
	return c.app().api().StopShare(ctx, id)
}
func (c *LocalController) Shares(ctx context.Context) ([]database.Share, error) {
	return c.app().api().Shares(ctx)
}
func (c *LocalController) Connect(ctx context.Context, shareID string, apply bool) (database.Session, any, error) {
	if apply {
		c.mu.Lock()
		previewed := c.connectPreviews != nil && time.Since(c.connectPreviews[shareID]) < 10*time.Minute
		c.mu.Unlock()
		if !previewed {
			return database.Session{}, nil, errors.New("run the connection dry-run preview before applying")
		}
	}
	s, p, err := c.app().Connect(ctx, shareID, !apply)
	if err == nil && !apply {
		c.mu.Lock()
		if c.connectPreviews == nil {
			c.connectPreviews = map[string]time.Time{}
		}
		c.connectPreviews[shareID] = time.Now()
		c.mu.Unlock()
	}
	return s, p, err
}
func (c *LocalController) Disconnect(ctx context.Context, sessionID string, apply bool) error {
	a := c.app()
	_, err := a.Disconnect(ctx, sessionID, !apply)
	if err == nil && apply {
		_ = a.api().Disconnect(ctx, sessionID)
	}
	return err
}
func (c *LocalController) Logs() string {
	a := c.app()
	b, err := os.ReadFile(a.Config.Agent.LogPath)
	if err != nil {
		return "No logs: " + err.Error()
	}
	return string(b)
}

func (c *LocalController) Monitor(ctx context.Context) {
	a := c.app()
	interval := a.Config.Agent.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	peers := map[string]string{}
	baselines := map[string]traffic.Baseline{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a = c.app()
			ids, err := a.Heartbeat(ctx)
			if err != nil {
				if a.Logger != nil {
					a.Logger.Error("", "heartbeat failed", err)
				}
				continue
			}
			if a.Config.Agent.Role == "consumer" {
				for _, id := range ids {
					_, err := a.Disconnect(ctx, id, false)
					if err != nil && a.Logger != nil {
						a.Logger.Error(id, "forced disconnect failed", err)
					}
				}
				report, doctorErr := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
				if doctorErr == nil {
					manager := wireguard.Manager{Runner: a.Runner, WGExe: report.WGExe}
					snapshots, _ := (state.Store{Dir: a.Config.Agent.StateDir}).Incomplete()
					for _, snapshot := range snapshots {
						if snapshot.Role != "consumer" {
							continue
						}
						if _, err := manager.Status(ctx, a.Config.Agent.TunnelName); err != nil {
							_, _ = a.Disconnect(ctx, snapshot.SessionID, false)
							_ = a.api().Disconnect(ctx, snapshot.SessionID)
							if a.Logger != nil {
								a.Logger.Error(snapshot.SessionID, "WireGuard tunnel failed; network restored", err)
							}
						}
					}
				}
				continue
			}
			report, err := (windowsnet.Doctor{Runner: a.Runner}).Inspect(ctx)
			if err != nil {
				continue
			}
			manager := wireguard.Manager{Runner: a.Runner, WireGuardExe: report.WireGuardExe, WGExe: report.WGExe}
			items, err := a.api().ProviderSessions(ctx, a.Config.Agent.DeviceID)
			if err != nil {
				continue
			}
			for _, item := range items {
				sid, key := item.Session.ID, item.Tunnel.ConsumerPublicKey
				if item.Session.Status != "active" && item.Session.Status != "pending" {
					if peers[sid] != "" {
						_, _ = manager.RemovePeer(ctx, a.Config.Agent.TunnelName, key)
						delete(peers, sid)
						delete(baselines, sid)
					}
					continue
				}
				if peers[sid] == "" {
					allowedIP := strings.Split(item.Tunnel.ConsumerTunnelIP, "/")[0] + "/32"
					if _, err := manager.AddPeer(ctx, a.Config.Agent.TunnelName, key, allowedIP); err != nil {
						if a.Logger != nil {
							a.Logger.Error(sid, "add WireGuard peer failed", err)
						}
						continue
					}
					peers[sid] = key
				}
				counter, err := (traffic.Reader{Runner: a.Runner, WGExe: report.WGExe}).Peer(ctx, a.Config.Agent.TunnelName, key)
				if err != nil {
					_ = a.api().Revoke(ctx, sid)
					_, _ = manager.RemovePeer(ctx, a.Config.Agent.TunnelName, key)
					delete(peers, sid)
					if a.Logger != nil {
						a.Logger.Error(sid, "WireGuard counter read failed; session revoked", err)
					}
					continue
				}
				baseline, exists := baselines[sid]
				if !exists {
					baseline.Last = counter
				} else {
					baseline = baseline.Advance(counter)
				}
				baselines[sid] = baseline
				exhausted, err := a.api().ReportTraffic(ctx, a.Config.Agent.DeviceID, database.TrafficReport{SessionID: sid, RXBytes: int64(baseline.Used.RX), TXBytes: int64(baseline.Used.TX), TotalBytes: int64(baseline.Used.Total())})
				if err == nil && exhausted {
					_, _ = manager.RemovePeer(ctx, a.Config.Agent.TunnelName, key)
					delete(peers, sid)
				}
			}
		}
	}
}

func (c CLI) ui(ctx context.Context, args []string) error {
	fs := flagSet("ui", c.Stderr)
	configPath := fs.String("config", config.DefaultAgentConfigPath("consumer"), "configuration file")
	listen := fs.String("listen", "", "override localhost listen address")
	role := fs.String("role", "", "lock UI to provider or consumer role")
	serverURL := fs.String("server-url", "", "override control server URL")
	openUI := fs.Bool("open-browser", false, "open the local UI in the default browser")
	embeddedServer := fs.Bool("embedded-server", false, "show that this process owns the embedded control server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadIfExists(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Agent.UIListen = *listen
	}
	if *role != "" {
		cfg.Agent.Role = *role
	}
	if *serverURL != "" {
		cfg.Agent.ServerURL = strings.TrimRight(*serverURL, "/")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(*configPath); err != nil {
		return err
	}
	logger, err := loggingForAgent(cfg)
	if err != nil {
		return err
	}
	defer logger.Close()
	controller := &LocalController{App: App{Config: cfg, Runner: c.Runner, Logger: logger, EmbeddedServer: *embeddedServer}, ConfigPath: *configPath, RoleLocked: *role, EmbeddedServer: *embeddedServer}
	server, err := webui.New(controller)
	if err != nil {
		return err
	}
	go controller.Monitor(ctx)
	uiURL := "http://" + cfg.Agent.UIListen
	fmt.Fprintf(c.Stdout, "TrafficShare local UI: %s\n", uiURL)
	if *openUI {
		go openBrowser(uiURL)
	}
	return webui.ListenAndServe(ctx, cfg.Agent.UIListen, server.Handler())
}

func openBrowser(target string) {
	time.Sleep(500 * time.Millisecond)
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.Command("open", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	_ = command.Start()
}

func flagSet(name string, w io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(w)
	return fs
}
func loggingForAgent(cfg config.Config) (*logging.Logger, error) {
	return logging.New("agent", cfg.Agent.LogPath)
}
