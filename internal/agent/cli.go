package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"trafficshare/internal/config"
	"trafficshare/internal/quota"
	"trafficshare/internal/windowsnet"
	"trafficshare/internal/wireguard"
)

type CLI struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	Runner windowsnet.CommandRunner
}

func (c CLI) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return c.usage()
	}
	switch args[0] {
	case "doctor":
		return c.doctor(ctx, args[1:])
	case "init":
		return c.initNetwork(ctx, args[1:])
	case "disconnect":
		return c.disconnect(ctx, args[1:])
	case "repair":
		return c.repair(ctx, args[1:])
	case "status":
		return c.status(ctx, args[1:])
	case "logs":
		return c.logs(args[1:])
	case "login":
		return c.login(ctx, args[1:])
	case "register":
		return c.register(ctx, args[1:])
	case "key":
		return c.key(args[1:])
	case "register-device":
		return c.registerDevice(ctx, args[1:])
	case "shares":
		return c.shares(ctx, args[1:])
	case "share":
		return c.share(ctx, args[1:])
	case "connect":
		return c.connect(ctx, args[1:])
	case "ui":
		return c.ui(ctx, args[1:])
	case "help", "-h", "--help":
		return c.usage()
	default:
		return fmt.Errorf("unknown agent command %q", args[0])
	}
}

func (c CLI) doctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := (windowsnet.Doctor{Runner: c.Runner}).Inspect(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(c.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Fprintf(c.Stdout, "Windows: %s (%s)\nPowerShell: %s\nGo: %s\nAdministrator: %t\n", report.OS, report.Architecture, report.PowerShell, report.Go, report.Administrator)
	if report.DefaultAdapter.Name != "" {
		a := report.DefaultAdapter
		fmt.Fprintf(c.Stdout, "Default interface: %s (index %d)\nLAN IPv4: %s/%d\nDefault gateway: %s\nDNS: %s\n", a.Name, a.Index, a.IPv4, a.PrefixLength, a.Gateway, strings.Join(a.DNS, ", "))
	} else {
		fmt.Fprintln(c.Stdout, "Default interface: not detected")
	}
	fmt.Fprintf(c.Stdout, "WireGuard: %s\nwg: %s\nWintun: %s\nNetNat: Get=%t New=%t\n", present(report.WireGuardExe), present(report.WGExe), present(report.WintunDLL), report.GetNetNat, report.NewNetNat)
	if len(report.ExistingNATs) == 0 {
		fmt.Fprintln(c.Stdout, "Existing NATs: none detected")
	} else {
		for _, nat := range report.ExistingNATs {
			fmt.Fprintf(c.Stdout, "Existing NAT: %s (%s, active=%t)\n", nat.Name, nat.Prefix, nat.Active)
		}
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(c.Stdout, "WARNING: %s\n", warning)
	}
	return nil
}

func (c CLI) usage() error {
	fmt.Fprintln(c.Stdout, "Usage: trafficshare-agent <doctor|status|logs|init|register|login|key|register-device|shares|share|connect|disconnect|repair|ui> [options]")
	return nil
}

func present(path string) string {
	if path == "" {
		return "not found"
	}
	return path
}

func (c CLI) initNetwork(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "", "configuration file")
	role := fs.String("role", "", "provider or consumer")
	sessionID := fs.String("session", "poc", "TrafficShare session id")
	endpoint := fs.String("endpoint", "", "provider LAN IPv4 (PoC only; production connect discovers it)")
	peer := fs.String("peer-public-key", "", "peer WireGuard public key")
	apply := fs.Bool("apply", false, "apply the displayed network plan (requires Administrator)")
	dryRun := fs.Bool("dry-run", false, "display the plan without applying it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doApply := *apply && !*dryRun
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *role != "" {
		cfg.Agent.Role = *role
	}
	app := App{Config: cfg, Runner: c.Runner}
	var preview Preview
	if cfg.Agent.Role == "provider" {
		preview, err = app.SetupProvider(ctx, SetupOptions{SessionID: *sessionID, PeerPublicKey: *peer, DryRun: !doApply})
	} else if cfg.Agent.Role == "consumer" {
		preview, err = app.SetupConsumer(ctx, SetupOptions{SessionID: *sessionID, EndpointIP: *endpoint, PeerPublicKey: *peer, DryRun: !doApply})
	} else {
		return fmt.Errorf("role must be provider or consumer")
	}
	printPreview(c.Stdout, preview, !doApply)
	return err
}

func printPreview(w io.Writer, p Preview, dry bool) {
	d := p.Doctor.DefaultAdapter
	fmt.Fprintf(w, "Mode: %s\nDetected adapter: %s (index %d)\nLAN IPv4: %s/%d\nDefault gateway: %s\nTunnel prefix: ", map[bool]string{true: "DRY-RUN", false: "APPLY"}[dry], d.Name, d.Index, d.IPv4, d.PrefixLength, d.Gateway)
	if len(p.Plan.Actions) > 0 {
		fmt.Fprintln(w, "10.66.0.0/24")
	} else {
		fmt.Fprintln(w, "not planned")
	}
	for i, action := range p.Plan.Actions {
		fmt.Fprintf(w, "%d. %s\n   resource: %s\n   PowerShell: %s\n", i+1, action.Description, action.Resource, action.Script)
	}
	if dry {
		fmt.Fprintln(w, "No network configuration was changed. Re-run with --apply from an Administrator terminal to execute this plan.")
	}
}

func (c CLI) disconnect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("disconnect", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "", "configuration file")
	sessionID := fs.String("session", "", "session id")
	apply := fs.Bool("apply", false, "perform cleanup")
	force := fs.Bool("force", false, "recover even after an abnormal exit")
	dryRun := fs.Bool("dry-run", false, "display cleanup only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doApply := *apply && !*dryRun
	_ = force
	if *sessionID == "" {
		return errors.New("--session is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	app := App{Config: cfg, Runner: c.Runner}
	plan, err := app.Disconnect(ctx, *sessionID, !doApply)
	if err == nil && doApply && cfg.Agent.Token != "" {
		_ = app.api().Disconnect(ctx, *sessionID)
	}
	for i, a := range plan.Actions {
		fmt.Fprintf(c.Stdout, "%d. %s (%s)\n", i+1, a.Description, a.Resource)
	}
	if !doApply {
		fmt.Fprintln(c.Stdout, "DRY-RUN: no network configuration was changed")
	}
	return err
}

func (c CLI) repair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("repair", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "", "configuration file")
	apply := fs.Bool("apply", false, "perform recovery")
	dryRun := fs.Bool("dry-run", false, "display recovery only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doApply := *apply && !*dryRun
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	plans, err := (App{Config: cfg, Runner: c.Runner}).Repair(ctx, !doApply)
	for _, p := range plans {
		fmt.Fprintf(c.Stdout, "Session %s: %d recovery actions\n", p.SessionID, len(p.Actions))
	}
	if len(plans) == 0 {
		fmt.Fprintln(c.Stdout, "No incomplete TrafficShare sessions found.")
	}
	if !doApply {
		fmt.Fprintln(c.Stdout, "DRY-RUN: no network configuration was changed")
	}
	return err
}

func (c CLI) status(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	v, err := (App{Config: cfg, Runner: c.Runner}).Status(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(c.Stdout).Encode(v)
	}
	sessions, _ := v["sessions"].([]map[string]any)
	fmt.Fprintf(c.Stdout, "User: %s\nDevice: %s\nRole: %s\nLAN IP: %v\nDefault interface: %v\nIncomplete/current sessions: %d\n", cfg.Agent.Username, cfg.Agent.DeviceID, cfg.Agent.Role, v["lan_ip"], v["default_interface"], len(sessions))
	return nil
}

func (c CLI) logs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(cfg.Agent.LogPath)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.Stdout, "No log file exists at", cfg.Agent.LogPath)
		return nil
	}
	if err != nil {
		return err
	}
	_, err = c.Stdout.Write(b)
	return err
}

func (c CLI) login(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "configs/local.json", "configuration file to update")
	username := fs.String("username", "", "username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || !*passwordStdin {
		return errors.New("--username and --password-stdin are required")
	}
	password, err := c.readSecret()
	if err != nil {
		return err
	}
	cfg, err := config.LoadIfExists(*configPath)
	if err != nil {
		return err
	}
	updated, err := (App{Config: cfg, Runner: c.Runner}).Login(ctx, *username, password)
	if err != nil {
		return err
	}
	if err := updated.Save(*configPath); err != nil {
		return err
	}
	fmt.Fprintln(c.Stdout, "Login succeeded; token saved to the local agent configuration.")
	return nil
}

func (c CLI) register(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "configs/local.json", "configuration file")
	username := fs.String("username", "", "username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || !*passwordStdin {
		return errors.New("--username and --password-stdin are required")
	}
	password, err := c.readSecret()
	if err != nil {
		return err
	}
	cfg, err := config.LoadIfExists(*configPath)
	if err != nil {
		return err
	}
	if err := (App{Config: cfg}).Register(ctx, *username, password); err != nil {
		return err
	}
	fmt.Fprintln(c.Stdout, "Registration succeeded.")
	return nil
}

func (c CLI) key(args []string) error {
	if len(args) == 0 || args[0] != "show" {
		return errors.New("usage: key show --config PATH")
	}
	fs := flag.NewFlagSet("key show", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	key, err := wireguard.LoadOrCreateKey(cfg.Agent.KeyPath)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Stdout, key.Public)
	return nil
}

func (c CLI) readSecret() (string, error) {
	if c.Stdin == nil {
		return "", errors.New("stdin is unavailable")
	}
	value, err := bufio.NewReader(c.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func (c CLI) registerDevice(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("register-device", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "configs/local.json", "configuration file")
	role := fs.String("role", "", "provider or consumer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *role != "" {
		cfg.Agent.Role = *role
	}
	d, err := (App{Config: cfg, Runner: c.Runner}).RegisterDevice(ctx)
	if err != nil {
		return err
	}
	cfg.Agent.DeviceID = d.ID
	cfg.Agent.DeviceName = d.DeviceName
	if err := cfg.Save(*configPath); err != nil {
		return err
	}
	fmt.Fprintf(c.Stdout, "Registered device %s (%s)\n", d.DeviceName, d.ID)
	return nil
}

func (c CLI) shares(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("shares", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "configs/local.json", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	shares, err := (App{Config: cfg}).api().Shares(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(c.Stdout).Encode(map[string]any{"shares": shares})
}

func (c CLI) share(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: share create --receiver USER --quota-gb N --hours N")
	}
	fs := flag.NewFlagSet("share create", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "configs/local.json", "configuration file")
	receiver := fs.String("receiver", "", "receiver username")
	quotaGB := fs.String("quota-gb", "20", "decimal GB quota")
	hours := fs.Int("hours", 24, "validity in hours")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	bytes, err := quota.ParseGB(*quotaGB)
	if err != nil {
		return err
	}
	share, err := (App{Config: cfg}).CreateShare(ctx, *receiver, bytes, time.Duration(*hours)*time.Hour)
	if err != nil {
		return err
	}
	return json.NewEncoder(c.Stdout).Encode(share)
}

func (c CLI) connect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	configPath := fs.String("config", "configs/local.json", "configuration file")
	shareID := fs.String("share", "", "share id")
	apply := fs.Bool("apply", false, "apply network configuration")
	dryRun := fs.Bool("dry-run", false, "display plan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	doApply := *apply && !*dryRun
	if *shareID == "" {
		return errors.New("--share is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	session, preview, err := (App{Config: cfg, Runner: c.Runner}).Connect(ctx, *shareID, !doApply)
	printPreview(c.Stdout, preview, !doApply)
	if session.ID != "" {
		fmt.Fprintln(c.Stdout, "Session:", session.ID)
	}
	return err
}

func parseInt(text string) (int, error) { return strconv.Atoi(text) }
func cleanPath(path string) string {
	if path == "" {
		return ""
	}
	p, _ := filepath.Abs(path)
	return p
}
