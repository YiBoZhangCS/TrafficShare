package windowsnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const ResourcePrefix = "TrafficShare-"

// Windows Firewall rejects ::/0 on some supported Windows builds. The
// equivalent inclusive range is accepted consistently and still matches only
// IPv6 destinations.
const allIPv6AddressRange = "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

type Action struct {
	Description string `json:"description"`
	Script      string `json:"script"`
	Resource    string `json:"resource,omitempty"`
}

type Plan struct {
	SessionID string   `json:"session_id"`
	Role      string   `json:"role"`
	Actions   []Action `json:"actions"`
}

type PlanOptions struct {
	SessionID       string
	TunnelAlias     string
	TunnelPrefix    string
	NATName         string
	EndpointIP      string
	InterfaceIndex  int
	Gateway         string
	ListenPort      int
	ControlPort     int
	FirewallProfile string
}

var safeName = regexp.MustCompile(`^TrafficShare-[A-Za-z0-9_.-]+$`)

func validateOptions(o PlanOptions) error {
	if !safeName.MatchString(o.TunnelAlias) || !safeName.MatchString(o.NATName) {
		return errors.New("resource names must begin with TrafficShare- and contain only safe characters")
	}
	if o.SessionID == "" || strings.ContainsAny(o.SessionID, "'\"; ") {
		return errors.New("invalid session id")
	}
	if o.ListenPort < 1 || o.ListenPort > 65535 {
		return errors.New("invalid WireGuard listen port")
	}
	_, network, err := net.ParseCIDR(o.TunnelPrefix)
	if err != nil || network.IP.To4() == nil {
		return errors.New("invalid IPv4 tunnel prefix")
	}
	if o.EndpointIP != "" && net.ParseIP(o.EndpointIP).To4() == nil {
		return errors.New("invalid provider endpoint IPv4")
	}
	if o.Gateway != "" && net.ParseIP(o.Gateway).To4() == nil {
		return errors.New("invalid original IPv4 gateway")
	}
	return nil
}

func ProviderPlan(o PlanOptions) (Plan, error) {
	if err := validateOptions(o); err != nil {
		return Plan{}, err
	}
	firewall := ResourcePrefix + "WireGuard-UDP-" + o.SessionID
	profile := o.FirewallProfile
	if profile == "" {
		profile = "Private,Domain"
	}
	if profile != "Public" && profile != "Private" && profile != "Domain" && profile != "Private,Domain" {
		return Plan{}, errors.New("invalid Windows firewall profile")
	}
	actions := []Action{
		{Description: "enable IPv4 forwarding on the WireGuard interface", Resource: o.TunnelAlias, Script: fmt.Sprintf("Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -Forwarding Enabled -ErrorAction Stop", o.TunnelAlias)},
		{Description: "create NAT for the TrafficShare tunnel prefix", Resource: o.NATName, Script: fmt.Sprintf("if (-not (Get-NetNat -Name '%s' -ErrorAction SilentlyContinue)) { New-NetNat -Name '%s' -InternalIPInterfaceAddressPrefix '%s' -ErrorAction Stop | Out-Null }", o.NATName, o.NATName, o.TunnelPrefix)},
		{Description: "allow WireGuard UDP from LocalSubnet on the active network profile", Resource: firewall, Script: fmt.Sprintf("New-NetFirewallRule -DisplayName '%s' -Direction Inbound -Action Allow -Protocol UDP -LocalPort %d -RemoteAddress LocalSubnet -Profile %s -ErrorAction Stop | Out-Null", firewall, o.ListenPort, profile)},
	}
	if o.ControlPort > 0 {
		if o.ControlPort > 65535 {
			return Plan{}, errors.New("invalid control server port")
		}
		controlRule := ResourcePrefix + "Control-TCP-" + o.SessionID
		actions = append(actions, Action{Description: "allow the embedded control server from LocalSubnet", Resource: controlRule, Script: fmt.Sprintf("if (-not (Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '%s' -Direction Inbound -Action Allow -Protocol TCP -LocalPort %d -RemoteAddress LocalSubnet -Profile %s -ErrorAction Stop | Out-Null }", controlRule, controlRule, o.ControlPort, profile)})
	}
	return Plan{SessionID: o.SessionID, Role: "provider", Actions: actions}, nil
}

func ConsumerPlan(o PlanOptions) (Plan, error) {
	if err := validateOptions(o); err != nil {
		return Plan{}, err
	}
	if o.InterfaceIndex <= 0 || o.Gateway == "" || o.EndpointIP == "" {
		return Plan{}, errors.New("consumer plan requires endpoint IP, original interface index and gateway")
	}
	routeName := ResourcePrefix + "EndpointRoute-" + o.SessionID
	ipv6Rule := ResourcePrefix + "Block-IPv6-" + o.SessionID
	return Plan{SessionID: o.SessionID, Role: "consumer", Actions: []Action{
		{Description: "pin provider endpoint to the original LAN gateway to avoid tunnel recursion", Resource: routeName, Script: fmt.Sprintf("New-NetRoute -DestinationPrefix '%s/32' -InterfaceIndex %d -NextHop '%s' -PolicyStore ActiveStore -ErrorAction Stop | Out-Null", o.EndpointIP, o.InterfaceIndex, o.Gateway)},
		{Description: "block IPv6 egress during the IPv4-only session to prevent bypass", Resource: ipv6Rule, Script: fmt.Sprintf("New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -RemoteAddress '%s' -Profile Any -ErrorAction Stop | Out-Null", ipv6Rule, allIPv6AddressRange)},
	}}, nil
}

type Engine struct {
	Runner CommandRunner
}

func (e Engine) Apply(ctx context.Context, plan Plan, dryRun bool) ([]Result, error) {
	if e.Runner == nil {
		return nil, errors.New("network command runner is nil")
	}
	if dryRun {
		return make([]Result, len(plan.Actions)), nil
	}
	admin, err := IsAdministrator(ctx, e.Runner)
	if err != nil {
		return nil, err
	}
	if !admin {
		return nil, errors.New("Administrator privileges are required")
	}
	results := make([]Result, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		result, err := RunPowerShell(ctx, e.Runner, action.Script)
		results = append(results, result)
		if err != nil {
			return results, fmt.Errorf("%s: %w", action.Description, err)
		}
	}
	return results, nil
}

func IsAdministrator(ctx context.Context, runner CommandRunner) (bool, error) {
	r, err := RunPowerShell(ctx, runner, `if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'true' } else { 'false' }`)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(r.Stdout) == "true", nil
}

func EnsureNoProviderConflicts(ctx context.Context, runner CommandRunner, natName, tunnelName, firewallName string) error {
	script := fmt.Sprintf(`$items=@();if(Get-NetNat -Name '%s' -ErrorAction SilentlyContinue){$items+='NAT %s'};if(Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue){$items+='Firewall %s'};if(Get-Service -Name 'WireGuardTunnel$%s' -ErrorAction SilentlyContinue){$items+='Tunnel %s'};$items -join ', '`, natName, natName, firewallName, firewallName, tunnelName, tunnelName)
	r, err := RunPowerShell(ctx, runner, script)
	if err != nil {
		return err
	}
	if value := strings.TrimSpace(r.Stdout); value != "" {
		return fmt.Errorf("planned TrafficShare resources already exist (%s); run repair or choose non-conflicting names", value)
	}
	return nil
}

func EnsureNoConsumerConflicts(ctx context.Context, runner CommandRunner, endpointIP string, interfaceIndex int, tunnelName, firewallName string) error {
	script := fmt.Sprintf(`$items=@();if(Get-NetRoute -DestinationPrefix '%s/32' -InterfaceIndex %d -ErrorAction SilentlyContinue){$items+='Endpoint route'};if(Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue){$items+='Firewall %s'};if(Get-Service -Name 'WireGuardTunnel$%s' -ErrorAction SilentlyContinue){$items+='Tunnel %s'};$items -join ', '`, endpointIP, interfaceIndex, firewallName, firewallName, tunnelName, tunnelName)
	r, err := RunPowerShell(ctx, runner, script)
	if err != nil {
		return err
	}
	if value := strings.TrimSpace(r.Stdout); value != "" {
		return fmt.Errorf("planned TrafficShare resources already exist (%s); run repair or choose non-conflicting names", value)
	}
	return nil
}

func CleanupPlan(sessionID string, resources []string, tunnelAlias string) (Plan, error) {
	if sessionID == "" || !safeName.MatchString(tunnelAlias) {
		return Plan{}, errors.New("invalid cleanup identifiers")
	}
	actions := []Action{}
	for _, resource := range resources {
		if !safeName.MatchString(resource) {
			return Plan{}, fmt.Errorf("refusing to delete untagged resource %q", resource)
		}
		switch {
		case strings.Contains(resource, "Firewall"), strings.Contains(resource, "WireGuard-UDP"), strings.Contains(resource, "Block-IPv6"), strings.Contains(resource, "Control-TCP"):
			actions = append(actions, Action{Description: "remove TrafficShare firewall rule", Resource: resource, Script: fmt.Sprintf("if (Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -DisplayName '%s' -ErrorAction Stop }", resource, resource)})
		case strings.Contains(resource, "NAT"):
			actions = append(actions, Action{Description: "remove TrafficShare NAT", Resource: resource, Script: fmt.Sprintf("if (Get-NetNat -Name '%s' -ErrorAction SilentlyContinue) { Remove-NetNat -Name '%s' -Confirm:$false -ErrorAction Stop }", resource, resource)})
		case strings.Contains(resource, "EndpointRoute"):
			// Route removal is performed from recorded destination/index/gateway data by the state restorer.
			continue
		}
	}
	return Plan{SessionID: sessionID, Role: "cleanup", Actions: actions}, nil
}
