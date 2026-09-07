package windowsnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
)

type Adapter struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Index        int      `json:"index"`
	Status       string   `json:"status"`
	IPv4         string   `json:"ipv4,omitempty"`
	PrefixLength int      `json:"prefix_length,omitempty"`
	Gateway      string   `json:"gateway,omitempty"`
	DNS          []string `json:"dns,omitempty"`
	Profile      string   `json:"profile,omitempty"`
}

type NATInfo struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	Active bool   `json:"active"`
}

type DoctorReport struct {
	OS             string    `json:"os"`
	Architecture   string    `json:"architecture"`
	PowerShell     string    `json:"powershell_version"`
	Go             string    `json:"go_version"`
	Administrator  bool      `json:"administrator"`
	Adapters       []Adapter `json:"active_adapters"`
	DefaultAdapter Adapter   `json:"default_adapter"`
	WireGuardExe   string    `json:"wireguard_exe,omitempty"`
	WGExe          string    `json:"wg_exe,omitempty"`
	WintunDLL      string    `json:"wintun_dll,omitempty"`
	GetNetNat      bool      `json:"get_net_nat_available"`
	NewNetNat      bool      `json:"new_net_nat_available"`
	ExistingNATs   []NATInfo `json:"existing_nats"`
	NATReadError   string    `json:"nat_read_error,omitempty"`
	Warnings       []string  `json:"warnings,omitempty"`
}

type Doctor struct {
	Runner CommandRunner
}

func ProviderReachable(ctx context.Context, runner CommandRunner, ip string) (bool, error) {
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		return false, errors.New("invalid provider IPv4 address")
	}
	result, err := RunPowerShell(ctx, runner, fmt.Sprintf(`if (Test-Connection -ComputerName '%s' -Count 1 -Quiet -ErrorAction SilentlyContinue) { 'true' } else { 'false' }`, ip))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(result.Stdout) == "true", nil
}

// Inspect is read-only. It never changes routes, interfaces, firewall rules or NAT.
func (d Doctor) Inspect(ctx context.Context) (DoctorReport, error) {
	if d.Runner == nil {
		return DoctorReport{}, fmt.Errorf("doctor command runner is nil")
	}
	result, err := RunPowerShell(ctx, d.Runner, doctorScript)
	if err != nil {
		return DoctorReport{}, err
	}
	var report DoctorReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err != nil {
		return DoctorReport{}, fmt.Errorf("decode doctor output: %w (output: %s)", err, result.Stdout)
	}
	report.Go = runtime.Version()
	if report.WireGuardExe == "" || report.WGExe == "" {
		report.Warnings = append(report.Warnings, "WireGuard for Windows is not fully installed")
	}
	if report.NATReadError != "" {
		report.Warnings = append(report.Warnings, "existing NAT configurations could not be read; run as Administrator before applying a plan")
	}
	return report, nil
}

const doctorScript = `$ErrorActionPreference = 'Stop'
$report = [ordered]@{
  os = [System.Environment]::OSVersion.VersionString
  architecture = $env:PROCESSOR_ARCHITECTURE
  powershell_version = $PSVersionTable.PSVersion.ToString()
  go_version = ''
  administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  active_adapters = @()
  default_adapter = $null
  wireguard_exe = ''
  wg_exe = ''
  wintun_dll = ''
  get_net_nat_available = [bool](Get-Command Get-NetNat -ErrorAction SilentlyContinue)
  new_net_nat_available = [bool](Get-Command New-NetNat -ErrorAction SilentlyContinue)
  existing_nats = @()
  nat_read_error = ''
  warnings = @()
}
$adapters = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {$_.OperationalStatus -eq 'Up'}
foreach ($adapter in $adapters) {
  try {
    $props = $adapter.GetIPProperties()
    $ipv4props = $props.GetIPv4Properties()
    if (-not $ipv4props) { continue }
    $ip = $props.UnicastAddresses | Where-Object {$_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $_.Address.ToString() -notlike '127.*' -and $_.Address.ToString() -notlike '169.254.*'} | Select-Object -First 1
    $gateway = $props.GatewayAddresses | Where-Object {$_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $_.Address.ToString() -ne '0.0.0.0'} | Select-Object -First 1
    $dns = @($props.DnsAddresses | Where-Object {$_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork} | ForEach-Object {$_.ToString()})
    $networkProfile = Get-NetConnectionProfile -InterfaceIndex $ipv4props.Index -ErrorAction SilentlyContinue | Select-Object -First 1
    $profileName = if ($networkProfile) { $networkProfile.NetworkCategory.ToString() } else { '' }
    $item = [ordered]@{name=$adapter.Name;description=$adapter.Description;index=$ipv4props.Index;status=$adapter.OperationalStatus.ToString();ipv4='';prefix_length=0;gateway='';dns=$dns;profile=$profileName}
    if ($ip) { $item.ipv4=$ip.Address.ToString(); $item.prefix_length=$ip.PrefixLength }
    if ($gateway) { $item.gateway=$gateway.Address.ToString() }
    $report.active_adapters += [pscustomobject]$item
    if ($gateway -and -not $report.default_adapter) { $report.default_adapter = [pscustomobject]$item }
  } catch {
    $report.warnings += "Skipping adapter '$($adapter.Name)': IPv4 properties are unavailable"
    continue
  }
}
$wgCandidates = @("$env:ProgramFiles\WireGuard\wireguard.exe", "$env:ProgramFiles\WireGuard\wg.exe")
if (Test-Path -LiteralPath $wgCandidates[0]) { $report.wireguard_exe = $wgCandidates[0] }
if (Test-Path -LiteralPath $wgCandidates[1]) { $report.wg_exe = $wgCandidates[1] }
$wintunCandidates = @("$env:ProgramFiles\WireGuard\wintun.dll", "$env:SystemRoot\System32\wintun.dll")
foreach ($candidate in $wintunCandidates) { if (Test-Path -LiteralPath $candidate) { $report.wintun_dll = $candidate; break } }
if ($report.get_net_nat_available) {
  try {
    foreach ($nat in @(Get-NetNat -ErrorAction Stop)) { $report.existing_nats += [pscustomobject]@{name=$nat.Name;prefix=$nat.InternalIPInterfaceAddressPrefix;active=[bool]$nat.Active} }
  } catch { $report.nat_read_error = $_.Exception.Message }
}
[pscustomobject]$report | ConvertTo-Json -Depth 8 -Compress`
