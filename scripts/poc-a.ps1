[CmdletBinding()]
param(
    [string]$Agent = ".\bin\trafficshare-agent.exe",
    [string]$SessionId = "poc-a",
    [string]$ConsumerPublicKey = "",
    [switch]$Apply
)

$ErrorActionPreference = "Stop"
$mode = if ($Apply) { "APPLY" } else { "DRY-RUN" }
Write-Host "TrafficShare Provider PoC ($mode)"
Write-Host "The command will detect the active adapter, LAN IPv4, interface index, gateway and existing NATs."
Write-Host "Planned resources: TrafficShare-Tunnel, TrafficShare-NAT, TrafficShare-WireGuard-UDP-$SessionId"

$arguments = @("init", "--role", "provider", "--session", $SessionId, "--peer-public-key", $ConsumerPublicKey)
if ($Apply) { $arguments += "--apply" } else { $arguments += "--dry-run" }
& $Agent @arguments
if ($LASTEXITCODE -ne 0) { throw "Provider PoC failed with exit code $LASTEXITCODE" }
