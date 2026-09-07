[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ProviderLanIP,
    [Parameter(Mandatory = $true)][string]$ProviderPublicKey,
    [string]$Agent = ".\bin\trafficshare-agent.exe",
    [string]$SessionId = "poc-b",
    [switch]$Apply
)

$ErrorActionPreference = "Stop"
$mode = if ($Apply) { "APPLY" } else { "DRY-RUN" }
Write-Host "TrafficShare Consumer PoC ($mode)"
Write-Host "The endpoint route will pin $ProviderLanIP to the original LAN gateway before the tunnel starts."
Write-Host "Planned resources: TrafficShare-Tunnel, TrafficShare-EndpointRoute-$SessionId, TrafficShare-Block-IPv6-$SessionId"

$arguments = @("init", "--role", "consumer", "--session", $SessionId, "--endpoint", $ProviderLanIP, "--peer-public-key", $ProviderPublicKey)
if ($Apply) { $arguments += "--apply" } else { $arguments += "--dry-run" }
& $Agent @arguments
if ($LASTEXITCODE -ne 0) { throw "Consumer PoC failed with exit code $LASTEXITCODE" }
