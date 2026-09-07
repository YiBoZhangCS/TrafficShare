[CmdletBinding()]
param(
    [string]$Agent = ".\bin\trafficshare-agent.exe",
    [string]$Config = ".\configs\local.json",
    [switch]$Apply
)

$ErrorActionPreference = "Stop"
Write-Host "TrafficShare cleanup only processes resources recorded in state files and tagged TrafficShare-*."
$arguments = @("repair", "--config", $Config)
if ($Apply) {
    Write-Host "APPLY: recorded TrafficShare resources will be removed."
    $arguments += "--apply"
} else {
    Write-Host "DRY-RUN: no network configuration will be changed."
    $arguments += "--dry-run"
}
& $Agent @arguments
if ($LASTEXITCODE -ne 0) { throw "TrafficShare cleanup failed with exit code $LASTEXITCODE" }
