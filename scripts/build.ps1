[CmdletBinding()]
param(
    [string]$OutputDir = ".\dist\TrafficShare-Windows-x64",
    [string]$GoExe = "go.exe"
)

$ErrorActionPreference = "Stop"
$go = Get-Command $GoExe -ErrorAction SilentlyContinue
if (-not $go) { throw "Go 1.26 or newer is required to build from source." }

& $go.Source fmt ./...
if ($LASTEXITCODE -ne 0) { throw "go fmt failed" }
& $go.Source vet ./...
if ($LASTEXITCODE -ne 0) { throw "go vet failed" }
& $go.Source test -count=1 ./...
if ($LASTEXITCODE -ne 0) { throw "go test failed" }

$repoRoot = (Resolve-Path .).Path
$fullOutput = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDir))
$repoPrefix = $repoRoot.TrimEnd('\') + '\'
if (-not $fullOutput.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDir must stay inside the repository"
}
if (Test-Path -LiteralPath $fullOutput) {
    Remove-Item -LiteralPath $fullOutput -Recurse -Force
}
$OutputDir = $fullOutput
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$guiFlags = '-s -w -H=windowsgui'
& $go.Source build -trimpath -ldflags $guiFlags -o "$OutputDir\TrafficShare-Host.exe" .\cmd\trafficshare-host
if ($LASTEXITCODE -ne 0) { throw "Host build failed" }
& $go.Source build -trimpath -ldflags $guiFlags -o "$OutputDir\TrafficShare-Provider.exe" .\cmd\trafficshare-provider
if ($LASTEXITCODE -ne 0) { throw "Provider build failed" }
& $go.Source build -trimpath -ldflags $guiFlags -o "$OutputDir\TrafficShare-Client.exe" .\cmd\trafficshare-client
if ($LASTEXITCODE -ne 0) { throw "Client build failed" }
& $go.Source build -trimpath -ldflags '-s -w' -o "$OutputDir\trafficshare-server.exe" .\cmd\trafficshare-server
if ($LASTEXITCODE -ne 0) { throw "Server build failed" }
& $go.Source build -trimpath -ldflags '-s -w' -o "$OutputDir\TrafficShare.exe" .\cmd\trafficshare
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

Copy-Item -LiteralPath README.md -Destination "$OutputDir\README.md" -Force
Copy-Item -LiteralPath SECURITY.md -Destination "$OutputDir\SECURITY.md" -Force
Copy-Item -LiteralPath configs\server-cloud.example.json -Destination "$OutputDir\server-cloud.example.json" -Force

$resolved = Resolve-Path $OutputDir
$zip = Join-Path (Split-Path $resolved -Parent) "TrafficShare-Windows-x64.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path "$resolved\*" -DestinationPath $zip -CompressionLevel Optimal
New-Item -ItemType Directory -Force -Path .\release | Out-Null
Copy-Item -LiteralPath $zip -Destination .\release\TrafficShare-Windows-x64.zip -Force
Write-Host "Built package: $zip"
