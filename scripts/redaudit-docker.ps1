# RedAudit Docker Scanner - Windows PowerShell Helper
# This script automatically detects your network and runs RedAudit
#
# Usage:
#   .\redaudit-docker.ps1                    # Interactive mode (Spanish)
#   .\redaudit-docker.ps1 -Lang en           # Interactive mode (English)
#   .\redaudit-docker.ps1 -Mode quick -Yes   # Quick non-interactive scan
#
# Requirements: Docker Desktop must be running

param(
    [string]$Target = "",
    [string]$Lang = "es",
    [string]$Mode = "",
    [switch]$Yes = $false,
    [string]$Output = ""
)

$Host.UI.RawUI.WindowTitle = "RedAudit Docker Scanner"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║          RedAudit Docker Scanner                  ║" -ForegroundColor Blue
Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

# Check if Docker is running
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Error: Docker is not running" -ForegroundColor Red
    Write-Host "  Please start Docker Desktop and try again."
    exit 1
}

# Detect network
function Get-LocalNetwork {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
           Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet|Docker|WSL' -and $_.IPAddress -notmatch '^169\.' } |
           Select-Object -First 1).IPAddress

    if ($ip) {
        $parts = $ip.Split('.')
        $network = "$($parts[0]).$($parts[1]).$($parts[2]).0/24"
        return @{ IP = $ip; Network = $network }
    }
    return $null
}

$networkInfo = Get-LocalNetwork

if (-not $Target) {
    if ($networkInfo) {
        Write-Host "✓ Detected your IP: $($networkInfo.IP)" -ForegroundColor Green
        Write-Host "✓ Target network: $($networkInfo.Network)" -ForegroundColor Cyan
        Write-Host ""

        $confirm = Read-Host "Use this network? [Y/n]"
        if ($confirm -match '^[Nn]') {
            $Target = Read-Host "Enter target network"
        } else {
            $Target = $networkInfo.Network
        }
    } else {
        Write-Host "⚠ Could not auto-detect your network." -ForegroundColor Yellow
        $Target = Read-Host "Enter target network (e.g., 192.168.1.0/24)"
    }
}

# Create reports directory
$ReportsDir = "C:\RedAudit-Reports"
if (-not (Test-Path $ReportsDir)) {
    New-Item -ItemType Directory -Path $ReportsDir | Out-Null
}
Write-Host "✓ Reports will be saved to: $ReportsDir" -ForegroundColor Green
Write-Host ""

# Pull latest image
Write-Host "→ Checking for updates..." -ForegroundColor Blue
docker pull ghcr.io/dorinbadea/redaudit:latest 2>&1 | Out-Null

# Build docker arguments
$dockerArgs = @(
    "run", "-it", "--rm",
    "-v", "${ReportsDir}:/reports",
    "ghcr.io/dorinbadea/redaudit:latest",
    "--target", $Target,
    "--lang", $Lang,
    "--output", "/reports"
)

if ($Mode) {
    $dockerArgs += @("--mode", $Mode)
}

if ($Yes) {
    $dockerArgs += "--yes"
}

# Run RedAudit
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "Starting RedAudit scan on $Target" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

& docker $dockerArgs

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "Scan complete! Reports saved to:" -ForegroundColor Green
Write-Host "$ReportsDir" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green

# Open report
$reportPath = Join-Path $ReportsDir "report.html"
if (Test-Path $reportPath) {
    Write-Host ""
    $openReport = Read-Host "Open HTML report in browser? [Y/n]"
    if ($openReport -notmatch '^[Nn]') {
        Start-Process $reportPath
    }
}
