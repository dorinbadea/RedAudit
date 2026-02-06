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

# Detect if terminal supports ANSI colors
# PowerShell ISE does NOT support ANSI escape codes
$SupportsANSI = $true
if ($Host.Name -eq "Windows PowerShell ISE Host") {
    $SupportsANSI = $false
    Write-Host ""
    Write-Host "NOTA: PowerShell ISE no soporta colores ANSI." -ForegroundColor Yellow
    Write-Host "      Los colores seran deshabilitados automaticamente." -ForegroundColor Yellow
    Write-Host "      Para mejor experiencia, usa Windows Terminal." -ForegroundColor Yellow
    Write-Host ""
}

# Also check for older PowerShell without VT support
if ($PSVersionTable.PSVersion.Major -lt 5) {
    $SupportsANSI = $false
}

# Try to enable VT processing on Windows 10+
if ($SupportsANSI) {
    try {
        $Host.UI.RawUI.WindowTitle = "RedAudit Docker Scanner"
    } catch {}
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Blue
Write-Host "          RedAudit Docker Scanner                      " -ForegroundColor Blue
Write-Host "=======================================================" -ForegroundColor Blue
Write-Host ""

# Check if Docker is running
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "[OK] Docker esta corriendo" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Docker no esta corriendo" -ForegroundColor Red
    Write-Host "        Por favor, abre Docker Desktop y espera a que este listo."
    Write-Host ""
    Write-Host "        1. Abre Docker Desktop desde el menu Inicio"
    Write-Host "        2. Espera a que el icono de la ballena este verde"
    Write-Host "        3. Ejecuta este script de nuevo"
    Write-Host ""
    Read-Host "Presiona Enter para salir"
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
        Write-Host "[OK] Tu IP detectada: $($networkInfo.IP)" -ForegroundColor Green
        Write-Host "[OK] Red objetivo: $($networkInfo.Network)" -ForegroundColor Cyan
        Write-Host ""

        $confirm = Read-Host "Usar esta red? [S/n]"
        if ($confirm -match '^[Nn]') {
            $Target = Read-Host "Introduce la red objetivo (ej: 192.168.1.0/24)"
        } else {
            $Target = $networkInfo.Network
        }
    } else {
        Write-Host "[!] No se pudo detectar tu red automaticamente." -ForegroundColor Yellow
        $Target = Read-Host "Introduce la red objetivo (ej: 192.168.1.0/24)"
    }
}

# Create reports directory
$ReportsDir = "C:\RedAudit-Reports"
if (-not (Test-Path $ReportsDir)) {
    New-Item -ItemType Directory -Path $ReportsDir | Out-Null
}
Write-Host "[OK] Los informes se guardaran en: $ReportsDir" -ForegroundColor Green
Write-Host ""

# Pull latest image
Write-Host "[...] Descargando/Actualizando RedAudit..." -ForegroundColor Blue
docker pull ghcr.io/dorinbadea/redaudit:latest

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

# IMPORTANT: Add --no-color if terminal doesn't support ANSI
if (-not $SupportsANSI) {
    $dockerArgs += "--no-color"
    Write-Host "[INFO] Modo sin colores activado (terminal no compatible)" -ForegroundColor Yellow
}

# Run RedAudit
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "Iniciando escaneo RedAudit en $Target" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""

& docker $dockerArgs

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "Escaneo completado! Informes guardados en:" -ForegroundColor Green
Write-Host "$ReportsDir" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Green

# Open report
$reportPath = Join-Path $ReportsDir "report.html"
if (Test-Path $reportPath) {
    Write-Host ""
    $openReport = Read-Host "Abrir el informe HTML en el navegador? [S/n]"
    if ($openReport -notmatch '^[Nn]') {
        Start-Process $reportPath
    }
}
