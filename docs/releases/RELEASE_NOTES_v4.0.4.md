# Release Notes v4.0.4

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v4.0.4_ES.md)

**Release Date:** 2026-01-05

This hotfix release addresses critical detection gaps and fixes a CLI visual regression introduced in v4.0.x.

## Highlights

### HyperScan Port Integration Fix

When HyperScan detected open ports during net_discovery but the initial nmap scan found none (due to identity threshold), we now force a deep scan. This fixes the Metasploitable2 detection gap where 10+ ports were detected by HyperScan but ignored.

### CLI Visual Regression Fixed

Restored full color output and visual feedback:

- `[INFO]` → bright blue
- `[WARN]` → bright yellow
- `[FAIL]` → bright red
- `[OK]` → bright green
- Spinner restored to progress bar
- Progress bar now shows IP string instead of raw `Host(...)` object

## Fixed

- **Critical: HyperScan Port Integration**: Force deep scan when HyperScan ports detected but nmap found none
- **Vulnerability Detection Gap**: Hosts with HTTP fingerprints now correctly trigger web vulnerability scanning
- **Port-based Web Detection**: Added `WEB_LIKELY_PORTS` constant for common web ports (3000, 8080, etc.)
- **Vuln Scan Host Selection**: Better selection of hosts for vulnerability scanning
- **Agentless Summary Accuracy**: HTTP signal counting fixed
- **Descriptive Title Priority**: SSL/TLS issues now rank above minor info leaks
- **CLI Visual Regression**: Changed from Rich markup to `rich.text.Text` objects
- **Progress Bar Display**: Now shows clean IP string instead of `Host(ip='...')`
- **Spinner Restored**: Re-added `SpinnerColumn` for visual feedback
- **UIManager State Sync**: Added `progress_active_callback` for consistent colors

## Changed

- **Deep Scan Logic**: Uses HyperScan ports as signal (`hyperscan_ports_detected` reason)
- **HyperScan Fallback**: When nmap times out, populate ports from HyperScan data
- **Rich Colors**: Upgraded to `bright_*` variants for better dark theme visibility

## Upgrade

```bash
git pull origin main
sudo bash redaudit_install.sh
```

## Verification

Run a scan to verify the fixes:

```bash
sudo redaudit --target <your-network> --mode full --nuclei --yes
```

You should see:

- Full color output for all status messages
- Spinner animation in progress bar
- Deep scan triggered for hosts with HyperScan-detected ports
