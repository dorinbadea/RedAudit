# Release Notes v4.3.0

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v4.3.0_ES.md)

**Release Date**: 2026-01-07
**Type**: Feature Release

## Highlights

### 🚀 HyperScan SYN Mode

Optional SYN-based port scanning using scapy for **~10x faster discovery** on large networks.

- **CLI Flag**: `--hyperscan-mode auto|connect|syn`
- **Auto Mode**: Tries SYN scan if running as root with scapy installed, otherwise falls back to TCP connect
- **Connect Mode**: Standard TCP connect (no root required, stealthier for IDS-sensitive environments)
- **SYN Mode**: Raw packet scanning (requires root + scapy, fastest option)

**Wizard Integration**: All profiles now support mode selection:

- Express: `auto` (fastest by default)
- Standard/Exhaustive with Stealth timing: `connect` (IDS evasion)
- Standard/Exhaustive with Normal/Aggressive timing: `auto`
- Custom: Explicit choice in Step 2

### 📊 Risk Score Breakdown Tooltip

HTML reports now show detailed risk score components on hover:

- Max CVSS Score
- Base Score calculation
- Density Bonus (for multiple vulns)
- Exposure Multiplier (for external-facing ports)

### 🎯 Identity Score Visualization

HTML reports display `identity_score` with color coding:

- 🟢 Green (≥3): Well-identified host
- 🟡 Yellow (=2): Partially identified
- 🔴 Red (<2): Weak identification (triggered deep scan)

Tooltip shows identity signals (hostname, vendor, MAC, etc.)

### 🔍 Smart-Check CPE Validation

Enhanced Nuclei false positive detection using CPE data:

- New functions: `parse_cpe_components()`, `validate_cpe_against_template()`, `extract_host_cpes()`
- Cross-validates findings against host CPEs before HTTP header checks
- Reduces false positives when CPE doesn't match expected vendor

### 📁 PCAP Management Utilities

New utilities for PCAP file organization:

- `merge_pcap_files()`: Consolidates capture files using `mergecap`
- `organize_pcap_files()`: Moves raw captures to subdirectory
- `finalize_pcap_artifacts()`: Orchestrates post-scan cleanup

## Breaking Changes

None. This release is fully backward compatible.

## New CLI Options

| Flag | Description |
|------|-------------|
| `--hyperscan-mode` | HyperScan discovery method: `auto`, `connect`, or `syn` |

## New Files

- `redaudit/core/syn_scanner.py` — Scapy-based SYN scanner module

## Dependencies

**Optional** (for SYN mode):

- `scapy` — Install with `pip install scapy` or `apt install python3-scapy`

## Upgrade Instructions

```bash
# Standard upgrade via auto-update
redaudit --check-update

# Or manual reinstall
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/main/redaudit_install.sh | sudo bash
```

## Testing Notes

- SYN mode requires root privileges (`sudo redaudit`)
- Test on Ubuntu/Debian with scapy installed for full functionality
- Fallback to connect mode works seamlessly when SYN is unavailable

## Contributors

- Dorin Badea ([@dorinbadea](https://github.com/dorinbadea))
