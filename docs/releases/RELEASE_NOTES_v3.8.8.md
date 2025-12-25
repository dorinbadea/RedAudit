# Release Notes v3.8.8

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.8.8_ES.md)

**Release Date**: 2025-12-25

## Highlights

This release introduces **HTTP Device Fingerprinting** to automatically identify network devices from their web interface titles, and fixes the CLI output noise issue for cleaner terminal capture logs.

## What's New

### HTTP Device Fingerprinting

RedAudit now automatically identifies device vendors and models by analyzing HTTP title and server headers during agentless verification. This is especially useful for:

- **Routers**: Vodafone, FRITZ!Box, TP-Link, NETGEAR, ASUS, Linksys, D-Link, Ubiquiti, MikroTik, Huawei, ZTE, DrayTek
- **Switches**: Cisco, HPE/Aruba, Juniper
- **Cameras**: Hikvision, Dahua, Axis, Reolink, ONVIF
- **IoT/Smart Home**: Philips Hue, Home Assistant, Tasmota, Shelly, Sonoff
- **NAS**: Synology, QNAP
- **Printers**: HP, Epson, Brother, Canon
- **Servers**: VMware ESXi, Proxmox, iLO/iDRAC

New fields in agentless fingerprint output:

- `device_vendor`: Identified manufacturer
- `device_model`: Specific model string
- `device_type`: Category (router, switch, camera, iot, nas, printer, server, etc.)

### CLI Output Noise Fix

Reduced Rich progress bar refresh rate from 10Hz to 4Hz across all 9 progress bars. This prevents excessive log file sizes when terminal output is captured externally (e.g., using the `script` command).

**Before**: ~479KB cli.txt with repeated spinner frames
**After**: ~20KB clean cli.txt matching internal session log

## Files Changed

- `redaudit/core/agentless_verify.py` - Added `_HTTP_DEVICE_PATTERNS` and `_fingerprint_device_from_http()`
- `redaudit/core/auditor.py` - Added `refresh_per_second=4` to 3 Progress bars
- `redaudit/core/auditor_scan.py` - Added `refresh_per_second=4` to 3 Progress bars
- `redaudit/core/auditor_vuln.py` - Added `refresh_per_second=4` to 1 Progress bar
- `redaudit/core/hyperscan.py` - Added `refresh_per_second=4` to 1 Progress bar
- `redaudit/core/nuclei.py` - Added `refresh_per_second=4` to 1 Progress bar

## Upgrade

```bash
redaudit --version  # Check current version
# If auto-update is enabled, RedAudit will prompt to update
# Or manually: curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/main/redaudit_install.sh | sudo bash
```

## Full Changelog

See [CHANGELOG.md](../../CHANGELOG.md) for the complete list of changes.
