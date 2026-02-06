[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.11.0/docs/releases/RELEASE_NOTES_v4.11.0.md) [![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.11.0/docs/releases/RELEASE_NOTES_v4.11.0_ES.md)

# RedAudit v4.11.0 Release Notes

## Summary

RedAudit v4.11.0 is a performance-focused release that introduces **Nuclei Scan Profiles**, dramatically improves **IoT Device Visibility**, and massively expands the **OUI Vendor Database**. This release addresses timeouts in dense networks by allowing users to choose between `fast`, `balanced`, and `full` scanning modes, and fixes critical blind spots in detecting smart home devices like WiZ bulbs that rely on specific UDP ports.

## Added

- **Nuclei Profile Selector**: Added `--profile` flag to control scan intensity and speed.
  - `full`: Complete scan with all templates (Default).
  - `balanced`: High-impact tags only (~4x faster).
  - `fast`: Critical CVEs and misconfigurations (~10x faster).
- **IoT Protocol Support**: Added specific detection for **WiZ Smart Bulbs** (UDP port 38899). These devices are now correctly identified and tagged as `iot`, preventing them from appearing as "closed" hosts.
- **Documentation**: Added "Closed-Port IoT" section to README, explaining how RedAudit detects devices visible only via multicast/broadcast.

## Improved

- **Nuclei Stability**:
  - Reduced batch size from 25 to 10 targets to prevent congestion.
  - Increased timeout from 300s to 600s for large batches.
  - Scans now return partial results even if specific batches fail, improving resilience.
- **Identity Engine**: Updated OUI (MAC Address) database from ~46 entries to **38,911 vendors**. "Unknown" vendor tags should now be extremely rare.
- **Timeout Verification**: Validated timeouts for Nikto (330s), TestSSL (90s), and WhatWeb (30s) as adequate for modern audit conditions.

## Fixed

- **Type Safety**: Fixed a `mypy` type error in `nuclei.py` related to findings list validation.

## Testing

- **Automated**: `pytest` suite passed (Core, CLI, Utils).
- **Manual**:
  - Verified `balanced` profile completes significantly faster on test subnets.
  - Confirmed 8+ WiZ bulbs are now visible with identifying metadata.
  - Verified timeout handling does not prematurely kill valid long-running scans.

## Upgrade

No breaking changes. Update and install dependencies:

```bash
git pull origin main
pip install -e .
```
