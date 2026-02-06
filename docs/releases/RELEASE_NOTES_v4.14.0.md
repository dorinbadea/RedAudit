[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.14.0/docs/releases/RELEASE_NOTES_v4.14.0_ES.md)

# RedAudit v4.14.0 - Consumer-Grade UX & Quality Fixes

This release focuses on delivering a consumer-grade user experience with enhanced wizard interactions, visually distinct menus, and significantly improved robust remediation guidance for diverse device types.

## Summary

- **Device-Aware Remediation**: Intelligent playbooks now distinguish between embedded devices (AVM FRITZ!), network gear, and Linux servers, providing tailored fix instructions (e.g., firmware updates vs. package managers).
- **Reduced False Positives**: Refined matching logic for CVSS-critical vulnerabilities (CVE-2024-54767) to target specific hardware models (FRITZ!Box 7530 vs 7590).
- **UX Polish**: The interactive wizard now features a professional color scheme and smarter credential flows.

## Added

- **Device-Aware Playbooks**:
  - **Embedded Devices**: Suggests Web UI firmware updates.
  - **Cisco/Network**: Suggests IOS updates.
  - **Linux**: Retains `apt/yum` commands.
- **Improved Type Safety**: Hardened internal logic against malformed vendor or host data.
- **Detailed Fallbacks**: Generates useful technical observations from raw service banners when tool-specific output is missing.

## Fixed

- **Playbook Titles**: Fixed a bug where URLs were incorrectly used as playbook titles.
- **Wizard Credentials**: Added prompt for manual configuration if keyring loading is declined.
- **Styling**: Applied generic DIM/BOLD color coding for better visual hierarchy in menus.

## Testing

- **Verified on**: macOS 26.2 (Darwin 25.2.0)
- **Python Versions**: 3.9, 3.10, 3.11, 3.12, 3.13
- **Test Suite**: 1937 tests passed (100% pass rate)

## Upgrade

```bash
git pull origin main
sudo bash redaudit_install.sh
```
