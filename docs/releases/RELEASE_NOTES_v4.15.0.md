# Release Notes v4.15.0

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.15.0/docs/releases/RELEASE_NOTES_v4.15.0_ES.md)

## Summary

Performance and UX sprint focused on HyperScan parallelism, Nuclei scan optimization, and terminal output consistency.

## Added

- **HyperScan Progress Bar**: Visual progress bar (magenta) showing host completion during HyperScan-First discovery phase.
- **Nuclei Auto-Fast Profile**: Automatic detection of hosts with 3+ HTTP ports, switching to "fast" profile (CVE-only templates) to prevent timeouts on complex hosts.

## Fixed

- **HyperScan True Parallelism**: Removed SYN scan lock that was serializing scans due to legacy scapy contention concerns. RustScan/asyncio now run in true parallel mode.
- **Minimalist Terminal Emojis**: Replaced colorful emojis with monochrome Unicode alternatives across 48 instances in 10+ files:
  - Check mark: ``
  - Cross mark: ``
  - Warning: `⚠`
- **Test Fixes**: Updated `test_session_log.py` to use new minimalist emojis.

## Testing

- Added `test_hyperscan_start_sequential_key_en` and `test_hyperscan_start_sequential_key_es` to verify i18n keys.
- All 1939 tests passed.
- Pre-commit hooks passed.

## Upgrade

```bash
git pull origin main
sudo bash redaudit_install.sh
```
