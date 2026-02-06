[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.13.0/docs/releases/RELEASE_NOTES_v4.13.0_ES.md)

# Release Notes v4.13.0 - Phase 4.13 Resilience

**Release Date**: 2026-01-17

## Summary

This release introduces the **Dead Host Retries** feature to improve scan resilience on networks with unresponsive hosts. It also includes i18n fixes for Nuclei profile time estimates.

## Added

- **Dead Host Retries** (`--dead-host-retries`): New CLI flag to abandon hosts after N consecutive timeouts (default: 3). Prevents scan stalls on unresponsive hosts.
- **ConfigurationContext Integration**: Added `dead_host_retries` property to the typed configuration wrapper for consistent access.

## Fixed

- **i18n Nuclei Time Estimates**: Corrected wizard profile time estimates:
  - `fast`: Was showing ~15min, now shows ~30-60min (realistic)
  - `balanced`: Was showing ~30min, now shows ~1h (realistic)
- **Wizard Text Truncation**: Shortened Spanish wizard profile descriptions to prevent terminal truncation on narrow displays.

## Upgrade

```bash
sudo redaudit  # Option 2: Check for Updates
# or
pip install --upgrade redaudit
```

## Full Changelog

See [CHANGELOG.md](https://github.com/dorinbadea/RedAudit/blob/main/CHANGELOG.md) for complete history.
