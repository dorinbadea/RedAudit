# RedAudit v4.19.17 - Installer Snap Bootstrap

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/docs/releases/RELEASE_NOTES_v4.19.17.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/docs/releases/RELEASE_NOTES_v4.19.17_ES.md)

## Summary

Improves installer fallbacks by provisioning snapd on Ubuntu-like systems so searchsploit and ZAP can be installed when apt packages are missing.

## Added

- None.

## Improved

- Snap-based tool installs now work on Ubuntu-like systems without preinstalled snapd.

## Fixed

- searchsploit and ZAP now install more reliably on Ubuntu derivatives when apt packages are unavailable.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.17.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.17/docs/INDEX.md)
