# RedAudit v4.19.11 - Installer Toolchain Resilience

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/docs/releases/RELEASE_NOTES_v4.19.11.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/docs/releases/RELEASE_NOTES_v4.19.11_ES.md)

## Summary

The installer now handles Ubuntu package gaps by enabling Universe/Multiverse and installing missing tools from GitHub when apt cannot provide them.

## Added

- None.

## Improved

- Installer flow now continues when individual apt packages are unavailable and applies targeted fallbacks.

## Fixed

- Ubuntu installs no longer fail when `exploitdb`, `enum4linux`, or `nuclei` are missing from apt.
- Nuclei, exploitdb/searchsploit, and enum4linux are installed via GitHub fallbacks when required.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.11.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.11/docs/INDEX.md)
