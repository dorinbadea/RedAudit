# RedAudit v4.19.15 - Installer ShellCheck Cleanup

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/docs/releases/RELEASE_NOTES_v4.19.15.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/docs/releases/RELEASE_NOTES_v4.19.15_ES.md)

## Summary

Removed unused installer variables to keep ShellCheck clean without altering behavior.

## Added

- None.

## Improved

- None.

## Fixed

- ShellCheck no longer flags unused distro variables in the installer.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.15.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/docs/INDEX.md)
