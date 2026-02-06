# RedAudit v4.19.7 - Red Team Self-Target Exclusion

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/docs/releases/RELEASE_NOTES_v4.19.7.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/docs/releases/RELEASE_NOTES_v4.19.7_ES.md)

## Summary

Red Team discovery now excludes auditor IPs from target selection to prevent self-enumeration.

## Added

- None.

## Improved

- None.

## Fixed

- Red Team target selection now skips auditor IPs before enumeration starts.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.7.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.7/docs/INDEX.md)
