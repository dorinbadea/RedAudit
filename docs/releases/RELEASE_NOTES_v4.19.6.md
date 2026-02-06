# RedAudit v4.19.6 - Nuclei Progress Detail and INFO Contrast

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/docs/releases/RELEASE_NOTES_v4.19.6.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/docs/releases/RELEASE_NOTES_v4.19.6_ES.md)

## Summary

Nuclei resume progress now reports parallel batch completion correctly and INFO output uses the standard blue color for readability.

## Added

- None.

## Improved

- Progress detail messaging now reflects parallel batch completion counts.

## Fixed

- INFO status lines no longer appear white in terminals that render cyan as white.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.6.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.6/docs/INDEX.md)
