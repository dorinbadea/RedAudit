# RedAudit v4.19.14 - Searchsploit Snap Fallback

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.14/docs/releases/RELEASE_NOTES_v4.19.14.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.14/docs/releases/RELEASE_NOTES_v4.19.14_ES.md)

## Summary

searchsploit now falls back to a snap install when GitHub-based installer paths fail.

## Added

- None.

## Improved

- None.

## Fixed

- searchsploit installs on Ubuntu now use a snap fallback if GitHub-based methods fail.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.14.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.14/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.14/docs/INDEX.md)
