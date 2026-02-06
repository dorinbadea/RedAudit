# RedAudit v4.18.15 - Hostname Hint Store

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.15/docs/releases/RELEASE_NOTES_v4.18.15_ES.md)

## Summary

This release externalizes hostname-based device hints into the signature data store to keep identity and asset classification configurable.

## Added

- None.

## Improved

- Hostname-based device hints now load from the signature data file for identity and asset classification.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.15 for data-driven hostname hints.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.15/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.15/docs/INDEX.md)
