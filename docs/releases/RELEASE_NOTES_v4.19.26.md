# RedAudit v4.19.26 - Seed Keyring Bash Compatibility

[![Ver en Espa\u00f1ol](https://img.shields.io/badge/Ver_en_Espa\u00f1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.26/docs/releases/RELEASE_NOTES_v4.19.26_ES.md)

## Summary

Ensures the seed keyring script runs correctly even when invoked via `bash`.

## Added

- None.

## Improved

- None.

## Fixed

- `scripts/seed_keyring.py` now re-routes to Python when launched with `bash`.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.26.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.26/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.26/docs/INDEX.md)
