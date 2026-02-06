# RedAudit v4.18.14 - Auditor Exclusion Fallback and Signature Store

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.14/docs/releases/RELEASE_NOTES_v4.18.14_ES.md)

## Summary

This release adds a data-driven signature store for vendor hints and Nuclei FP templates, and hardens auditor IP exclusion with best-effort local IP fallbacks.

## Added

- Signature data files for vendor hints and Nuclei FP template expectations.

## Improved

- None.

## Fixed

- Auditor IP exclusion now falls back to local IP discovery when network info and topology are empty.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.14 for clearer auditor exclusion safety and easier signature maintenance.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.14/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.14/docs/INDEX.md)
