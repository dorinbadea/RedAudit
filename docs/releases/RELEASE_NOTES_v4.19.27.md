# RedAudit v4.19.27 - Nuclei Warning and Resume Cancel

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.27/docs/releases/RELEASE_NOTES_v4.19.27_ES.md)

## Summary

Clarifies the Nuclei runtime warning before scans start and ensures Ctrl+C cancels Nuclei resumes cleanly.

## Added

- None.

## Improved

- None.

## Fixed

- Nuclei runtime warning is now specific to Nuclei and shown before scan start.
- Ctrl+C during Nuclei resume now cancels cleanly without a stack trace.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.27.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.27/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.27/docs/INDEX.md)
