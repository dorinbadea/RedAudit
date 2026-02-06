# RedAudit v4.19.2 - Nuclei Resume Progress

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.2/docs/releases/RELEASE_NOTES_v4.19.2.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.2/docs/releases/RELEASE_NOTES_v4.19.2_ES.md)

## Summary

Clarifies Nuclei resume behavior and restores progress UI during budgeted resumes.

## Added

- None.

## Improved

- Resume runs now use the standard progress UI even when a runtime budget is set.
- Resume candidates are ordered by the latest update timestamp.

## Fixed

- Budget/timeout warnings now appear after resume runs with pending targets, and summaries capture resume budget metadata.

## Testing

- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.2.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.2/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.2/docs/INDEX.md)
