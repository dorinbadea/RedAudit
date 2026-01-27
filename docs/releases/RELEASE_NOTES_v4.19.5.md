# RedAudit v4.19.5 - Nuclei Resume Metadata Fix

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/docs/releases/RELEASE_NOTES_v4.19.5.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/docs/releases/RELEASE_NOTES_v4.19.5_ES.md)

## Summary

Resume reports now preserve target networks and total duration after Nuclei resumes.

## Added

- None.

## Improved

- Resume context restores missing target networks for consistent reporting.

## Fixed

- Resume summaries no longer reset duration to 0:00:00 after completing pending Nuclei targets.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.5.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.5/docs/INDEX.md)
