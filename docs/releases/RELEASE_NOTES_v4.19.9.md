# RedAudit v4.19.9 - Nuclei Resume UI Consistency

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/docs/releases/RELEASE_NOTES_v4.19.9.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/docs/releases/RELEASE_NOTES_v4.19.9_ES.md)

## Summary

Nuclei resume and progress output now match pending-only totals, report sequential vs parallel correctly, and align CLI messaging with the active language.

## Added

- None.

## Improved

- Nuclei batch and heartbeat status messages now use localized, consistent wording.

## Fixed

- Sequential Nuclei runs no longer report parallel batches when runtime budgets force sequential execution.
- Nuclei resume progress shows pending-only totals instead of full target counts.
- Spanish CLI output now localizes CVE correlation, output directory prompts, and elapsed strings.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.9.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/docs/INDEX.md)
