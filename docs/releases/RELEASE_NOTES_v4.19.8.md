# RedAudit v4.19.8 - Resume Artifact Integrity

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/docs/releases/RELEASE_NOTES_v4.19.8.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/docs/releases/RELEASE_NOTES_v4.19.8_ES.md)

## Summary

Resume artifacts now stay consistent across summaries, targets, and JSONL exports while keeping Nuclei target lists intact.

## Added

- None.

## Improved

- Nuclei resume progress now reflects overall target counts with resume context.

## Fixed

- Resume summaries count hosts from existing results and preserve target networks.
- Nuclei resume no longer overwrites `nuclei_targets.txt`; pending targets stay in `nuclei_pending.txt`.
- JSONL exports backfill stub assets for vulnerability-only hosts to keep `asset_id` populated.
- Session logs retain INFO colors by honoring terminal TTY status.
- Deep identity warnings omit legacy strategy version suffixes.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.8.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.8/docs/INDEX.md)
