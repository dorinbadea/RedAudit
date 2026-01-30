# RedAudit v4.19.16 - Nuclei Output Coherence

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/docs/releases/RELEASE_NOTES_v4.19.16.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/docs/releases/RELEASE_NOTES_v4.19.16_ES.md)

## Summary

Clarifies Nuclei reporting and resume status so partial runs and suspected-only findings are reflected consistently.

## Added

- None.

## Improved

- Nuclei progress detail now reflects active batches to reduce parallelism confusion.

## Fixed

- Nuclei summaries now clear success on partial/timeouts and avoid "completed (no findings)" when results are incomplete.
- Resume summaries now retain timeout/failed batch info and recompute success consistently.
- Wizard yes/no label matching no longer mis-colors "Normal" timing options.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.16.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.16/docs/INDEX.md)
