# RedAudit v4.19.1 - Nuclei Budget Enforcement

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/docs/releases/RELEASE_NOTES_v4.19.1.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/docs/releases/RELEASE_NOTES_v4.19.1_ES.md)

## Summary

Fixes Nuclei runtime budget enforcement and clarifies progress/reporting when a budget ends a run.

## Added

- None.

## Improved

- Report summaries now include `budget_exceeded` when the runtime budget ends the Nuclei phase.
- Manual and usage docs now clarify total budget behavior, sequential batching, and resume artifacts.

## Fixed

- Batches are capped to the remaining budget and stop mid-batch with pending targets preserved.
- Progress detail lines use the status color, and budget-only stops no longer display timeout warnings.

## Testing

- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.1.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.1/docs/INDEX.md)
