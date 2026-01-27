# RedAudit v4.19.4 - Nuclei Resume Budget Control

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/docs/releases/RELEASE_NOTES_v4.19.4.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/docs/releases/RELEASE_NOTES_v4.19.4_ES.md)

## Summary

Nuclei resume now supports budget overrides and budget-aware batching to reduce unnecessary re-scans.

## Added

- Resume prompts allow changing or disabling the saved Nuclei runtime budget (0 = unlimited).
- CLI resume honors `--nuclei-max-runtime` overrides.

## Improved

- Budgeted runs skip starting a new batch when remaining time cannot cover the estimated batch runtime.
- Resume state updates the saved budget when an override is selected.

## Fixed

- Reduced repeated target scans when a budget is nearly exhausted.

## Testing

- `pytest tests/core/test_nuclei_helpers.py tests/core/test_auditor_orchestrator.py tests/cli/test_cli.py -v`

## Upgrade

No breaking changes. Update to v4.19.4.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/docs/INDEX.md)
