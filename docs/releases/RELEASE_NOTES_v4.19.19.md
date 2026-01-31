# RedAudit v4.19.19 - Nuclei Progress Rendering Fixes

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/docs/releases/RELEASE_NOTES_v4.19.19.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/docs/releases/RELEASE_NOTES_v4.19.19_ES.md)

## Summary

Fixes Nuclei progress rendering: status colors now appear correctly during Rich progress, and running batches no longer show 100% completion.

## Added

- None.

## Improved

- None.

## Fixed

- Status messages now respect warning/error colors during Rich progress output.
- Nuclei progress no longer reports 100% while batches are still running (ES detail handling).

## Testing

- `pytest tests/cli/test_ui_manager.py tests/core/test_auditor_orchestrator.py -v`

## Upgrade

No breaking changes. Update to v4.19.19.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.19/docs/INDEX.md)
