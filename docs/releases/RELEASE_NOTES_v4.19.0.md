# RedAudit v4.19.0 - Nuclei Runtime Resume

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/docs/releases/RELEASE_NOTES_v4.19.0.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/docs/releases/RELEASE_NOTES_v4.19.0_ES.md)

## Summary

Adds a Nuclei runtime budget with resume artifacts and a wizard flow to continue pending targets without stopping the rest of the audit.

## Added

- Nuclei runtime budget with resume artifacts (`nuclei_resume.json`, `nuclei_pending.txt`) and a 15-second resume prompt.
- CLI resume flags: `--nuclei-max-runtime`, `--nuclei-resume`, `--nuclei-resume-latest`.
- Main menu entry to resume pending Nuclei runs.

## Improved

- Reports and schema now record Nuclei resume metadata and `nuclei_max_runtime` in the config snapshot.

## Fixed

- None.

## Testing

- `pytest tests/core/test_nuclei_helpers.py tests/core/test_auditor_orchestrator.py tests/core/test_auditor_run_complete_scan.py tests/cli/test_wizard.py tests/cli/test_cli.py tests/utils/test_config.py tests/core/test_auditor_defaults.py tests/core/test_reporter.py -q`

## Upgrade

No breaking changes. Update to v4.19.0.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/docs/INDEX.md)
