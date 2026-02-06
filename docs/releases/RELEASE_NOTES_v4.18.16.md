# RedAudit v4.18.16 - Coverage Guardrail and Test Expansion

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.16/docs/releases/RELEASE_NOTES_v4.18.16_ES.md)

## Summary

This release adds a workflow guardrail for test coverage and expands automated tests to lift overall coverage to 98%.

## Added

- Workflow now requires 100% test coverage for modified code paths.

## Improved

- Expanded test coverage across updater flows to reach 98% overall coverage.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -q --cov=redaudit --cov-report=term-missing`

## Upgrade

No breaking changes. Update to v4.18.16 for coverage enforcement and expanded tests.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.16/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.16/docs/INDEX.md)
