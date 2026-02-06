# RedAudit v4.19.20 - Resume HTML Refresh

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.20/docs/releases/RELEASE_NOTES_v4.19.20.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.20/docs/releases/RELEASE_NOTES_v4.19.20_ES.md)

## Summary

Ensures resume runs regenerate HTML reports when existing report artifacts are present.

## Added

- None.

## Improved

- None.

## Fixed

- Resume flows now detect `report.html` and regenerate HTML output as expected.

## Testing

- `pytest tests/core/test_auditor_orchestrator.py -v`

## Upgrade

No breaking changes. Update to v4.19.20.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.20/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.20/docs/INDEX.md)
