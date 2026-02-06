# RedAudit v4.18.17 - HyperScan Summary Alignment and UDP Visibility

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.17/docs/releases/RELEASE_NOTES_v4.18.17_ES.md)

## Summary

This release aligns HyperScan-First summary counts with CLI output and exposes UDP discovery totals in pipeline summaries and HTML reports.

## Added

- Pipeline net discovery counts now include total HyperScan UDP ports for report visibility.
- HTML pipeline summaries now show the HyperScan UDP port count.

## Improved

- Report schema documentation now includes the HyperScan UDP count field.

## Fixed

- HyperScan-First comparisons now track TCP-only discovery to match CLI output.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.17 for aligned HyperScan summaries and UDP visibility.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.17/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.17/docs/INDEX.md)
