# RedAudit v4.19.18 - Nuclei Control and Timeout Clarity

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/docs/releases/RELEASE_NOTES_v4.19.18.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/docs/releases/RELEASE_NOTES_v4.19.18_ES.md)

## Summary

Adds Nuclei target exclusion controls and clearer progress/timeout diagnostics for long-running batches.

## Added

- Nuclei exclude list (CLI and wizard) to skip targets by host, host:port, or URL.
- Timeout warnings now include a host/port summary for the stalled batch.

## Improved

- Progress detail now shows retry attempts and split depth for Nuclei batches.
- Nuclei summaries include `targets_excluded` for traceability.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.18.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.18/docs/INDEX.md)
