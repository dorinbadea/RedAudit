# RedAudit v4.19.34 - Risk Breakdown Traceability

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.34/docs/releases/RELEASE_NOTES_v4.19.34_ES.md)

## Summary

Risk breakdowns now separate evidence-backed signals from heuristics, authenticated scan failures surface in reports, and asset exports include open ports for inventory pipelines.

## Added

- None.

## Improved

- Risk breakdown tooltips expose evidence vs heuristic signals and the max-CVSS source.
- Authenticated scan failures appear in HTML and summary exports.

## Fixed

- `assets.jsonl` now includes open ports for downstream inventory use.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.34.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.34/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.34/docs/INDEX.md)
