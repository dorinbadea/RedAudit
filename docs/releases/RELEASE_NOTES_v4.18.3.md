# RedAudit v4.18.3 - HyperScan Progress and Nuclei Wizard Clarity

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.3/docs/releases/RELEASE_NOTES_v4.18.3_ES.md)

## Summary

This release improves HyperScan progress output and clarifies Nuclei wizard options.

## Added

- None.

## Improved

- Nuclei profile labels now describe template scope instead of port coverage.
- The full coverage prompt now clarifies it scans all detected HTTP ports beyond 80/443.

## Fixed

- HyperScan progress no longer interleaves per-host status lines above the progress bar.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- No special steps. Update and run as usual.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.3/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.3/docs/INDEX.md)
