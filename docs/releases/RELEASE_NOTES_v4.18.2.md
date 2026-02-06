# RedAudit v4.18.2 - UI Colors and Report Consistency

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.2/docs/releases/RELEASE_NOTES_v4.18.2_ES.md)

## Summary

This release fixes UI color consistency during progress output and aligns report/manifest counts with generated artifacts.

## Added

- None.

## Improved

- Nuclei full coverage defaults now follow the selected Nuclei profile (Full => Yes, Balanced/Fast => No).

## Fixed

- Status colors now render correctly during HyperScan progress output.
- Summary vulnerability sources now match consolidated findings.
- Run manifest PCAP counts now reflect all listed artifacts.
- Spanish Nuclei full coverage prompt text updated for clarity.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- No special steps. Update and run as usual.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.2/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.2/docs/INDEX.md)
