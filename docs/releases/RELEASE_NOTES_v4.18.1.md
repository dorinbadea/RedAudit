# RedAudit v4.18.1 - Report Consistency and Nuclei Policy

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.1/docs/releases/RELEASE_NOTES_v4.18.1_ES.md)

## Summary

This release aligns Nuclei reporting with actual execution state and keeps audit intent consistent when full coverage is enabled.

## Added

- None.

## Improved

- Nuclei summary in HTML and TXT now surfaces partial and suspected-only outcomes.

## Fixed

- Nuclei partial status, timeout batches, and failed batches are now shown in reports.
- Vulnerability source counts reflect enriched findings instead of falling back to `unknown`.
- Auto-fast profile switching is skipped when full coverage is enabled to honor the selected profile.

## Testing

- `pytest tests/ -v`

## Upgrade

- No special steps. Update and run as usual.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.1/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.1/docs/INDEX.md)
