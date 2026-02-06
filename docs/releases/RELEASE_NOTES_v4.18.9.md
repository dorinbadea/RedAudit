# RedAudit v4.18.9 - Report Traceability Fixes

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.9/docs/releases/RELEASE_NOTES_v4.18.9_ES.md)

## Summary

This release improves report traceability, reduces topology noise, and fixes false network leak flags.

## Added

- None.

## Improved

- HTML reports now show Nuclei profile and full coverage in the summary.
- ARP discovery deduplicates identical IP/MAC entries to reduce clutter.

## Fixed

- In-scope targets are filtered consistently in network leak detection.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.9 for cleaner reports and corrected leak detection.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.9/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.9/docs/INDEX.md)
