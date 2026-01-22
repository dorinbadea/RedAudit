# RedAudit v4.18.6 - Auth Scan Robustness and Reporting Clarity

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.6/docs/releases/RELEASE_NOTES_v4.18.6_ES.md)

## Summary

This patch hardens authenticated scan storage, improves PCAP reporting accuracy, tightens identity threshold validation, and aligns documentation details.

## Added

- None.

## Improved

- Documentation now clarifies thread fallback, jitter behavior, identity threshold range, and USAGE section numbering.

## Fixed

- Lynis results now store safely for Host objects during authenticated scans.
- Removed duplicate `host_agentless` assignment in the Nuclei false-positive filter path.
- CLI summary now counts all PCAP artifacts, including full capture files.
- `--identity-threshold` is now bounded to 0-100 with a safe fallback.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.6 and re-run scans to pick up the fixes.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.6/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.6/docs/INDEX.md)
