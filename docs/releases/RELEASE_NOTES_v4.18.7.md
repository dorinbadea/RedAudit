# RedAudit v4.18.7 - Accurate PCAP Summary Counts

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.7/docs/releases/RELEASE_NOTES_v4.18.7_ES.md)

## Summary

This patch fixes an inflated PCAP count in the CLI final summary by using per-run PCAP metadata.

## Added

- None.

## Improved

- None.

## Fixed

- CLI summary now reports the correct PCAP count for the current run, avoiding counts from other report folders.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.7 to get accurate CLI PCAP summaries.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.7/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.7/docs/INDEX.md)
