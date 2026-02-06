# RedAudit v4.18.13 - Auditor Exclusions and SMB Domain Parsing

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.13/docs/releases/RELEASE_NOTES_v4.18.13_ES.md)

## Summary

This release adds explicit auditor IP exclusion metadata to the run manifest and fixes SMB domain parsing to avoid FQDN contamination in agentless summaries.

## Added

- Run manifest and pipeline summaries now include `auditor_exclusions` with excluded IPs and reasons.

## Improved

- None.

## Fixed

- SMB agentless parsing no longer falls through to FQDN lines when the domain field is blank.

## Testing

- `pytest tests/core/test_agentless_verify.py -v`
- `pytest tests/core/test_reporter.py -v`

## Upgrade

No breaking changes. Update to v4.18.13 for clearer auditor exclusion transparency and corrected SMB domain hints.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.13/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.13/docs/INDEX.md)
