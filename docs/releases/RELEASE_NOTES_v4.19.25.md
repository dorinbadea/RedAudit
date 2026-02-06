# RedAudit v4.19.25 - BetterCAP Cleanup

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.25/docs/releases/RELEASE_NOTES_v4.19.25_ES.md)

## Summary

Ensures BetterCAP is terminated after L2 recon to prevent lingering processes.

## Added

- None.

## Improved

- None.

## Fixed

- BetterCAP now performs a best-effort shutdown after recon to avoid leaving it running.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.25.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.25/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.25/docs/INDEX.md)
