[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.30/docs/releases/RELEASE_NOTES_v4.19.30_ES.md)

# RedAudit v4.19.30 - Nuclei Full Coverage Targets

## Summary
- Full coverage now includes all detected HTTP ports for strong-identity hosts, matching the prompt behavior.

## Added
- None.

## Improved
- Nuclei full coverage selection now aligns with the interactive prompt to scan all HTTP ports.

## Fixed
- Optimized target selection no longer truncates HTTP ports when full coverage is enabled.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No action required.
