[![Ver en Español](https://img.shields.io/badge/Ver_en_Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.33/docs/releases/RELEASE_NOTES_v4.19.33_ES.md)

# RedAudit v4.19.33 - Release Workflow Reliability

## Summary
- The release workflow now updates existing releases and uses versioned release notes, avoiding failures when a release already exists.

## Added
- None.

## Improved
- None.

## Fixed
- Release job now uses the repo release notes file and allows updates to existing releases.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No action required.
