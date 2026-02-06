[![Ver en Español](https://img.shields.io/badge/Ver_en_Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.32/docs/releases/RELEASE_NOTES_v4.19.32_ES.md)

# RedAudit v4.19.32 - Installer ShellCheck Fix

## Summary
- The installer now defines the OUI seeding helper before use, keeping ShellCheck clean and the auto-install path reliable.

## Added
- None.

## Improved
- None.

## Fixed
- Resolved ShellCheck SC2218 in the installer by moving the OUI helper definition above its call site.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No action required.
