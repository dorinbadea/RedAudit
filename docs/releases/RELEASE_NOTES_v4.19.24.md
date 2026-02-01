# RedAudit v4.19.24 - Report Hardening and Resume Cleanup

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.24/docs/releases/RELEASE_NOTES_v4.19.24_ES.md)

## Summary

Defensive hardening for HTML reports, better observability on chown failures, and documentation for Nuclei resume cleanup.

## Added

- None.

## Improved

- HTML reports now include a Content-Security-Policy meta header for defense-in-depth.
- Best-effort chown now logs debug details on failure for easier troubleshooting.
- The default Nuclei timeout override is centralized in a shared constant.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.24.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.24/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.24/docs/INDEX.md)
