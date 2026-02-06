# RedAudit v4.18.11 - Updater Sync and HTML Transparency

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.11/docs/releases/RELEASE_NOTES_v4.18.11_ES.md)

## Summary

This release improves update UX, clarifies pipeline visibility in HTML reports, and hardens lab maintenance guidance.

## Added

- None.

## Improved

- The updater refreshes tags and fast-forwards clean `main` checkouts to avoid stale version prompts.
- HTML pipeline summaries now include authenticated scan outcomes when available.
- The lab setup script now applies Docker log rotation to prevent runaway container logs.
- The `.30` SMB container is force-redeployed during lab setup to avoid stale configuration.
- Lab setup guidance now includes full cleanup steps and manual log-rotation flags.

## Fixed

- DHCP timeout hints no longer claim missing IPv4 when interface data cannot be verified.
- Spanish HTML reports now translate pipeline error messages (e.g., DHCP timeouts).

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.11 for clearer updates, improved HTML traceability, and safer lab operations.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.11/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.11/docs/INDEX.md)
