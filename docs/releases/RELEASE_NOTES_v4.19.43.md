[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.43/docs/releases/RELEASE_NOTES_v4.19.43_ES.md)

# RedAudit v4.19.43 - Startup Update Check UX Optimization

## Summary

This patch improves the update-check experience by making startup checks automatic, lightweight, and non-blocking.

## Added

- Startup update checks now use cache metadata to reduce repeated network calls.

## Improved

- RedAudit now checks for updates automatically at launch and only notifies when a newer version is available.
- Startup update checks use a short timeout and keep the scan flow responsive.

## Fixed

- Startup update behavior now remains consistent across launch modes while respecting `--skip-update-check`.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
