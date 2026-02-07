# RedAudit v4.19.51 - Installer Config Policy Alignment

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.51/docs/releases/RELEASE_NOTES_v4.19.51_ES.md)

## Summary

This patch aligns installer behavior with expected user experience: clean manual reinstalls and preference-preserving auto-updates.

## Added

- No new end-user features in this release.

## Improved

- Manual reinstall now applies installer-selected language from a clean config baseline.
- Auto-update path preserves existing user preferences (language, API key, and defaults).

## Fixed

- Reinstalling in English no longer reopens in Spanish due to stale persisted config.
- Saving NVD API key during install now merges config safely and no longer overwrites `defaults.lang`.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
