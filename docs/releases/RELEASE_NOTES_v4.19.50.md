# RedAudit v4.19.50 - Startup UX and Language Persistence

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.50/docs/releases/RELEASE_NOTES_v4.19.50_ES.md)

## Summary

This patch improves first-run usability and update visibility in interactive mode.

## Added

- No new end-user features in this release.

## Improved

- Startup update notices are shown after banner/menu rendering, so users can see available updates immediately.
- Wizard prompts are cleaner by removing the decorative `?` prefix.

## Fixed

- Installer now persists selected language (`en`/`es`) into user config (`~/.redaudit/config.json`).
- Reinstalling in English no longer reopens in Spanish due to locale-only fallback behavior.
- Installer applies best-effort ownership/permissions for persisted language config when running as root.

## Testing

- Internal validation completed.

## Upgrade

- No action required.
