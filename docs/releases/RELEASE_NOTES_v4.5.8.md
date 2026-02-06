# Release Notes v4.5.8

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.8/docs/releases/RELEASE_NOTES_v4.5.8_ES.md)

**Release Date:** 2026-01-10

## Summary

This release fixes a `NoKeyringError` when running RedAudit or the Credential Seeder as **root** on systems without a desktop session (Headless).

It introduces a fallback to `keyrings.alt.file.PlaintextKeyring` when the system backend is unavailable.

## Headless Root Support

When running as root (e.g., `sudo redaudit`), if no secure system keyring service (GNOME Keyring, KWallet) is connected, RedAudit will now automatically store credentials in a local file protected by strict file permissions.

## Fixes

- **Dependency**: Added `keyrings.alt` to `redaudit_install.sh`.
- **Core Logic**: Both `redaudit` and `scripts/seed_keyring.py` now handle `NoKeyringError` gracefully.

## Upgrade Instructions

1. **Pull and Install**:

   ```bash
   git pull
   # Important: Run install again to get keyrings.alt dependency
   sudo bash redaudit_install.sh
   ```

2. **Re-seed Credentials**:

   ```bash
   sudo python3 scripts/seed_keyring.py
   ```
