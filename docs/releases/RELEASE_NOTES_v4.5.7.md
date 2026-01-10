# Release Notes v4.5.7

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.7/docs/releases/RELEASE_NOTES_v4.5.7_ES.md)

**Release Date:** 2026-01-10

## Summary

This is a **HOTFIX** release regarding Credential Loading.

It fixes an issue where running `seed_keyring.py` as a regular user stored credentials in the user's keyring, making them invisible to `sudo redaudit` (which runs as root).

## Fixed

- **Credential Visibility (Sudo)**
  - The updater now preserves root context when running the auto-seed script, ensuring credentials are available to `sudo redaudit`.
  - `scripts/seed_keyring.py` now warns if run without `sudo`.

## Instruction for Users

If you ran the seeder previously and RedAudit still doesn't see credentials:

1. Update to v4.5.7.
2. Run the seeder with `sudo`:

   ```bash
   sudo python3 scripts/seed_keyring.py
   ```

3. Now `sudo redaudit` will see them.
