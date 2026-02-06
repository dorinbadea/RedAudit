# Release Notes v4.5.5

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.5/docs/releases/RELEASE_NOTES_v4.5.5_ES.md)

**Release Date:** 2026-01-10

## Summary

This release packages the **Lab Credentials Seeder** (`scripts/seed_keyring.py`) and enhances the auto-updater to automatically run it. This ensures a seamless transition to the new credential loading feature.

## Added

- **Lab Credentials Script (Spray Mode)**
  - New script: `scripts/seed_keyring.py`
  - Contains **ALL** Phase 4 lab credentials (11 sets)
  - Configured for Spray Mode (multiple credentials per protocol)
  - Pre-populates keyring with:
    - SSH: auditor, msfadmin, openplc
    - SMB: Administrator, docker, msfadmin
    - SNMP: admin-snmp

- **Updater Auto-Seed**
  - Wizard update (Option 2) automatically executes `seed_keyring.py` if present
  - Reduces manual setup steps for users updating RedAudit

## Important Note for this Update

Since you are updating *from* an older version that lacks the auto-seed logic, the automatic seeding **will not trigger** during the update to v4.5.5.

**Manual Step (One Time Only):**
After updating, run:

```bash
python3 scripts/seed_keyring.py
```

Future updates will handle this automatically.
