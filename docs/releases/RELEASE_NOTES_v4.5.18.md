# Release v4.5.18

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.18/docs/releases/RELEASE_NOTES_v4.5.18_ES.md)

**Date:** 2026-01-11
**Version:** v4.5.18

## Summary

This hotfix addresses a critical deployment issue in the Lab Environment setup script (`scripts/setup_lab.sh`). It ensures that the Windows/Samba target (IP `.30`) is correctly deployed using the modern `elswork/samba` image with appropriate volume mounts and user configuration, resolving issues with broken or outdated containers from previous installations.

## Fixed

- **Lab Setup (Hotfix)**:
  - Forced removal of `target-windows` container before creation to ensure clean deployment.
  - Updated deployment command for IP `172.20.0.30` to correctly use `elswork/samba` with persistent volumes (`/srv/lab_smb/Public`) and predefined user credentials (`docker:password123`).
  - Ensures the target is exploitable/auditable as intended in the RedAudit Lab Scenarios.

## Upgrade

To apply this fix to your lab environment:

1. Update RedAudit:

   ```bash
   sudo redaudit
   # Select "Yes" to update
   ```

2. Re-run the lab installer (this will fix the container):

   ```bash
   cd ~/RedAudit/scripts
   ./setup_lab.sh install
   ```
