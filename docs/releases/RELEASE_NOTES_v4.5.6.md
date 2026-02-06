# Release Notes v4.5.6

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.6/docs/releases/RELEASE_NOTES_v4.5.6_ES.md)

**Release Date:** 2026-01-10

## Summary

This release adds comprehensive **Lab Setup Automation** (`scripts/setup_lab.sh`) and detailed documentation. Users can now easily spin up the exact Docker environment that RedAudit's test credentials correspond to.

## Added

- **Lab Setup Script** (`scripts/setup_lab.sh`)
  - Automates installation, starting, stopping, and status checking of the lab.
  - Provisions 11 targets including SCADA, Active Directory, and IoT simulators.
  - **Usage**: `sudo bash scripts/setup_lab.sh [install|start|stop|status]`

- **Documentation**
  - [Lab Setup Guide](../../docs/LAB_SETUP.md)
  - Updated README with Quick Start link to lab guide.

## How to use

1. **Update and Install**:

   ```bash
   cd ~/RedAudit && git pull && sudo bash redaudit_install.sh
   # (This will also run the credential seeder if you haven't already)
   ```

2. **Setup Lab**:

   ```bash
   sudo bash scripts/setup_lab.sh install
   ```

3. **Check Status**:

   ```bash
   sudo bash scripts/setup_lab.sh status
   ```

4. **Verify Seeder**:

   ```bash
   # If you updated from <v4.5.5, run this once:
   python3 scripts/seed_keyring.py
   ```
