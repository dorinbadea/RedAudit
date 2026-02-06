# Release Notes v4.5.11

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.11/docs/releases/RELEASE_NOTES_v4.5.11_ES.md)

**Release Date:** 2026-01-10

## Summary

This update fixes an installation failure on modern Linux distributions (e.g., Ubuntu 24.04 Noble) where `python3-pysnmp` is no longer available in the repositories.

The installer now treats `python3-pysnmp` as an optional system package and attempts a graceful fallback or warning, ensuring the main RedAudit installation completes successfully even if this specific library cannot be installed via APT.

## Fixed

- **Universal Installer**:
  - `python3-pysnmp` is now installed in a separate, optional step that does not halt the script on failure.
  - Fixed a code duplication error in `redaudit_install.sh` introducted in v4.5.10.

## Upgrade Instructions

```bash
git pull
sudo bash redaudit_install.sh
```
