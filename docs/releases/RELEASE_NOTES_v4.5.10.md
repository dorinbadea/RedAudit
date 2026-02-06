# Release Notes v4.5.10

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.10/docs/releases/RELEASE_NOTES_v4.5.10_ES.md)

**Release Date:** 2026-01-10

## Summary

This release improves the robustness of the installation script, specifically addressing `PySNMP missing` errors on modern Debian/Kali systems where `pip install` might be restricted or unreliable for system-wide packages.

## Improved

- **Installer (`redaudit_install.sh`)**:
  - **New Dependency**: Added `python3-pysnmp` to the APT package list. This is the preferred way to install the library on Debian-based systems, bypassing potential pip regressions.
  - **Verbose Pip**: Removed the `--quiet` flag from the `pip install` command. If pip fails to install auxiliary packages, the error will now be clearly visible in the console instead of being suppressed.

## Verification

If you experienced issues with SNMP credentials not loading or see "[WARN] PySNMP missing", please run:

```bash
git pull
sudo bash redaudit_install.sh
```

You should see `python3-pysnmp` being installed via apt, or clear error messages from pip if something else is wrong.
