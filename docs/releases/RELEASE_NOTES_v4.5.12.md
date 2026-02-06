# Release Notes v4.5.12

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.12/docs/releases/RELEASE_NOTES_v4.5.12_ES.md)

**Release Date:** 2026-01-10

## Summary

This update solves the "Externally Managed Environment" (PEP 668) error encountered when installing Python dependencies on modern distributions like Ubuntu 24.04 (Noble) and recent Kali Linux versions.

## Fixed

- **Smart Pip Retry Logic**:
  - The installer now robustly handles `pip install` failures. If the standard installation fails due to managed environment restrictions (PEP 668), it automatically retries with the `--break-system-packages` flag.
  - This ensures that critical dependencies like `pysnmp` (which may be missing from APT repositories) can still be installed system-wide for RedAudit to function correctly.

## Verification

If you previously saw `error: externally-managed-environment` or `[WARN] pip install failed`, simply run:

```bash
git pull
sudo bash redaudit_install.sh
```

The script will now intelligently bypass the restriction to ensure a complete installation.
