# Release Notes v3.8.6 — Docker Build Fix

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](RELEASE_NOTES_v3.8.6_ES.md)

**Release Date:** 2025-12-22

## Summary

This hotfix ensures the Docker image builds successfully by installing build tools required for `netifaces`. It also aligns recent release notes with the bilingual badge format used in earlier versions.

---

## Fixed

### Docker Build for netifaces

The Docker image now installs build dependencies so `pip install` can compile `netifaces` during the image build.

---

## Documentation

- Added EN/ES language badges to release notes for v3.8.4 and v3.8.5.

---

## Upgrade

```bash
cd /path/to/RedAudit
git pull origin main
```

No configuration changes required.

---

[Back to README](../../README.md) | [Full Changelog](../../CHANGELOG.md)
