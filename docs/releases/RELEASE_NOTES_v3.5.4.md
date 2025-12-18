# RedAudit v3.5.4

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.5.4_ES.md)

**Date**: 2025-12-18
**Type**: Patch Release (Hotfix)

## 📌 Highlights

### Version detection fix for system installs

This release fixes an updater loop where RedAudit could show `v0.0.0-dev` after a system install update (script-based `/usr/local/lib/redaudit` installs without Python package metadata).

- RedAudit now ships an internal `redaudit/VERSION` file and uses it as a fallback when `importlib.metadata` is unavailable.
- Result: the banner shows the correct version, and update checks stop repeating the same update.

