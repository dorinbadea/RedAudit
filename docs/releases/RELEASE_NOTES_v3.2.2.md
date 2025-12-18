# RedAudit v3.2.2 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.2.2_ES.md)

**Release Date**: December 16, 2025
**Type**: Production Hardening
**Previous Version**: v3.2.1

---

## Overview

Version 3.2.2 focuses on production hardening: safer updates with atomic installation and rollback, cleaner CLI output, and honest security documentation.

---

## What's New in v3.2.2

### 1. Staged Atomic Installation

The update system now uses a staged approach:

1. New files are copied to `.new` staging directory
2. Staging directory is validated for key files
3. Current installation is renamed to `.old`
4. Staging directory is atomically renamed to final location
5. If any step fails, automatic rollback restores the previous version

This prevents the "half-installed" state that could occur if the system crashed mid-update.

### 2. CLI Output Polish

Internal status tokens (`OKGREEN`, `OKBLUE`, `WARNING`) are now mapped to user-friendly labels in all output modes:

| Internal Token | Display Label |
|---------------|---------------|
| `OKGREEN` | `OK` |
| `OKBLUE` | `INFO` |
| `HEADER` | `INFO` |
| `WARNING` | `WARN` |
| `FAIL` | `FAIL` |

### 3. Honest Security Documentation

- Renamed "Secure Update Module" → "Reliable Update Module"
- SECURITY.en.md Section 7 clarifies integrity verification (git hashes) vs. authenticity (cryptographic signatures)
- Explicit note: **no GPG signature verification is performed**

---

## ⚠️ Upgrade Notice for v3.2.1 Users

The auto-update from v3.2.1 → v3.2.2 may fail with "Clone verification failed" due to a bug in how annotated git tags were resolved. The fix is included in v3.2.2, but users on v3.2.1 need to reinstall manually (one time only):

```bash
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.2.2/redaudit_install.sh | sudo bash
```

**After this manual update, all future auto-updates will work correctly.**

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **Security Documentation**: [docs/en/SECURITY.en.md](../SECURITY.en.md) / [docs/es/SECURITY.en.md](../SECURITY.en.md)
