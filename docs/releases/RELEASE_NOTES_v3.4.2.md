# Release Notes v3.4.2 - Wizard Output Directory Hotfix

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.4.2_ES.md)

**Release Date**: 2025-12-17

## Overview

RedAudit v3.4.2 is a small hotfix that improves the interactive wizard experience when running via `sudo`.

## Fixes

- **Wizard output directory prompt (sudo)**: If an older persisted default points to `/root/...`, RedAudit automatically rewrites it to the invoking user’s `Documents` folder.

## Upgrade Instructions

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.2 - Small hotfix, cleaner defaults.*
