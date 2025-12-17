# Release Notes v3.4.1 - Output Directory Hotfix

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.4.1_ES.md)

**Release Date**: 2025-12-17

## Overview

RedAudit v3.4.1 is a small hotfix release that corrects where reports are saved when running via `sudo`.

## Fixes

- **Default output location under sudo**: Reports now default to the invoking user’s Documents folder (instead of `/root`).
- **`~` expansion under sudo**: Paths like `--output ~/Documents/...` and persisted defaults expand to the invoking user.
- **Ownership**: The report output folder is best-effort `chown`’d to the invoking user to avoid root-owned artifacts under the user’s home.

## Upgrade Instructions

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.1 - Small hotfix, smoother UX.*
