# Release Notes v3.4.3 - Descriptive Finding Titles

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.4.3_ES.md)

**Release Date**: 2025-12-17

## Overview

RedAudit v3.4.3 is a small hotfix that improves readability by generating short descriptive titles for web findings.

## Fixes

- **Finding titles**: Web findings now get a short `descriptive_title` derived from parsed observations (improves HTML report table titles, webhooks, and playbook headings).
- **Wizard output directory**: When the default would land under `/root/...`, RedAudit now prefers the user’s `Documents` folder (invoking user under `sudo`, and a single detected `/home/<user>` when running as root without `sudo`).
- **Wizard selection marker**: Uses an ASCII `>` marker for maximum terminal compatibility.

## Upgrade Instructions

```bash
cd ~/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

*RedAudit v3.4.3 - Cleaner triage output.*
