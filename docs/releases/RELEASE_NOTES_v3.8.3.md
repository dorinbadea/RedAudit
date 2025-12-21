# RedAudit v3.8.3 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.8.3_ES.md)

**Release Date:** 2025-12-21  
**Focus:** Wizard & Reporting UX

---

## What's New

### Auditor Identity in Reports

The wizard now asks for the auditor name and includes it in TXT/HTML reports.

### Bilingual HTML Output

When the run language is Spanish, RedAudit generates `report_es.html` alongside the default HTML report.

---

## Fixes

- **Wizard prompt duplication** removed in vulnerability scan options.
- **Progress detail colors** now respect INFO/WARN/FAIL while the UI is active.
- **Net Discovery progress** no longer shows a stuck 100% before the final step finishes.

---

## Changes

- **HTML footer** is now neutral (license + GitHub) without personal author credit.

---

## Installation

```bash
cd ~/RedAudit
git fetch origin
git checkout main
git pull
sudo ./redaudit_install.sh -y
```

---

## Upgrade Notes

This release is backward compatible. No configuration changes are required.

---

**Full Changelog:** [CHANGELOG.md](../../CHANGELOG.md)
