# RedAudit v3.8.2 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.8.2_ES.md)

**Release Date:** 2025-12-20
**Focus:** UX Polish

---

## What's New

### HTML Report Watermark

Professional footer added to HTML reports with:

- GPLv3 license notice
- Author credit (Dorin Badea)
- GitHub repository link

### Progress Bar Improvements

- **Spinner Removed**: Eliminated `SpinnerColumn` from progress bars (was causing display freezes during long phases)
- Progress now displays: `description + bar + percentage + elapsed time`

---

## Changelog Summary

### Added

- Professional watermark in HTML reports

### Fixed

- Progress bar display freezes during Net Discovery and Deep Scan phases

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

This is a minor UX polish release. No breaking changes or configuration updates required.

---

**Full Changelog:** [CHANGELOG.md](../../CHANGELOG.md)
