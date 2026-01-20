# RedAudit v4.18.0 - UX Fixes and Documentation

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.0/docs/releases/RELEASE_NOTES_v4.18.0_ES.md)

## Summary

This release fixes visual bugs during progress bar displays and improves documentation for Nuclei configuration options.

## Fixed

- **Rich Progress Color Bugs**: Fixed [WARN], [OK], and [INFO] messages appearing white during progress bar display.
  - Root cause: Creating a new Console() was bypassing the active Rich progress, losing color formatting.
  - Fix: Added `_active_progress_console` tracking in UIManager to ensure correct console usage.
  - Also fixed Deep Scan and Net Discovery heartbeat messages to use `Text()` objects for reliable color output.

## Improved

- **Shortened Wizard Prompts**: Reduced terminal truncation by shortening prompts:
  - `nuclei_full_coverage_q`: Shortened to prevent terminal wrap on narrow windows.
  - `trust_hyperscan_q`: Simplified for clarity while maintaining intent.

## Documentation

- **Nuclei Configuration Section**: Added comprehensive documentation to USAGE guides (EN/ES):
  - Scan profiles (fast/balanced/full) with time estimates.
  - Full coverage option explained as wizard-only (not a CLI flag).
  - RustScan documented as optional performance boost for HyperScan.
- **CLI Reference Updates**: Added missing `--profile` and `--nuclei-timeout` flags to MANUAL CLI reference.
- **Critical Correction**: Clarified that `--nuclei-full` does NOT exist as a CLI flag; full coverage is a wizard-only interactive option.

## Testing

- All 1945 tests pass.
- Pre-commit hooks pass.
- Manual verification of Rich color output during progress bars.

## Upgrade

```bash
cd /path/to/RedAudit
git pull origin main
sudo bash redaudit_install.sh
```

---

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.0/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.0/docs/INDEX.md)
