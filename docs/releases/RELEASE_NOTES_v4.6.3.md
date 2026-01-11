# RedAudit v4.6.3 - Wizard Hotfix

**Date:** 2026-01-11
**Type:** Hotfix Release

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.3/docs/releases/RELEASE_NOTES_v4.6.3_ES.md)

This hotfix addresses a UX issue where the "Trust HyperScan" optimization was available in the CLI but missing from the Interactive Wizard.

### 🐛 Bug Fixes & UX Improvements

- **Wizard**: Added missing interactive prompt for "Trust HyperScan" in the **Custom** profile (Step 2).
- **Defaults**: Enabled `Trust HyperScan` by default in **Express** and **Standard** profiles for immediate performance benefits on quiet networks.
- **Exhaustive Mode**: Explicitly disables `Trust HyperScan` (paranoid mode preserved).

---
**Full Changelog**: <https://github.com/dorinbadea/RedAudit/compare/v4.6.2...v4.6.3>
