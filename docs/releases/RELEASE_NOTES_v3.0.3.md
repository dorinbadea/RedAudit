# RedAudit v3.0.3 - Release Notes

**Release Date**: December 14, 2025
**Type**: Patch Release - Update UX & Language Preservation
**Previous Version**: v3.0.2

---

## Overview

Version 3.0.3 improves the auto-update experience by making the process more explicit (what was downloaded/changed/installed) and fixes a regression where the installed language could reset to English after updating.

This release is backward compatible with v3.0.2 and requires no migration steps.

---

## What's New in v3.0.3

### 1. Language Preserved on Auto-Update

Auto-update now preserves the installed language preference (e.g., Spanish stays Spanish) during the manual installation step.

### 2. More Explicit Auto-Update Output

During update, RedAudit now prints:

- Target ref/tag and verified commit hash
- System installation changes summary (**added / modified / removed** files)
- Explicit install and backup steps (system path + home folder copy)

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **Security Specification**: [docs/en/SECURITY.en.md](../SECURITY.en.md)
