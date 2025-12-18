# RedAudit v3.0.4 - Release Notes

**Release Date**: December 14, 2025
**Type**: Patch Release - Interactive UX Clarifications
**Previous Version**: v3.0.3

---

## Overview

Version 3.0.4 improves the interactive UX around the host scan limit by making the default behavior explicit: scan all discovered hosts unless you set a numeric cap.

This release is backward compatible with v3.0.3 and requires no migration steps.

---

## What's New in v3.0.4

### 1. Clearer Host Limit Prompt (Interactive Mode)

- Default is now **all** discovered hosts (`todos`/`all`)
- The prompt now explicitly clarifies that entering a number sets a maximum host count (not a host selector)

### 2. Documentation Alignment

- Manuals and usage docs clarify `--max-hosts` behavior and the interactive prompt

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **User Manual (EN)**: [docs/en/MANUAL.en.md](../MANUAL.en.md)
- **Manual (ES)**: [docs/es/MANUAL.en.md](../MANUAL.en.md)
