# RedAudit v3.1.2 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.1.2_ES.md)

**Release Date**: December 14, 2025
**Type**: Patch Release - Update UX & CLI Formatting
**Previous Version**: v3.1.1

---

## Overview

Version 3.1.2 improves the auto-update experience:

- CLI-friendly “What’s new” preview (Markdown cleaned + wrapped for terminals).
- More reliable post-update restart (PATH-aware) with clear fallback instructions.

This release is backward compatible with v3.1.1 and requires no migration steps.

---

## What's New in v3.1.2

### 1. CLI-Friendly Update Notes

- Release notes preview is rendered for terminals (no raw Markdown noise).
- Spanish users prefer `CHANGELOG_ES.md` when previewing update notes.

### 2. More Reliable Restart After Update

- Restart attempts to re-run the original entrypoint first.
- If auto-restart fails, RedAudit exits and prints the exact re-run command.

### 3. Clearer Interactive Prompts

- FULL UDP coverage now offers simple presets (50/100/200/500) plus a custom option.
- Topology-only wording clarifies that **NO** keeps the normal host/port scan + topology.
- Saving defaults now includes a confirmation step and explains the impact either way.

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **User Manual (EN)**: [docs/en/MANUAL.en.md](../MANUAL.en.md)
- **Manual (ES)**: [docs/es/MANUAL.en.md](../MANUAL.en.md)
- **Report Schema (EN)**: [docs/en/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
- **Report Schema (ES)**: [docs/es/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
