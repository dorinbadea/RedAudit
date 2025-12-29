# RedAudit v3.9.9 Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.9.9_ES.md)

**Release Date:** 2025-12-29

## Printer Heuristic Fix

This hotfix corrects a classification edge case introduced by workstation brand heuristics.

### Printer Hostnames

- Printer tokens now take precedence over workstation brand hints.
- Prevents hostnames like `hp-printer-01` from being classified as workstations.

---

**Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
