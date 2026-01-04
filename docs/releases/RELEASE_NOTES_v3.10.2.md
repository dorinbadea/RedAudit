# Release Notes v3.10.2

[![ES](https://img.shields.io/badge/lang-ES-red.svg)](RELEASE_NOTES_v3.10.2_ES.md)

**Release Date:** 2026-01-04
**Codename:** Auditor Node & MAC Display Fix

## Summary

This patch release fixes a critical bug where MAC addresses were not displaying in HTML reports, and introduces the "Auditor Node" feature that clearly identifies the scanner's own machine in audit reports.

## New Features

### Auditor Node Detection

Scanner's own network interfaces are now automatically detected and marked in HTML reports:

- Displays `(Auditor Node)` / `(Nodo Auditor)` instead of `-` for MAC column
- Works for all interfaces (Ethernet, Wi-Fi, etc.)
- Improves professional audit context

### Architecture Foundation (Internal)

Preparatory work for v4.0 modular architecture:

- `UIManager` standalone class for UI operations
- `ConfigurationContext` typed wrapper for configuration
- `NetworkScanner` with identity scoring utilities
- Adapter properties for backward compatibility

## Fixes

### MAC Address Display in HTML Reports

Fixed a bug where MAC addresses were not showing in HTML reports despite being captured correctly:

- **Root cause:** Key mismatch (`host.get("mac")` vs `host.get("mac_address")`)
- **Fix:** Now checks both `mac_address` (canonical) and `mac` (legacy) keys
- **Scope:** Affected all hosts without a full deep scan

## Testing

- 1264+ tests passing
- 82 new tests for architecture components
- Coverage: 84.72%

## Upgrade Notes

This is a backward-compatible patch release. No configuration changes required.

---

[Full Changelog](../../CHANGELOG.md) | [Documentation Index](../INDEX.md)
