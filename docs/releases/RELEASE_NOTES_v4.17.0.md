[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v4.17.0_ES.md)

# Release Notes - v4.17.0

**Release Date:** 2026-01-20

## Summary

This release adds user control over Nuclei target limiting, allowing users to choose between audit-focus efficiency (default for Custom mode) or full port coverage (default for Exhaustivo mode).

## Added

### Nuclei Full Coverage Option

New wizard question: "Scan ALL HTTP ports with Nuclei?"

| Mode | Default | Behavior |
|------|---------|----------|
| Exhaustivo | Yes | Scans all HTTP ports (pentesting-like) |
| Custom | No | Limits to 2 ports/host (audit efficiency) |

**Config key:** `nuclei_full_coverage`

When enabled, the v4.16 audit-focus limiting is skipped, and all discovered HTTP endpoints are scanned.

## Testing

- Added `TestNucleiFullCoverage` (4 tests)
- Added `TestNucleiFullCoverageI18n` (2 tests)
- All 6 tests passing

## Upgrade

```bash
git pull origin main
pip install -e .
```
