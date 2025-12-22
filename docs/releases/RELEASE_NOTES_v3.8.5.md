# Release Notes v3.8.5 — Quiet-Host Identity Improvements

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](RELEASE_NOTES_v3.8.5_ES.md)

**Release Date:** 2025-12-22

## Summary

This release improves identity enrichment for quiet hosts by adding a short HTTP/HTTPS probe and using the captured title to label assets without hostnames. It also refines asset classification to avoid router mislabels and recognize switch models from vendor/title cues.

---

## Added

### Quiet-Host HTTP Probe

A short HTTP/HTTPS probe on common ports runs when a host has vendor hints but zero open ports. It captures the page title/server header to provide model context without a full deep scan.

---

## Fixed

### Asset Classification Priorities

Device-specific hostname matches (e.g., `iphone`, `msi`) now take precedence over router suffixes like `fritz`, reducing false positives.

### Asset Naming from HTTP Titles

Assets without hostnames now use `http_title` as a human-friendly label, and switch models are classified using vendor/title patterns (e.g., Zyxel `GS` series).

---

## Technical Details

- **Files modified:** `redaudit/core/auditor_scan.py`, `redaudit/core/entity_resolver.py`, `redaudit/core/scanner.py`, `redaudit/core/siem.py`
- **Outputs affected:** HTML host table "Agentless" column, JSON `agentless_fingerprint`, `unified_assets.asset_name`, `asset_type`

---

## Upgrade

```bash
cd /path/to/RedAudit
git pull origin main
```

No configuration changes required.

---

[Back to README](../../README.md) | [Full Changelog](../../CHANGELOG.md)
