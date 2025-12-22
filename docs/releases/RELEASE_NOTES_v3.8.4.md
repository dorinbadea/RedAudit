# Release Notes v3.8.4 — Agentless Verification & Color Fixes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](RELEASE_NOTES_v3.8.4_ES.md)

**Release Date:** 2025-12-21

## Summary

This release introduces **Agentless Verification**, a new fingerprinting stage for identity enrichment, along with visual fixes for the CLI progress bar.

---

## Added

### Agentless Verification

A new optional stage that runs safe, non-intrusive Nmap scripts against discovered services (SMB, RDP, LDAP, SSH, HTTP) to gather more detailed identity information without credentials.

- **Enable:** Select "Yes" in the wizard when prompted for "Agentless Verification", or use `--agentless-verify`.
- **Control:** Limit the number of targets with `--agentless-verify-max-targets` (default: 20).
- **Benefit:** Provides OS hints, domain names, and service headers that helps clarify the "identity" of a host.

---

## Fixed

### Status Colors During Progress

When Rich Progress was active (during host scanning phases), status messages printed via `print_status()` could lose their ANSI color formatting. This occurred because Rich's output handling interfered with direct `print()` calls using raw ANSI codes.

**Solution:** When `_ui_progress_active` is true, the `print_status()` method now uses Rich's `console.print()` with proper markup:

| Status | Rich Style |
|--------|------------|
| INFO | `bright_blue` |
| OK | `green` |
| WARN | `yellow` |
| FAIL | `red` |

This ensures consistent color display regardless of progress bar state.

---

## Technical Details

- **File modified:** `redaudit/core/auditor.py`
- **Method:** `InteractiveNetworkAuditor.print_status()`
- **Fallback:** Standard ANSI codes are still used when progress is not active or Rich is unavailable

---

## Upgrade

```bash
cd /path/to/RedAudit
git pull origin main
```

No configuration changes required.

---

[Back to README](../../README.md) | [Full Changelog](../../CHANGELOG.md)
