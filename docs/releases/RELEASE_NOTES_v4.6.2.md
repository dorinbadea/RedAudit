# RedAudit v4.6.2 - Quiet Host Optimization

**Date:** 2026-01-11
**Type:** Feature / Optimization Release

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.2/docs/releases/RELEASE_NOTES_v4.6.2_ES.md)

This release implements a critical optimization for "Quiet" or "Mute" infrastructure (e.g., Repeaters, IoT Hubs) when "Trust HyperScan" is enabled.

### ⚡ Quiet Host Optimization

Previously, if **HyperScan** (Phase 0) found **0 open ports** on a host, RedAudit v4.6.0 (paranoid mode) would assume it missed something and fallback to a full 65,535 port scan (`-p-`). This caused massive delays (25+ minutes) for legitimate "mute" devices.

**New Behavior (`--trust-hyperscan` + 0 ports):**

- RedAudit now "Trusts Negative Results" from HyperScan.
- If HyperScan discovers 0 ports, RedAudit executes a **Sanity Check** (`--top-ports 1000`) instead of `-p-`.
- **Result**: Scan time for these devices drops from ~25 minutes to <1 minute while maintaining a reasonable safety margin.

###  Bug Fixes

- **CI/Type Checking**: Resolved 12 `mypy` type errors in `auditor_scan.py` to ensure robust CI pipelines.

---
**Full Changelog**: <https://github.com/dorinbadea/RedAudit/compare/v4.6.1...v4.6.2>
