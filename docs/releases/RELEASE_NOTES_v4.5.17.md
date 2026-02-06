# Release v4.5.17

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.17/docs/releases/RELEASE_NOTES_v4.5.17_ES.md)

**Date:** 2026-01-11
**Version:** v4.5.17

## Summary

This release resolves critical issues regarding scan logic consistency and Deep Scanning behavior. It ensures that port sweeps (`-p-` 65,535 ports) are always preserved for full Deep Scans, while intelligently optimizing scan times for well-identified infrastructure devices (routers/gateways) by leveraging existing identity signals. It also improves documentation regarding installation updates.

## Fixed

- **Scan Logic (BUG-01):** Fixed an issue where HyperScan-discovered ports were sometimes overwritten if the subsequent Nmap scan returned confirmed zero ports (due to timeouts or aggressive filtering). Now, HyperScan ports are always preserved in the final report.
- **Deep Scan Performance (UX-03):** Fixed extremely slow scan times (25+ minutes) for FritzBox and other routers.
  - **Logic Change:** Infrastructure devices (routers, gateways) with **strong identity** (score >= 3, vendor known, version detected, <= 20 ports) now correctly reach the `identity_strong` threshold and skip the redundant Deep Scan phase.
  - **Safety Net:** Hosts flagged as "suspicious" or with weak identity logic will **ALWAYS** receive the full 65,535 port sweep (`-p-`), preserving the strict security philosophy of RedAudit.
  - **Result:** Router scan times reduced from 25+ mins to ~2-3 mins without compromising security coverage for ambiguous hosts.
- **Input Handling (BUG-02):** Fixed a Python traceback when pressing `Ctrl+C` during the interactive wizard setup. Now exits gracefully.
- **CLI (BUG-03):** Added missing `--verbose` / `-v` flag to the argument parser.

## Documentation

- **Installation Updates (DOC-01/02):**
  - Updated `README.md` to clarify that RedAudit includes an **automatic update mechanism** via the wizard (`sudo redaudit`).
  - Added a note for **Ubuntu 24.04+ (Noble)** users regarding `externally-managed-environment` errors (pip restriction), explaining that the installer uses system packages by default.

## Upgrade

To update to this version, simply run the wizard:

```bash
sudo redaudit
# Select "Yes" when prompted to check for updates
```
