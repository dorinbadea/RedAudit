# Release Notes v4.5.13

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.13/docs/releases/RELEASE_NOTES_v4.5.13_ES.md)

**Release Date:** 2026-01-10

## Summary

This hotfix addresses a critical runtime crash in the **Authenticated Scanning** phase caused by incorrect handling of `Host` objects (legacy dictionary access). It also refines the `LAB_SETUP` documentation to clarify optimal deployment architectures (Native/VM vs Docker).

## Fixed

- **Authenticated Scanning Crash (`AttributeError`)**:
  - **Issue**: The scanner attempted to access `Host` object properties (IP, etc.) using dictionary syntax (`host.get("ip")`), causing a crash during SSH/Lynis audits.
  - **Fix**: Updated logic to correctly access properties via dot notation (`host.ip`) while maintaining backward compatibility for dictionary-based tests.
  - **Impact**: Authenticated scans (SSH) now run to completion without crashing.

## Documentation

- **Lab Setup Guide**:
  - Added language navigation badges.
  - Explicitly listed **Windows** as a supported host for the Victim Lab.
  - Clarified that **RedAudit (The Auditor)** is best run on **Native Linux or VMs** to ensure L2 network visibility, while noting Docker limitations on macOS/Windows.

## Upgrading

```bash
git pull
sudo bash redaudit_install.sh  # (Optional, mainly code update)
```
