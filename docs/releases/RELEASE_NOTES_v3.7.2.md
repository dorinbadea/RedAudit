# RedAudit v3.7.2 Release Notes

**Release Date:** 2025-12-19

[![Ver en Español](https://img.shields.io/badge/🇪🇸_Español-red?style=flat-square)](RELEASE_NOTES_v3.7.2_ES.md)

## Overview

RedAudit v3.7.2 is a patch release focused on **operator experience**: clearer wizard prompts and more stable progress
feedback (especially during Net Discovery HyperScan and Nuclei template scans).

## Fixed

### Net Discovery (HyperScan) Progress Stability

- Reduced flickering by throttling progress updates during HyperScan parallel discovery.

### Nuclei Progress & ETA

- Nuclei scanning now reports progress/ETA without competing Rich Live displays, improving visibility and avoiding UI
  conflicts.

### Wizard UX (Defaults + Net Discovery)

- If you choose to review/modify defaults and skip the defaults summary, RedAudit no longer asks whether to start
  immediately with those defaults.
- Net Discovery prompts now make it explicit when ENTER keeps the default value or skips an optional field (SNMP
  community / DNS zone).

## Documentation

- [Full Changelog](CHANGELOG.md)
- [Roadmap](docs/ROADMAP.en.md)

