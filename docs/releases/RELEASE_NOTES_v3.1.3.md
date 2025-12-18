# RedAudit v3.1.3 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.1.3_ES.md)

**Release Date**: December 15, 2025
**Type**: Patch Release - Async UDP & Topology
**Previous Version**: v3.1.2

---

## Overview

Version 3.1.3 focuses on speed improvements via asyncio while keeping behavior best-effort and non-breaking:

- Fast concurrent UDP probing (priority ports) during deep scan.
- Faster topology discovery by running independent collection steps in parallel.

This release is backward compatible with v3.1.2 and requires no migration steps.

---

## What's New in v3.1.3

### 1. Async UDP Probe (Best-Effort)

- Deep scan now runs a fast asyncio UDP probe on priority ports (bounded timeout + concurrency limit).
- Results are recorded as `deep_scan.udp_priority_probe` for evidence and quick triage.

### 2. Async Topology Discovery (Best-Effort)

- Topology collection runs independent commands concurrently (routes/gateway, LLDP, ARP, VLAN hints).
- Improves UX when `--topology` or `--topology-only` is enabled, without changing the JSON schema.

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **User Manual (EN)**: [docs/en/MANUAL.en.md](../MANUAL.en.md)
- **Manual (ES)**: [docs/es/MANUAL.en.md](../MANUAL.en.md)
- **Report Schema (EN)**: [docs/en/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
- **Report Schema (ES)**: [docs/es/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
