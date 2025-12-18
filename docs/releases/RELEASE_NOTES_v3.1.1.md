# RedAudit v3.1.1 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.1.1_ES.md)

**Release Date**: December 14, 2025
**Type**: Patch Release - Topology, Persistent Defaults & UDP Coverage
**Previous Version**: v3.1.0

---

## Overview

Version 3.1.1 is a patch release that improves operational workflows and network context discovery:

- Best-effort topology discovery (ARP/VLAN/LLDP + gateway/routes) to help spot “hidden networks”.
- Persistent defaults in `~/.redaudit/config.json` to avoid repeating common flags.
- Configurable UDP coverage (`--udp-ports`) for the full UDP identity phase.

This release is backward compatible with v3.1.0 and requires no migration steps. New fields are optional.

---

## What's New in v3.1.1

### 1. Topology Discovery (Best-Effort)

- New `topology` block in the JSON report root when enabled.
- New CLI flags:
  - `--topology` (enable)
  - `--no-topology` (disable, override persisted defaults)
  - `--topology-only` (topology without host scanning)
- Collects best-effort context (depends on tools/privileges/traffic):
  - Routes + default gateway mapping
  - ARP discovery (active `arp-scan` + passive neighbor cache)
  - VLAN hints (link details + limited tcpdump capture)
  - LLDP (when available) and CDP raw observations (best-effort)

### 2. Persistent Defaults (`~/.redaudit/config.json`)

- New `defaults` section in config:
  - `threads`, `output_dir`, `rate_limit`
  - `udp_mode`, `udp_top_ports`
  - `topology_enabled`, `lang`
- Save defaults via:
  - CLI: `--save-defaults`
  - Interactive: optional “save defaults?” prompt

### 3. Configurable UDP Coverage (`--udp-ports`)

- New flag: `--udp-ports N` (range: 50-500; default: 100).
- Used only in `--udp-mode full` for Phase 2b identity discovery.
- Recorded in host `deep_scan.udp_top_ports` when Phase 2b runs.

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **User Manual (EN)**: [docs/en/MANUAL.en.md](../MANUAL.en.md)
- **Manual (ES)**: [docs/es/MANUAL.en.md](../MANUAL.en.md)
- **Report Schema (EN)**: [docs/en/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
- **Report Schema (ES)**: [docs/es/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
