# RedAudit v3.7.3 Release Notes

**Release Date:** 2025-12-20

[![Ver en Español](https://img.shields.io/badge/🇪🇸_Español-red?style=flat-square)](RELEASE_NOTES_v3.7.3_ES.md)

## Overview

RedAudit v3.7.3 is a patch release focused on **scan reliability** and **reporting accuracy**, especially for mixed
networks with routers and IoT devices.

## Fixed

### Nmap XML Parsing & Timeouts

- Preserve full Nmap XML output and extract the `<nmaprun>` block before parsing to prevent XML parse errors.
- When no `--host-timeout` is specified, fallback timeouts now respect the scan mode (full/completo = 300s).

### Host Identity Continuity

- If Nmap fails, RedAudit now falls back to topology/neighbor MAC+vendor data to keep host identity in reports.

### Report Accuracy

- "Hosts Discovered" now deduplicates targets so it matches the actual unique host set.

## Documentation

- [Full Changelog](CHANGELOG.md)
- [Roadmap](docs/ROADMAP.en.md)
