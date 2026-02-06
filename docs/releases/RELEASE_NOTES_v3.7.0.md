# RedAudit v3.7.0 Release Notes

**Release Date:** 2025-12-18

[![Ver en Español](https://img.shields.io/badge/_Español-red?style=flat-square)](RELEASE_NOTES_v3.7.0_ES.md)

## Overview

RedAudit v3.7.0 introduces **Wizard UX enhancements** and **SIEM Integration** capabilities, making it easier to configure advanced options interactively and export scan results to enterprise security platforms.

## New Features

### Interactive Webhooks

Configure real-time alert webhooks directly from the wizard:

- Supports Slack, Microsoft Teams, and PagerDuty
- Optional test alert to verify connectivity
- Persisted to `~/.redaudit/config.json`

### Advanced Net Discovery Wizard

New wizard prompts for expert Red Team options:

- SNMP community string (default: `public`)
- DNS zone for zone transfer attempts
- Maximum targets for Red Team modules

### Native SIEM Pipeline

Bundled configurations for Elastic Stack integration:

- `siem/filebeat.yml` - ECS v8.11 compliant JSONL ingestion
- `siem/logstash.conf` - Severity normalization and CVE extraction
- `siem/sigma/` - 3 detection rules (critical vulns, missing headers, SSL/TLS)

### Osquery Verification

New module for post-scan host validation:

- Execute Osquery queries via SSH
- Verify open ports, running services, SSL certificates
- Confirm scan findings against live host state

### Session Logging

Terminal output automatically captured during scans:

```
<output_dir>/
└── session_logs/
    ├── session_<timestamp>.log  # Raw with ANSI colors
    └── session_<timestamp>.txt  # Clean, readable
```

### Nuclei Progress Spinner

Visual feedback during Nuclei template scans:

```
⠋ Nuclei scanning 19 targets... 0:01:23
```

## Fixed

- **CodeQL CI**: Downgraded `codeql-action` to v3 for GitHub Actions compatibility

## Installation

```bash
# Update existing installation
pip install --upgrade redaudit

# Or from source
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && pip install -e .
```

## Documentation

- [SIEM Integration Guide](docs/SIEM_INTEGRATION.en.md)
- [Full Changelog](CHANGELOG.md)
