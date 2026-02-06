# RedAudit v3.3.0 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.3.0_ES.md)

**Date:** December 17, 2025
**Codename:** "Visual Insight"
**Focus:** Developer Experience (DX), Visualization, and Alerting

## Overview

RedAudit v3.3.0 represents a significant leap in usability and operational awareness. While previous versions focused on deep scanning capabilities, this release focuses on how that data is consumed and acted upon. This release introduces professional-grade HTML dashboards, real-time webhook alerting, and visual differential analysis.

## Key Features

### 1. Interactive HTML Dashboard (`--html-report`)

Previously, analysts had to parse JSON or read static text files. v3.3 introduces a self-contained, interactive HTML report:

- **Zero-Dependency**: No external JS/CSS required; safe for air-gapped networks.
- **Data Visualization**: Charts for OS distribution, Severity breakdown, and Top Ports.
- **Search & Filter**: Instant search across hundreds of findings.

### 2. Webhook Alerting (`--webhook`)

For DevSecOps and continuous monitoring workflows, RedAudit can now push findings in real-time to:

- Slack / Microsoft Teams / Discord
- Custom SOAR pipelines
- Centralized logging endpoints
**Data Sent**: Severity, Title, Target IP, and Description.

### 3. Visual Differential Analysis (`--diff` with HTML)

The differential engine introduced in v3.0 has been upgraded. The `--diff old.json new.json` command now produces a visual HTML report highlighting:

- **New Findings**: Marked in Red.
- **Resolved Issues**: Marked in Green.
- **Regressions**: Easily spot reopened vulnerabilities.

## Improvements

- **CLI DX**: Improved banner, cleaner heartbeat messages, and better error handling.
- **Security**: Added `[tool.bandit]` configuration to suppress false positives in scans.
- **Performance**: Optimized HTML generation to be instant even for large datasets.

## Bug Fixes

- Fixed `bandit` B101 false positive in CI pipeline.
- Fixed potential crash when `templates/` directory is missing (now falls back gracefully).

## Upgrading

Existing users can upgrade using the installer or git:

```bash
cd RedAudit
git pull
sudo bash redaudit_install.sh
```

## Contributors

- @dorinbadea (Lead Developer)
