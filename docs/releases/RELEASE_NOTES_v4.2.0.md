# RedAudit v4.2.0 - Deep Scan & Web Power Release

## Overview

This major release decouples the Deep Scan phase for true parallel execution, integrates advanced web scanning capabilities (sqlmap, ZAP), and significantly improves UX with multi-bar progress and robustness fixes.

[![Español](https://img.shields.io/badge/lang-Español-yellow.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.2.0/docs/releases/RELEASE_NOTES_v4.2.0_ES.md)

## Key Features

###  Parallel Deep Scan Architecture

- **Decoupled Phase**: Deep Scan (detecting OS, versions, banners) is now a standalone phase after Host Discovery.
- **True Concurrency**: Removes previous sequential bottlenecks. Now uses all configured threads (up to 50) to scan hosts simultaneously.
- **Multi-Bar UI**: Visualization of parallel progress for each active host during the Deep Scan phase.

###  Web Application Security

- **sqlmap Integration**: Added native support for `sqlmap` to detect SQL injection vulnerabilities (level 3/risk 3 in exhaustive profiles).
- **OWASP ZAP Support**: Basic integration for ZAP spidering and scanning.
- **Vulnerability Correlation**: Web findings are now correlated with NVD data (if configured).

### ️ Core Improvements

- **Robust Deduplication**: Implemented aggressive sanitization to prevent "ghost" duplicate hosts caused by invisible characters in upstream tools.
- **Smart-Check Logic**: Improved `compute_identity_score` to better leverage HyperScan data.
- **Strict Emoji Policy**: UI now uses a standardized set of status icons (, ⚠️, ) for clarity and policy compliance.

###  Internationalization

- **Full Spanish Support**: Deep Scan and HyperScan status messages are now fully localized.
- **Unified Manual**: Updated documentation in English and Spanish.

## Fixes

- Fixed duplicate host reporting in CLI and HTML reports.
- Fixed thread underutilization in small networks.
- Fixed legacy "prescan" references in documentation.

## Installation / Upgrade

```bash
git pull
sudo bash redaudit_install.sh
```
