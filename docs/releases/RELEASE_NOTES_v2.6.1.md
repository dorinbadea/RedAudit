# RedAudit v2.6.1 Release Notes

**Release Date**: December 8, 2025
**Type**: Feature Enhancement

## Overview

Version 2.6.1 adds **exploit intelligence** and **SSL/TLS deep analysis** capabilities while maintaining RedAudit's adaptive scanning philosophy.

## New Features

### SearchSploit Integration (Exploit Intelligence)

Automatic ExploitDB lookup for services with detected versions.

- **What**: Queries `searchsploit` for known exploits when product+version identified
- **When**: All scan modes (runs automatically on version detection)
- **Performance**: 10-second timeout per query
- **Output**: Up to 10 exploit titles per service in JSON/TXT reports

### TestSSL.sh Integration (SSL/TLS Security Analysis)

Comprehensive SSL/TLS vulnerability assessment for HTTPS services.

- **What**: Deep analysis for Heartbleed, POODLE, BEAST, weak ciphers, deprecated protocols
- **When**: Only in `full` mode (heavy operation, 60s timeout)
- **Output**: Vulnerability summary, findings list, protocol analysis

## Technical Details

**New Functions:**

- `exploit_lookup()` in `redaudit/core/scanner.py`
- `ssl_deep_analysis()` in `redaudit/core/scanner.py`

**Updated Components:**

- `redaudit/core/auditor.py` - Tool integration orchestration
- `redaudit/core/reporter.py` - Enhanced TXT/JSON output
- `redaudit/utils/i18n.py` - English/Spanish translations

**Installation:**

```bash
sudo bash redaudit_install.sh
```

New optional dependencies: `exploitdb`, `testssl.sh` (12 total optional tools)

## Philosophy

Both tools follow RedAudit's "smart enrichment" approach:

- **SearchSploit**: Lightweight, automatic when applicable
- **TestSSL**: Resource-intensive, only in full audit mode

## Upgrade

```bash
cd /path/to/RedAudit
git pull
sudo bash redaudit_install.sh
```

For full changelog, see [CHANGELOG.md](../../CHANGELOG.md)
