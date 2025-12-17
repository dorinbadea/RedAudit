# RedAudit v3.2.1 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.2.1_ES.md)

**Release Date**: December 15, 2025
**Focus**: Professional CLI UX, Main Menu, and Interaction Polish

---

## Overview

Version 3.2.1 is a significant UX polish release, introducing a new **Interactive Main Menu** as the default entry point, streamlining the **Topology Discovery** workflow, and resolving visual artifacts in non-interactive (CI/pipeline) environments. It also expands internationalization (i18n) to cover all remaining hardcoded CLI strings.

---

## What's New in v3.2.1

### 1. Interactive Main Menu

The CLI now presents a professional main menu when run without arguments, serving as the central hub for all operations:

- **[1] Start Scan (Wizard)**: Launches the standard configuration wizard.
- **[2] Check for Updates**: Manually checks for new versions.
- **[3] Diff Reports (JSON)**: New interface to compare two previous scan reports.
- **[0] Exit**: Clean exit.

### 2. Installer Enhancements

- **Leak Detection**: New heuristic analysis to find private IP leakage in HTTP headers.
- **Improved UI**: Cleaner interactive prompts with colored separators.
- **New Tools**: Native support for installing `kerbrute` (GitHub binary) and `proxychains4` (SOCKS5 proxy).

### 3. Streamlined Topology Workflow

The previous multi-step topology prompt has been consolidated into a single, clear choice:

- **Option 1**: Disabled (standard scan)
- **Option 2**: Enabled (scan + topology discovery)
- **Option 3**: Topology Only (skip host/port scan, focus on L2/L3 discovery)

### 3. Non-TTY / CI Pipeline Support

- Fixed `[OKGREEN]` and other color code artifacts appearing in logs when output is piped to a file or CI system.
- Output now automatically detects non-TTY environments and strips color codes, replacing them with neutral text labels (e.g., `[OK]`).

### 4. Consolidated Defaults ("Base Values")

- Renamed "Factory Values" to "Base Values" for clarity.
- Simplified the end-of-wizard flow, reducing redundant confirmations to a maximum of two prompts (Save Defaults? -> Start Audit?).

### 5. Internationalization (i18n)

- Added 60+ new translation keys to cover previously hardcoded English strings (proxy errors, target validation, random password generation messages).
- Full English (EN) and Spanish (ES) support for all new menu and wizard interfaces.

### 6. Subnet Leak Detection (Guest Analysis)

A new post-processing module automatically detects potential **Hidden Networks** (like Guest VLANs or Admin Management subnets) by analyzing "leaks" in HTTP services:

- **Redirect Analysis**: Investigates `Location` headers pointing to private IPs outside the scan range.
- **Content Analysis**: Checks `Content-Security-Policy` and error messages.
- **Reporting**: Automatically flags these as "Potential Hidden Networks" in the final report, facilitating professional pivoting.

---

## Upgrade Notes

- **No Breaking Changes**: This update focuses on the interactive layer. Existing automation scripts using flags (e.g., `redaudit --target ... --yes`) are unaffected.
- **Config Update**: Configuration files will automatically include a new `topology_only` tracking field.

---

## Testing

```bash
# Interactive Menu
redaudit

# Scan with simplified workflow
redaudit --target 192.168.1.0/24

# Verify clean output in non-interactive mode
redaudit --target 192.168.1.1 --yes > clean_output.log
```
