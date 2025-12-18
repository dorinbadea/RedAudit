# RedAudit v3.0.2 - Release Notes

**Release Date**: December 14, 2025
**Type**: Patch Release - UX, Reporting & NVD Improvements
**Previous Version**: v3.0.1

---

## Overview

Version 3.0.2 is a patch release focused on professional-grade CLI output, clearer reporting around Deep Scan/PCAP artifacts, and safer NVD CVE enrichment behavior.

This release is backward compatible with v3.0.1 and requires no migration steps.

---

## What's New in v3.0.2

### 1. Cleaner CLI Output (Professional UX)

- Thread-safe status printing to prevent interleaved output during concurrent scans.
- Word-wrapped status lines to avoid splitting words/flags across lines.
- Improved Spanish output for scan progress and deep scan messaging.

### 2. PCAP & Deep Scan Visibility

- Final summary includes a **PCAP count** for the session.
- TXT report includes:
  - Deep scan command count (identity-only vs executed deep scan).
  - PCAP file path when captured.

> **Note**: PCAP files are created only when a deep scan runs and capture tools are available (`tcpdump`/`tshark`).

### 3. NVD CVE Correlation Refinements

- Correct API key source messaging (no longer labels config/env keys as CLI-provided).
- Avoids overly broad wildcard-version CPE queries when the service version is unknown.

### 4. Version Bump

- Updated package metadata, scripts, and documentation references to **v3.0.2**.

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **Security Specification**: [docs/en/SECURITY.en.md](../SECURITY.en.md)
