# RedAudit v3.1.0 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.1_ES.md)

**Release Date**: December 14, 2025
**Type**: Feature Release - SIEM & AI Pipeline Enhancements
**Previous Version**: v3.0.4

---

## Overview

Version 3.1.0 introduces enterprise-grade SIEM integration and AI pipeline exports. It adds deterministic finding correlation, severity normalization, structured evidence extraction, and flat JSONL views optimized for streaming ingestion.

This release is backward compatible with v3.0.4 and requires no migration steps. New fields are optional, and JSONL/evidence export views are skipped when report encryption is enabled to avoid plaintext artifacts.

---

## What's New in v3.1.0

### 1. JSONL Export Views (SIEM/AI Pipelines)

Each scan can generate three flat export files in the output folder (when report encryption is disabled):

- `findings.jsonl`: one finding per line (SIEM-friendly)
- `assets.jsonl`: one asset per line (inventory-friendly)
- `summary.json`: compact dashboard summary

### 2. Deterministic Finding Correlation (`finding_id`)

Findings now include a stable `finding_id` (deterministic hash) based on:

- asset (`observable_hash`)
- scanner/tool
- protocol/port
- signature (CVE/plugin/rule/normalized finding line)
- normalized title

This enables cross-scan correlation and deduplication.

### 3. Category Classification + Normalized Severity

Each finding is enriched with:

- `category`: surface/misconfig/crypto/auth/info-leak/vuln
- `severity`: info/low/medium/high/critical
- `severity_score`: numeric 0–100 (SIEM-friendly)
- `normalized_severity`: numeric 0.0–10.0 (CVSS-like)
- `original_severity`: preserved tool-native value for traceability

### 4. Parsed Observations + Evidence Handling

For web/TLS tools (Nikto/TestSSL), RedAudit now extracts:

- `parsed_observations`: short structured list for fast search and AI summarization
- `raw_tool_output_sha256`: hash of raw output (integrity/dedup)
- `raw_tool_output_ref`: externalized raw output path (only when encryption is disabled and output is large)

### 5. Tool Provenance (`scanner_versions`)

Reports now include `scanner_versions`, a best-effort map of detected tool versions (e.g., nmap/nikto/testssl/whatweb/searchsploit) plus RedAudit itself.

### 6. New Modules

```text
redaudit/core/
├── scanner_versions.py  # Tool version detection
├── evidence_parser.py   # Nikto/TestSSL observation extraction
└── jsonl_exporter.py    # JSONL/summary export views
```

---

## Useful Links

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
- **GitHub Release Notes**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **User Manual (EN)**: [docs/en/MANUAL.en.md](../MANUAL.en.md)
- **Manual (ES)**: [docs/es/MANUAL.en.md](../MANUAL.en.md)
- **Report Schema (EN)**: [docs/en/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
- **Report Schema (ES)**: [docs/es/REPORT_SCHEMA.en.md](../REPORT_SCHEMA.en.md)
- **Security Specification**: [EN](../SECURITY.en.md) / [ES](../SECURITY.en.md)
