# RedAudit v3.1.4 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.1.4_ES.md)

**Release Date**: December 15, 2025
**Focus**: Output Quality Improvements for Maximum SIEM/AI Scoring

---

## Overview

Version 3.1.4 addresses output quality issues identified during scan analysis. The primary goal is to maximize the usefulness of RedAudit findings for SIEM ingestion and AI analysis pipelines by improving title clarity, reducing false positives, and adding contextual metadata.

---

## What's New in v3.1.4

### Descriptive Finding Titles

**Before**: Generic titles like `"Finding on http://192.168.1.1:80/"`
**After**: Contextual titles like `"Missing X-Frame-Options Header (Clickjacking Risk)"`

The `_extract_title()` function in `jsonl_exporter.py` now analyzes finding observations to generate meaningful titles:

- Security header issues → "Missing HSTS Header", "Missing X-Content-Type-Options"
- SSL/TLS problems → "SSL Certificate Hostname Mismatch", "SSL Certificate Expired"
- CVE references → "Known Vulnerability: CVE-2023-12345"
- Information disclosure → "Internal IP Address Disclosed in Headers"

### Nikto Cross-Validation

New `detect_nikto_false_positives()` function compares Nikto findings with captured HTTP headers from `curl` and `wget`:

```json
{
  "nikto_findings": ["The X-Content-Type-Options header is not set."],
  "curl_headers": "X-Content-Type-Options: nosniff\r\n...",
  "potential_false_positives": [
    "X-Content-Type-Options: Header present in response but Nikto reports missing"
  ]
}
```

This helps analysts quickly identify contradictions and prioritize investigation.

### RFC-1918 Severity Adjustment

Internal IP disclosures on private networks are now correctly rated:

- **Before**: `{"severity": "high", "severity_score": 70}` (incorrectly high)
- **After**: `{"severity": "low", "severity_score": 30, "severity_note": "RFC-1918 disclosure on private network (reduced severity)"}`

The `is_rfc1918_address()` helper detects when the target host itself is in RFC-1918 space (10.x, 172.16-31.x, 192.168.x).

### OS Fingerprint Extraction

New `extract_os_detection()` function parses Nmap output to extract structured OS info:

```python
extract_os_detection("OS details: Linux 5.4 - 5.11")  # Returns "Linux 5.4 - 5.11"
extract_os_detection("Running: Microsoft Windows 10")  # Returns "Microsoft Windows 10"
```

### Relative PCAP Paths

PCAP file references are now portable:

```json
{
  "pcap_file": "traffic_192.168.1.1.pcap",
  "pcap_file_abs": "/root/Documents/RedAuditReports/RedAudit_2025-12-15/traffic_192.168.1.1.pcap"
}
```

Reports can be moved between systems without breaking file references.

### Configurable TestSSL Timeout

The `ssl_deep_analysis()` function now accepts a configurable timeout:

```python
ssl_deep_analysis(host_ip, port, extra_tools, timeout=120)  # Extended timeout
```

Default increased from 60s to 90s to accommodate complex SSL configurations.

### Schema Version Constant

New `SCHEMA_VERSION` constant in `constants.py` separates report schema versioning from application versioning:

```python
VERSION = "3.1.4"        # Application version
SCHEMA_VERSION = "3.1"   # Report schema version
```

---

## Files Changed

| File | Changes |
|------|---------|
| `redaudit/core/jsonl_exporter.py` | Enhanced `_extract_title()` with 10+ pattern matchers |
| `redaudit/core/scanner.py` | Added `extract_os_detection()`, relative PCAP paths, configurable timeout |
| `redaudit/core/siem.py` | Added `is_rfc1918_address()`, `detect_nikto_false_positives()`, severity adjustment |
| `redaudit/utils/constants.py` | Added `SCHEMA_VERSION` constant |

---

## New Report Fields

| Field | Location | Description |
|-------|----------|-------------|
| `severity_note` | Finding | Explanation when severity was adjusted |
| `potential_false_positives` | Finding | Array of detected contradictions |
| `pcap_file` | PCAP capture | Relative filename (portable) |
| `pcap_file_abs` | PCAP capture | Absolute path (internal use) |

---

## Upgrade Notes

- **Backward compatible**: All changes are additive; existing pipelines will continue to work
- **No migration required**: New fields are optional and only appear when relevant
- **Recommended action**: Update SIEM parsers to utilize `potential_false_positives` for triage

---

## Testing

```bash
# Verify version
redaudit --version  # Should show: RedAudit v3.1.4

# Run a scan and check for new fields
sudo redaudit --target 192.168.1.0/24 --mode normal --yes
jq '.hosts[].vulnerabilities[] | select(.potential_false_positives)' report.json
```
