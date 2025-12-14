# Release Notes v3.1

## SIEM & AI Pipeline Enhancements

**Release Date**: December 2025

### Overview

v3.1 introduces enterprise-grade SIEM integration and AI pipeline support. The new schema enables deterministic finding correlation, structured evidence extraction, and flat JSONL exports optimized for streaming ingestion.

### New Features

#### JSONL Export Views

Each scan now auto-generates three flat export files:

| File | Purpose |
|:---|:---|
| `findings.jsonl` | One finding per line for SIEM ingestion |
| `assets.jsonl` | One asset per line for inventory |
| `summary.json` | Compact dashboard-ready summary |

#### Finding Deduplication

- **`finding_id`**: Deterministic SHA256 hash based on asset, scanner, port, and signature
- Enables cross-scan correlation and tracking of resolved vs recurring issues

#### Category Classification

Findings are now automatically classified:

| Category | Examples |
|:---|:---|
| `surface` | Open port, exposed service |
| `misconfig` | Missing headers, directory listing |
| `crypto` | TLS 1.0, weak ciphers, expired cert |
| `auth` | Default credentials, no auth |
| `info-leak` | Version disclosure, internal IP |
| `vuln` | CVE identified |

#### Normalized Severity

- **`normalized_severity`**: 0.0-10.0 scale (CVSS-like)
- **`original_severity`**: Preserved tool-native values
- Enum: `info`, `low`, `medium`, `high`, `critical`

#### Parsed Observations

- **`parsed_observations`**: Structured list extracted from Nikto/TestSSL
- Reduces noise for AI processing
- Large raw outputs externalized to `evidence/` folder

#### Scanner Versions

- **`scanner_versions`**: Detected tool versions for provenance
- Example: `{"redaudit": "3.1.0", "nmap": "7.95", "nikto": "2.5.0"}`

### New Modules

```text
redaudit/core/
├── scanner_versions.py  # Tool version detection
├── evidence_parser.py   # Nikto/TestSSL observation extraction
└── jsonl_exporter.py    # JSONL/JSON export generation
```

### JSON Schema Update

```json
{
  "schema_version": "3.1",
  "generated_at": "2025-12-14T18:00:00",
  "scanner_versions": {"redaudit": "3.1.0", "nmap": "7.95"},
  "vulnerabilities": [{
    "host": "192.168.1.1",
    "vulnerabilities": [{
      "finding_id": "12273fca7e8dbe0e262589c87708f76f",
      "category": "misconfig",
      "severity": "high",
      "normalized_severity": 7.0,
      "original_severity": {"tool": "nikto", "value": "HIGH"},
      "parsed_observations": ["Missing X-Frame-Options header"]
    }]
  }]
}
```

### Upgrade Notes

- **Backward Compatible**: All new fields are optional
- **No CLI Changes**: Features are automatic
- **Schema Version**: Updated to 3.1

### Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete history.
