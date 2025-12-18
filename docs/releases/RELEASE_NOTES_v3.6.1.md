# RedAudit v3.6.1 - Scan Quality & UX

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.6.1_ES.md)

Release Date: 2025-12-18

## Highlights

- **Findings Consolidation**: Duplicate findings on the same host (e.g., "Missing X-Frame-Options" on 5 ports) are now merged into single entries with an `affected_ports` array.
- **OUI Fallback Lookup**: New module for online MAC vendor lookup via macvendors.com when the local database is incomplete.
- **HTTPS Port Detection**: Expanded SSL/TLS detection to include common non-standard ports (8443, 4443, 9443, 49443).

## Bug Fixes

- **Nuclei Integration**: Fixed `get_http_targets_from_hosts()` which was checking for `state != "open"` but RedAudit ports don't have a `state` field. Now uses `is_web_service` flag correctly.
- **Progress Bar Noise**: Condensed nmap command output from full command to `[nmap] IP (scan type)` for cleaner terminal display.
- **False Positive Handling**: When cross-validation detects Nikto reported a missing header that curl/wget shows as present, severity is now degraded to `info` with `verified: false`.

## Changes

- **testssl Execution**: Now runs on all HTTPS ports (8443, 49443, etc.), not just port 443.

## Files Changed

- `redaudit/core/auditor.py` - OUI fallback integration, progress bar cleanup
- `redaudit/core/nuclei.py` - Fixed target generation
- `redaudit/core/siem.py` - Added `consolidate_findings()`, FP severity degradation
- `redaudit/utils/oui_lookup.py` - New module

## Documentation

- [CHANGELOG.md](../../CHANGELOG.md)
- [USAGE Guide](../USAGE.en.md)
