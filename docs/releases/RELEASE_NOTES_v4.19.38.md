[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.38/docs/releases/RELEASE_NOTES_v4.19.38_ES.md)

# RedAudit v4.19.38 - Auditability and Installer Hardening

## Summary

This release strengthens credential operation traceability and hardens installer-side configuration generation while preserving the recent report consistency and SIEM risk stability fixes.

## Added

- Credential audit events for provider access/store operations (`credential_audit` key/value log format without secrets).

## Improved

- Security documentation now clarifies keyring backend behavior in headless/root contexts and documents credential audit events.

## Fixed

- Partial report coherence when Nuclei is partial (`PARTIAL_` naming and TXT status align with manifest state).
- SIEM host risk stability by calculating risk after finding normalization/consolidation and host finding remapping.
- Installer NVD config JSON generation now uses `jq` when available and a `python3` fallback instead of raw shell JSON echoing.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Pull `v4.19.38` from the official repository.
2. Re-run installer if you manage system-wide deployments via `redaudit_install.sh`.
3. Validate your existing automation/reporting pipeline with one complete scan and one Nuclei resume flow.
