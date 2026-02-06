[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.40/docs/releases/RELEASE_NOTES_v4.19.40_ES.md)

# RedAudit v4.19.40 - Consistency and Risk Evidence Alignment

## Summary

This patch improves resume consistency and aligns dashboard severity summaries with risk evidence already used by host scoring.

## Added

- `summary.json` now includes:
  - `risk_evidence_severity_breakdown`
  - `combined_severity_breakdown`
  - `total_risk_evidence_findings`
  - `total_findings_with_risk_evidence`

## Improved

- Experimental TestSSL findings now receive stricter confidence handling when paired with "no web server found" signals.
- Report schema documentation (EN/ES) now documents the new summary risk-evidence fields.

## Fixed

- Severity enrichment is now idempotent for already-normalized findings, preventing resume-induced risk drift on informational findings.
- Summary exports now expose risk-evidence severity counts from CVEs/exploits/backdoor signatures attached to host ports.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Pull `v4.19.40` from the official repository.
2. Run one scan and verify `summary.json` includes the new risk-evidence keys.
3. Confirm resumed scans keep host risk stable when no new findings are added.
