[![Ver en Espanol](https://img.shields.io/badge/Ver_en_Espanol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.41/docs/releases/RELEASE_NOTES_v4.19.41_ES.md)

# RedAudit v4.19.41 - Canonical Vendor and Risk Transparency Alignment

## Summary

This patch aligns vendor identity and host risk evidence across SIEM enrichment and user-facing outputs, reducing ambiguity while keeping the scan pipeline optimized by default.

## Added

- Canonical vendor metadata in SIEM-enriched host records:
  - `vendor_source`
  - `vendor_confidence`
- Explicit host risk-evidence counters for service CVEs (critical/high split), exploits, backdoor signatures, and finding totals.

## Improved

- HTML, TXT, and JSONL exports now use the same canonical vendor source to prevent output drift.
- HTML host risk tooltips and TXT host sections now expose risk evidence components more explicitly.

## Fixed

- Reduced vendor false positives by preventing generic `*.fritz.box` labels from forcing AVM guesses.
- Improved NAS inventory classification by mapping Synology/QNAP/Asustor/TerraMaster vendor hints to `server` by default.
- ECS host vendor now follows canonical vendor resolution before deep-scan fallback.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Pull `v4.19.41` from the official repository.
2. Run one audit and verify HTML/TXT/JSONL vendor values are consistent for the same host.
3. Confirm host risk details include explicit evidence counters (CVEs/exploits/backdoor/findings).
