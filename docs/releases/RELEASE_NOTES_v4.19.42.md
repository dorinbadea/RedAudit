[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.42/docs/releases/RELEASE_NOTES_v4.19.42_ES.md)

# RedAudit v4.19.42 - Resume and Reporting Consistency Hardening

## Summary

This patch improves report coherence for interrupted and resumed runs by aligning Nuclei counters, resume artifact indexing, host risk evidence totals, and hostname fallback behavior across JSONL outputs.

## Added

- `run_manifest.json` now includes a `nuclei_resume` object (when present) with:
  - pending target count
  - resume count
  - last/update timestamps
  - profile/output metadata
- `counts.nuclei_pending_targets` was added to manifest totals.

## Improved

- Nuclei summary now distinguishes:
  - `targets_total` (effective targets executed after optimization)
  - `targets_pre_optimization` (discovered total before optimization)
- JSONL hostname export consistency improved by using reverse-DNS fallback when `hostname` is empty.

## Fixed

- Session log finalization order now guarantees that `run_manifest.json` includes the latest `session_resume_*` artifacts.
- Risk breakdown now tracks `finding_total` correctly and avoids invalid `risk findings 1/0` displays in TXT/HTML.
- Hostname drift between TXT/HTML and JSONL was fixed for hosts resolved only through reverse DNS.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Pull `v4.19.42` from the official repository.
2. Run a scan with one or more Nuclei resumes and verify `run_manifest.json` includes `nuclei_resume` metadata.
3. Confirm JSONL hostnames match TXT/HTML fallback behavior for reverse-DNS-only assets.
