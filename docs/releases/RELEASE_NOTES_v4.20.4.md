# RedAudit v4.20.4 - Artifact Validation and Nuclei Resume Observability

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.4/docs/releases/RELEASE_NOTES_v4.20.4_ES.md)

## Summary

This patch release improves scan-output reliability controls and Nuclei resume observability without changing scan targeting semantics.

## Added

- Added a reproducible validation gate for completed scan folders:
  - `scripts/check_scan_artifacts.py`
  - `redaudit/utils/scan_artifact_gate.py`
- The gate validates:
  - `run_manifest.json` artifact completeness/readability
  - minimal PCAP header integrity
  - JSON/JSONL contract checks for `summary.json`, `assets.jsonl`, and `findings.jsonl`
- Added strict mode support to fail fast when SIEM export files or required fields are missing.

## Improved

- Nuclei progress detail now explicitly shows sub-batch elapsed context and clearer split-depth semantics during timeout retries.
- HTML/pipeline reporting now exposes resume context fields for partial runs:
  - `resume_pending`
  - `resume_count`
  - `last_resume_at`
  - `resume_state_file`

## Fixed

- Normalized Nuclei resume metadata serialization across report outputs to avoid ambiguous/missing resume fields in downstream consumers.

## Testing

Internal validation completed.

## Upgrade

No action required.
