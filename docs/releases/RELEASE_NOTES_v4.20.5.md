# RedAudit v4.20.5 - Nuclei Resume Stability and NDJSON Contract Hardening

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.5/docs/releases/RELEASE_NOTES_v4.20.5_ES.md)

## Summary

This patch release fixes a real Nuclei resume runtime error, improves operator clarity in progress/report outputs, and hardens artifact contract validation for NDJSON streams.

## Added

- Extended scan artifact validation to check Nuclei raw streams as NDJSON:
  - `nuclei_output.json`
  - `nuclei_output_resume.json`
- Added explicit scope-expansion runtime status lines for operators:
  - IoT probe runtime counters
  - Leak-follow target augmentation count before Nuclei

## Improved

- Nuclei progress detail text now clearly separates:
  - sub-batch elapsed context
  - total Nuclei elapsed timer
  - split depth semantics (`current/max`)
- HTML report mode display is now language-consistent:
  - English UI displays `fast/normal/full`
  - Spanish UI displays `rapido/normal/completo`
  - Internal JSON contract values remain unchanged for compatibility.
- EN/ES documentation now explicitly describes:
  - NDJSON contract for Nuclei raw output files
  - interpretation of `partial + resume_pending`
  - expected behavior when `nuclei_output_resume.json` is empty.

## Fixed

- Fixed Nuclei resume prompt compatibility: `ask_yes_no_with_timeout` now accepts both `timeout` and `timeout_s`, preventing the runtime `TypeError` observed in resume flows.

## Testing

Internal validation completed.

## Upgrade

No action required.
