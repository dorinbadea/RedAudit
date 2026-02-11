# RedAudit v4.20.7 - Nuclei Progress and Elapsed Time Clarity

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.7/docs/releases/RELEASE_NOTES_v4.20.7_ES.md)

## Summary

This patch improves Nuclei operator visibility without changing scan semantics. Progress output is now easier to read in terminal sessions, and elapsed-time reporting is now explicitly wall-clock based for both initial runs and resume runs.

## Added

- New Nuclei timing fields in pipeline/report outputs:
  - `last_run_elapsed_s`
  - `last_resume_elapsed_s`
  - `nuclei_total_elapsed_s`

## Improved

- Nuclei progress now uses a compact two-line layout:
  - Progress bar line
  - Telemetry line (`batch`, `split depth`, `sub-batch elapsed`, `total elapsed`)
- HTML Nuclei summary now shows:
  - Last run elapsed
  - Last resume elapsed
  - Total Nuclei elapsed
- Completion messages now print explicit duration:
  - `Nuclei completed in ...`
  - `Nuclei resume completed in ...`

## Fixed

- Corrected elapsed accounting to use wall-clock timing around run/resume execution.
- Fixed timeout prompt output so auto-continue text no longer collides with the next status line.

## Testing

Internal validation completed.

## Upgrade

No action required.
