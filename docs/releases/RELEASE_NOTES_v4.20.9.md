# RedAudit v4.20.9 - Nuclei Dual Live Progress Stabilization

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.9/docs/releases/RELEASE_NOTES_v4.20.9_ES.md)

## Summary

This patch hardens Nuclei progress UX for long-running scans by keeping a dedicated live bar plus a parallel live telemetry line, reducing terminal noise without changing scan semantics.

## Added

- No new runtime flags were added in this patch.

## Improved

- Nuclei live progress now keeps the main progress bar and telemetry on separate synchronized live lines.
- Split depth, active batches, and elapsed context are updated in-place for better readability during long timeout/retry windows.

## Fixed

- Resolved repetitive Nuclei telemetry log bursts (`[nuclei] active batches ...`) that previously flooded terminal output under long runs.

## Testing

Internal validation completed.

## Upgrade

No action required.
