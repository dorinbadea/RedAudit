# RedAudit v4.20.10 - Nuclei Progress UX and Artifact Parity Hardening

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.10/docs/releases/RELEASE_NOTES_v4.20.10_ES.md)

## Summary

This patch improves Nuclei operator experience during long runs by separating progress bar rendering from telemetry rendering, reducing visual compression and console noise. It also hardens artifact validation with strict parity checks for Nuclei resume/timing fields across summary and manifest outputs.

## Added

- New Nuclei reporting field: `targets_selected_after_optimization` to distinguish total selected targets from optimized-host-only counters.
- Strict artifact gate parity checks for Nuclei timing/resume metadata between `summary.json` and `run_manifest.json`.

## Improved

- Nuclei live progress now uses one real bar line plus one telemetry-only line.
- Telemetry wording is now compact (`AB`/`B`, `SB`, `SD`) for better readability in long scans.
- The total elapsed timer is now shown once in the main bar line, avoiding duplicate elapsed output.
- HTML/TXT report context now surfaces the selected-after-optimization metric clearly.

## Fixed

- Reduced Nuclei terminal noise in long timeout/retry cycles through throttled and deduplicated telemetry updates.
- Fallback progress logging now avoids sub-batch churn spam while preserving key state transitions.

## Testing

Internal validation completed.

## Upgrade

No action required.
