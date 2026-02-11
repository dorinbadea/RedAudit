# RedAudit v4.20.8 - Nuclei Progress Noise Reduction

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.8/docs/releases/RELEASE_NOTES_v4.20.8_ES.md)

## Summary

This patch improves terminal usability during long Nuclei runs by reducing progress-line noise. Scan logic and targeting semantics are unchanged.

## Added

- No new runtime features were added in this patch.

## Improved

- Nuclei telemetry now reports compact state changes instead of per-second elapsed churn.
- Progress output stays readable under long timeout/retry cycles.
- Telemetry wording was shortened to reduce line wrapping in narrow terminals.

## Fixed

- Progress-state tracking now normalizes telemetry keys (`active batches`, `split depth`, retries) and ignores volatile `sub-batch elapsed` values that previously caused log storms.

## Testing

Internal validation completed.

## Upgrade

No action required.
