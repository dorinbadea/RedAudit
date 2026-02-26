# RedAudit v4.20.12 - Nuclei Compact Progress and Timeout Aggregation

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.12/docs/releases/RELEASE_NOTES_v4.20.12_ES.md)

## Summary

This patch improves Nuclei terminal usability during long timeout/retry cycles by compacting live timeout noise and preserving detail in a single grouped summary block.

## Added

- Added Nuclei timeout aggregation fields in pipeline/report outputs: `timeout_batches_count`, `timeout_events_count`, and `timeout_summary_compact`.

## Improved

- Nuclei live progress now suppresses repetitive per-timeout warning detail while the live bar is active.
- End-of-phase timeout reporting now prints one grouped summary block with batch-level context.
- `run_manifest.json` now mirrors additional pipeline sections (`topology`, `agentless_verify`, `scope_expansion`) for stronger output parity.

## Fixed

- Reduced terminal line corruption risk caused by warning/log output colliding with active live progress rendering.

## Testing

Internal validation completed.

## Upgrade

No action required.
