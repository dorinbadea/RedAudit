# RedAudit v4.6.24 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver_en_Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.24/docs/releases/RELEASE_NOTES_v4.6.24_ES.md)

## Summary

**RedAudit v4.6.24** delivers a critical performance overhaul for the Nuclei vulnerability scanner integration. This release addresses significant bottlenecks in large-network scans by introducing parallel batch execution and fixing a retry logic bug that caused infinite loops on timeouts.

## Improved

- **Parallel Nuclei Batches**: Nuclei scans now execute up to **4 batches simultaneously** (using thread pooling). This dramatically reduces total scan time for large networks.
- **Smaller Default Batches**: Reduced default batch size from 25 to **10** hosts. This minimizes the impact of a single slow target on the entire batch.
- **Optimized Timeout Strategy**: Replaced the "extended timeout retry" logic with an "immediate split" strategy. If a batch times out, it is immediately split into smaller chunks rather than retried, preventing wasted time.

## Fixed

- **Infinite Retry Loop**: Fixed a bug where nested retries inherited the `retry_attempt` counter reset, causing batches to retry indefinitely if they kept timing out.
- **ETA Formatting**: Fixed a regresssion in ETA symbol consistency.

## Testing

- Added `tests/core/test_nuclei_parallel.py` to verify concurrent execution speedup.
- Verified ~4x speedup on simulated large network scans (40+ web targets).

## Upgrade

```bash
git pull origin main
```
