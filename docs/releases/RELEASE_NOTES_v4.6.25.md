# RedAudit v4.6.25 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver_en_Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.25/docs/releases/RELEASE_NOTES_v4.6.25_ES.md)

## Summary

**RedAudit v4.6.25** is a hotfix release that secures the new parallel Nuclei scanning engine. It introduces thread safety mechanisms to prevent data loss during concurrent batch execution and extends parallel processing capabilities to the standard CLI interface.

## Fixed

- **Race Condition Prevention**: Implemented `threading.Lock` around critical sections (file I/O, statistics updates) in `nuclei.py`. This prevents race conditions where multiple parallel batches could try to write to the main output file simultaneously, potentially corrupting or losing findings.
- **CLI Parallel Execution**: Fixed an oversight where parallel batch execution was only active for API callbacks. Now, standard CLI users (using the Rich progress bar) also benefit from the ~4x speedup of parallel processing.

## Testing

- Updated `tests/core/test_nuclei_parallel.py` to verify not just speed, but also **data integrity** (ensuring all findings are correctly written to disk without loss).

## Upgrade

```bash
git pull origin main
```
