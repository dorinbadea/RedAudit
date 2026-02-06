# RedAudit v4.6.27 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver_en_Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.27/docs/releases/RELEASE_NOTES_v4.6.27_ES.md)

## Summary

**RedAudit v4.6.27** solves the performance bottleneck in the **HyperScan-First** phase that was causing scans to take ~1 minute per host instead of seconds.

## Fixed

- **HyperScan Throttling Logic**:
  - **Previous Behavior**: The scanner treated "Connection Refused" (closed ports) the same as "Connection Timed Out". The adaptive rate controller (SmartThrottle) interpreted this as 99% packet loss, forcing the scan speed down to the minimum safe limit (100 ports/batch).
  - **New Behavior**: Explicitly distinguishes between `RST` (Port Closed) and `Timeout`. Closed ports are now correctly counted as successful network probes.
  - **Impact**: The scanner now correctly identifies network stability and accelerates up to 20,000 ports/batch, reducing full port sweeps (1-65535) from ~60s to ~3s per host.

## Upgrade

```bash
git pull origin main
```
