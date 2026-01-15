# Release Notes - v4.7.0

**Release Date**: 2026-01-15

## Summary

This release introduces the **HyperScan Masscan Integration**, dramatically improving port discovery speed from approximately 30 minutes to under 10 seconds for typical networks.

## New Features

### HyperScan Masscan Integration

A new `masscan_scanner.py` module provides fast port discovery using masscan as the primary backend:

- **`masscan_sweep()`**: Scans the top 10,000 ports on a single IP in seconds
- **`masscan_batch_sweep()`**: Efficient multi-host scanning
- **Automatic fallback**: If masscan is unavailable, falls back to asyncio TCP connect scanning
- **Rate limiting**: Uses 1000 packets per second to avoid network saturation

### Performance Improvement

| Metric | v4.6.x (scapy) | v4.7.0 (masscan) |
|--------|----------------|------------------|
| 36 hosts scan | ~30 minutes | ~10 seconds |
| Per-host time | ~1 minute | <1 second |

## Technical Details

The integration modifies `hyperscan_full_port_sweep()` in `hyperscan.py` to:

1. Check if masscan is available (installed + root privileges)
2. Use masscan for the initial port sweep (1-10000)
3. Fall back to the original asyncio implementation if masscan fails

## Requirements

- Masscan must be installed (included in `redaudit_install.sh`)
- Root privileges required for masscan (standard RedAudit operation)

## Upgrade Notes

No breaking changes. The masscan integration is transparent - if masscan is unavailable, the previous scanning method is used automatically.
