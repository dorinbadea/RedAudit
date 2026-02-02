# v4.6.31: HyperScan Velocity (Hotfix)

**Date:** 2026-01-15

Addressed a performance bottleneck in the **HyperScan-First** phase where hosts were scanned sequentially, causing significant delays (e.g., ~40 mins for 40 hosts).

##  Performance

- **Parallel HyperScan**: Now executes up to **8 hosts concurrently** in the pre-scan phase (previously sequential).
- **Adaptive Batching**: Automatically calculates safe `batch_size` based on system File Descriptor limits (`ulimit -n`) to maximize speed without crashing.

## ️ Fixes

- **FD Safety**: Prevents `Too many open files` errors by dynamically scaling concurrency.
