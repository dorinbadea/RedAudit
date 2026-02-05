# RedAudit v4.4.0 - Enterprise Scalability & Smart-Throttle

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v4.4.0_ES.md)

This release introduces major scalability improvements and adaptive rate limiting, allowing RedAudit to scan massive networks (e.g., /16 subnets) without memory exhaustion or network congestion.

## New Features

### Smart-Throttle (Adaptive Congestion Control)

RedAudit now "senses" the network. Instead of a static batch size, the new **AIMD (Additive Increase, Multiplicative Decrease)** engine dynamically adjusts the scanning speed:

- **Congestion Detected**: If packets drop or timeouts occur, RedAudit throttles back immediately to preserve accuracy.
- **Stable Network**: If the link is healthy, it accelerates to maximize throughput.
- **Visual Feedback**: The CLI progress bar now indicates real-time throttling status (e.g., `[▼25]` for throttling, `[▲100]` for acceleration).

### Generator-based Targeting

The target expansion logic was rewritten to use **lazy evaluation** (generators) instead of in-memory lists.

- **Problem Solved**: Scanning a `/16` previously required generating 65k+ IP objects in memory before starting.
- **Solution**: Targets are now yielded on-demand.
- **Effect**: Memory usage remains flat and minimal (<100MB) even when scanning millions of targets.

### Future-Ready Architecture

- **Distributed Design**: Added `docs/design/distributed_scanning.md` detailing the upcoming Coordinator/Worker architecture for multi-node scanning.
- **AsyncIO Migration Path**: Added `docs/design/asyncio_migration.md` outlining the roadmap for a full non-blocking I/O rewrite in v5.0.

## Improvements

- **Report Memory Optimization**: Refactored `_collect_discovery_hosts` to filter and process hosts more efficiently during large scans.
- **UI Tweaks**: Improved progress bar stability to prevent "heartbeat" messages from breaking the visual layout.
- **Developer Experience**: Added `requirements.lock` and instructions for reproducible pip-based installs.

## Fixes

- Fixed a UI bug where status messages would duplicate on new lines during deep scans.
- Fixed indentation in `hyperscan.py` that caused potential logic issues in connection handling.

## Upgrading

```bash
cd RedAudit
git pull origin main
# No new dependencies, but good practice to check:
pip install -r requirements.txt
```
