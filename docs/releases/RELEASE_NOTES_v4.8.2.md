# Release Notes v4.8.2

**Release Date:** 2026-01-16
**Type:** Hotfix

## Critical Fixes

### RustScan Port Range Regression

- **Issue**: In v4.8.0/v4.8.1, RustScan was integrated as the primary scanner but used its default behavior of scanning only the top 1000 ports. This caused a regression compared to the previous Masscan implementation which scanned all 65,535 ports by default.
- **Fix**: Updated `rustscan.py` and `hyperscan.py` to explicitly force a full port range scan (`1-65535`) during the HyperScan phase.
- **Impact**: Network discovery will now correctly identify services running on non-standard high ports (e.g., 8182, 8189, 55063) commonly found on routers and IoT devices.

## Upgrading

```bash
git pull
./redaudit_install.sh  # Re-run to ensure dependencies are checked
```
