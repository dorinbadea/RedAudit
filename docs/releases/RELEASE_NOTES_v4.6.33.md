# Release Notes v4.6.33 - Performance, Accuracy & Localization

**Date**: 2026-01-15
**Version**: 4.6.33

This hotfix release addresses critical performance bottlenecks in Net Discovery, improves HyperScan accuracy, and refines Spanish localization.

##  Key Improvements

### ⚡ Net Discovery Optimization

- **Faster Protocol Timeouts**: Reduced default timeouts for blocking protocols (Fping, NetBIOS, ARP) from **30s** to **15s**. This resolves instances where Net Discovery could hang for 10-12 minutes on complex or unresponsive networks.
- **Granular Debug Logging**: Added detailed debug logs (`NetDiscovery: Starting {proto}`) to identify specific stalling protocols in real-time.

###  HyperScan Accuracy

- **Increased Timeout**: `HyperScan-First` timeout increased from **0.5s** to **1.5s**. This prevents false negatives (reporting 0 ports) on hosts with slight network latency or high load.
- **Parallel Logging**: Corrected misleading log messages that stated execution was "sequential" when it was actually running in parallel.
- **Parallel Stability**: Fixed a critical race condition bug in `HyperScan-First` that could overwrite host results due to stale loop variable usage.

###  Localization (Spanish)

- **Spain Spanish Standards**: Standardized terms for the Spanish locale (`es_ES`):
  - Changed "Archivo" to "Fichero".
  - Standardized "Net Discovery" terminology in Wizard.
  - Added missing translation for "UDP probes" -> "Sondas UDP".
- **Typo Fixes**: Corrected "sequential" typo in HyperScan start message.

##  Changes

- `redaudit/utils/i18n.py`: Updated translations.
- `redaudit/core/hyperscan.py`: Increased timeout and added localization support.
- `redaudit/core/net_discovery.py`: Optimized timeouts and added logging.

---
**Upgrade**: `git pull && sudo pip3 install .`
