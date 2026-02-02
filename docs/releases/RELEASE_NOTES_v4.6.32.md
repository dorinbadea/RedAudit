# v4.6.32: Parallel Discovery (Velocity II) ️

**Date:** 2026-01-15

Following the HyperScan parallelization, the entire **Net Discovery** phase (DHCP, ARP, Fping, NetBIOS, mDNS, UPnP) has been parallelized.

##  Performance

- **Parallel Protocols**: All discovery protocols now run simultaneously using a ThreadPool.
- **Speedup**: Phase duration reduced from ~2-3 minutes to ~30-45 seconds (limited only by the slowest protocol, usually NetBIOS or UPnP timeout).
- **Zero Loss**: Full coverage maintained; results are securely aggregated from all threads.

## ️ Internal

- Refactored `discover_networks` to use `ThreadPoolExecutor`.
