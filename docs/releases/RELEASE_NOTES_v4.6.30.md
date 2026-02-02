# v4.6.30: Safety First (Zombie Reaper) ‍♂️️

**Date:** 2026-01-15

This release focuses on **robustness and safety** for high-concurrency environments. Following the "threads unleashed" update (v4.6.29), we identified a risk of orphaned subprocesses during interruptions. This update safeguards your system resources.

## ️ Safety & Reliability

- **Zombie Reaper**: Implemented a native process cleanup mechanism (`pkill -P <PID>`) that reliably terminates **all** child processes (Nmap, Nuclei, etc.) when RedAudit is interrupted (e.g., via `Ctrl+C`).
- **Resource Protection**: With `MAX_THREADS=100`, this prevents leaving dozens of "zombie" scans running in the background if the main process is killed abruptly.
- **FD Leak Audit**: Verified that all internal file operations use context managers (`with open(...)`) to prevent file descriptor leaks under load.

## ⚡ Improvements

- **Exception Safety**: Audited `ThreadPoolExecutor` usage to ensure all worker exceptions are caught and logged, preventing silent thread failures.

##  Verification

- Added `tests/core/test_auditor_cleanup.py` to verify the new Zombie Reaper logic.
- Full regression suite passed.
