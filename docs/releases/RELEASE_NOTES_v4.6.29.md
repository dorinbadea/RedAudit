# Release Notes v4.6.29

![Version](https://img.shields.io/badge/version-v4.6.29-blue?style=flat-square) [![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v4.6.29_ES.md)

## 🚀 Performance Unlocked: Thread Limits Unleashed

In response to modern hardware capabilities (M2/M3 chips, Threadrippers), we have significantly increased the concurrency limits for RedAudit.

### ⚡ Highlights

- **Thread Cap Increased (16 → 100)**: The artificial limit of 16 threads has been lifted. You can now use up to **100 threads** for deep scanning, allowing RedAudit to fully utilize high-performance CPUs.
- **Deep Scan Concurrency**: The Deep Scan phase now respects the global `MAX_THREADS` limit, removing the previous hardcoded cap of 50.
- **Config Integrity**: Fixed a consistency issue where `nuclei_timeout` was missing from the configuration context defaults.

---

### 🛠️ Key Changes

#### Performance

- **Uncapped Threads**: `MAX_THREADS` constant updated to 100.
- **Deep Scan**: Updated logic to use dynamic thread limits.

#### Fixes

- **Config**: Added `nuclei_timeout` to `ConfigurationContext`.

#### Verification

- **Tests**: Added `tests/core/test_thread_limits.py` to verify thread limit adherence.

---

*[Back to Changelog](../../CHANGELOG.md)*
