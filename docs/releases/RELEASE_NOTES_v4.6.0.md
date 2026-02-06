# RedAudit v4.6.0 - Trust HyperScan Optimization

**Date:** 2026-01-11
**Type:** Feature Release

This release introduces a critical optimization for time-sensitive audits: **Trust HyperScan**.

### ⚡ Trust HyperScan Mode

Previously, RedAudit's paranoid security model forced a full 65,535 port scan (`nmap -p-`) for any host undergoing Deep Scan, regardless of prior discovery results. This ensured maximum accuracy but caused significant delays (20-30 mins) on slow consumer routers or rate-limited networks.

**New Feature (`--trust-hyperscan`):**

- Allows the Deep Scan engine to **reuse** ports discovered by HyperScan (Phase 2).
- Bypasses the redundant `-p-` sweep, reducing scan times from ~25 mins to <2 mins per host.
- **Optional**: Disabled by default to maintain professional rigor. Can be enabled via CLI or interactive Wizard.

### CLI Changes

- Added `--trust-hyperscan` (alias `--trust-discovery`) flag.

### Wizard Changes

- Added interactive prompt: *"Enable 'Trust HyperScan'? (Reuse discovery ports for faster Deep Scan)"*.

### Infrastructure

- Updated build and versioning to v4.6.0.

---
**Full Changelog**: <https://github.com/dorinbadea/RedAudit/compare/v4.5.18...v4.6.0>
