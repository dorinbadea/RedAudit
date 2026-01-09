# RedAudit v4.4.4 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver_en-Español-yellow.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.4.4/docs/releases/RELEASE_NOTES_v4.4.4_ES.md)

This release focuses on quality and reliability, reaching a milestone of ~90% code coverage. It includes enhanced testing for SIEM integration, SYN scanning, and reporting reliability, ensuring RedAudit remains stable across complex network environments.

## Improvements

* **Aggressive Coverage Push**:
  * Reached **~90% total code coverage** (up from 89%).
  * **SIEM Reliability**: Expanded tests for `siem.py` covering risk score breakdowns, CEF generation, and tool-specific severity mapping (Nuclei, TestSSL).
  * **SYN Scanning Robustness**: Added failure path testing for the new Scapy-based SYN scanner.
  * **Reporting Safety**: Hardened `reporter.py` with tests for file system permission errors and encrypted artifact verification.
  * **Core Orchestration**: Improved coverage for `auditor.py` and `hyperscan.py` initialization and connection logic.

## Fixes (from v4.4.3 Hotfix)

* **mDNS Log Noise Suppressed**: Gracefully handle mDNS timeouts.
* **Agentless Verification Restored**: Fixed data loss bug when handling newer `Host` objects.
* **SNMP Parsing**: Fixed regex syntax for safer CIDR/SNMP extraction.

---

**Full Changelog**: [v4.4.2...v4.4.4](https://github.com/dorinbadea/RedAudit/compare/v4.4.2...v4.4.4)
