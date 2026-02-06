# RedAudit v4.4.3 Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver_en-Español-yellow.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.4.3/docs/releases/RELEASE_NOTES_v4.4.3_ES.md)

This hotfix release addresses critical log noise from mDNS probes, fixes a data loss bug in agentless verification due to type mismatches, and increases test coverage for core scan components.

## Fixes

* **mDNS Log Noise Suppressed**:
  * Previously, the mDNS probe in `_run_low_impact_enrichment` dumped full `TimeoutError` tracebacks to the logs when hosts did not respond.
  * This has been patched to handle timeouts gracefully as expected behavior (debug level logging), significantly reducing log clutter during scans.

* **Agentless Verification Data Restored**:
  * Fixed a regression where agentless probe results (like OS versions from `rpcclient` or `snmpwalk`) were being discarded.
  * The issue was caused by the `run_agentless_verification` logic filtering out `Host` dataclass objects during index creation. This has been corrected to handle both legacy dictionaries and modern `Host` objects transparently.

* **Safer SNMP Parsing**:
  * Corrected a regex syntax error in the SNMP `sysDescr` parser that could cause failures when stripping type prefixes (e.g., `STRING:`).

## Technical Improvements

* **Increased Test Coverage**: Added targeted unit tests for `auditor_scan.py` covering failure paths for DNS, mDNS, and SNMP enrichment.
* **Consolidated Tests**: New tests have been integrated into `test_auditor_core.py` to maintain a cleaner test architecture.

---

**Full Changelog**: [v4.4.2...v4.4.3](https://github.com/dorinbadea/RedAudit/compare/v4.4.2...v4.4.3)
